<?php
/**
 * OAuth server tests.
 *
 * @package WP\MCP\Tests
 */

declare( strict_types=1 );

namespace WP\MCP\Tests\Unit\OAuth;

use ReflectionMethod;
use WP\MCP\OAuth\OAuthServer;
use WP\MCP\Tests\TestCase;
use WP_REST_Request;
use WP_REST_Response;

/**
 * Covers the built-in WordPress OAuth primitives without replacing WordPress
 * capability authorization.
 */
final class OAuthServerTest extends TestCase {

	/**
	 * Authorization header value saved before a test mutates it.
	 *
	 * @var string|null
	 */
	private ?string $previous_authorization_header = null;

	/**
	 * Clean up request globals used by authentication tests.
	 */
	public function tearDown(): void {
		if ( null === $this->previous_authorization_header ) {
			unset( $_SERVER['HTTP_AUTHORIZATION'] );
		} else {
			$_SERVER['HTTP_AUTHORIZATION'] = $this->previous_authorization_header;
		}

		parent::tearDown();
	}

	/** OAuth points at the canonical default MCP HTTP resource. */
	public function test_resource_url_targets_default_mcp_server(): void {
		$this->assertSame(
			rest_url( 'mcp/mcp-adapter-default-server' ),
			OAuthServer::resource_url()
		);
	}

	/** Issuer is the WordPress site itself. */
	public function test_issuer_is_wordpress_home_url(): void {
		$this->assertSame( untrailingslashit( home_url( '/' ) ), OAuthServer::issuer() );
	}

	/** Existing WordPress authentication wins over a Bearer token. */
	public function test_bearer_auth_does_not_replace_existing_wordpress_authentication(): void {
		$this->set_authorization_header( 'Bearer ignored-token' );

		$this->assertSame( 123, OAuthServer::instance()->authenticate_bearer_token( 123 ) );
	}

	/** Non-Bearer Authorization headers are ignored so Application Passwords remain available. */
	public function test_basic_authorization_header_is_ignored(): void {
		$this->set_authorization_header( 'Basic dXNlcjpwYXNz' );

		$this->assertFalse( OAuthServer::instance()->authenticate_bearer_token( false ) );
	}

	/** Unknown Bearer tokens do not authenticate a WordPress user. */
	public function test_unknown_bearer_token_is_rejected(): void {
		$this->set_authorization_header( 'Bearer definitely-not-a-valid-token' );

		$this->assertFalse( OAuthServer::instance()->authenticate_bearer_token( false ) );
	}

	/** A valid access token resolves directly to the WordPress user that authorized it. */
	public function test_valid_bearer_token_resolves_wordpress_user(): void {
		$token = 'valid-access-token';
		$this->store_token_record(
			$token,
			array(
				'type'      => 'access',
				'user_id'   => 42,
				'client_id' => 'test-client',
				'resource'  => OAuthServer::resource_url(),
				'scope'     => 'mcp:access',
				'expires'   => time() + HOUR_IN_SECONDS,
			)
		);
		$this->set_authorization_header( 'Bearer ' . $token );

		$this->assertSame( 42, OAuthServer::instance()->authenticate_bearer_token( false ) );

		delete_option( $this->token_option_name( $token ) );
	}

	/** Expired access tokens fail closed and are removed from storage. */
	public function test_expired_bearer_token_is_rejected_and_cleaned_up(): void {
		$token = 'expired-access-token';
		$name  = $this->token_option_name( $token );

		$this->store_token_record(
			$token,
			array(
				'type'      => 'access',
				'user_id'   => 42,
				'client_id' => 'test-client',
				'resource'  => OAuthServer::resource_url(),
				'scope'     => 'mcp:access',
				'expires'   => time() - 1,
			)
		);
		$this->set_authorization_header( 'Bearer ' . $token );

		$this->assertFalse( OAuthServer::instance()->authenticate_bearer_token( false ) );
		$this->assertFalse( get_option( $name, false ) );
	}

	/** Refresh tokens cannot be used as Bearer access tokens. */
	public function test_refresh_token_cannot_authenticate_mcp_request(): void {
		$token = 'refresh-token-used-as-bearer';
		$this->store_token_record(
			$token,
			array(
				'type'      => 'refresh',
				'user_id'   => 42,
				'client_id' => 'test-client',
				'resource'  => OAuthServer::resource_url(),
				'scope'     => 'mcp:access',
				'expires'   => time() + HOUR_IN_SECONDS,
			)
		);
		$this->set_authorization_header( 'Bearer ' . $token );

		$this->assertFalse( OAuthServer::instance()->authenticate_bearer_token( false ) );

		delete_option( $this->token_option_name( $token ) );
	}

	/** Tokens issued for another resource are not accepted by this MCP server. */
	public function test_bearer_token_with_wrong_resource_is_rejected(): void {
		$token = 'wrong-resource-token';
		$this->store_token_record(
			$token,
			array(
				'type'      => 'access',
				'user_id'   => 42,
				'client_id' => 'test-client',
				'resource'  => rest_url( 'some-other-resource' ),
				'scope'     => 'mcp:access',
				'expires'   => time() + HOUR_IN_SECONDS,
			)
		);
		$this->set_authorization_header( 'Bearer ' . $token );

		$this->assertFalse( OAuthServer::instance()->authenticate_bearer_token( false ) );

		delete_option( $this->token_option_name( $token ) );
	}

	/** MCP 401 responses advertise OAuth Protected Resource Metadata. */
	public function test_mcp_unauthorized_response_gets_bearer_challenge(): void {
		$request  = new WP_REST_Request( 'POST', '/mcp/mcp-adapter-default-server' );
		$response = new WP_REST_Response( array(), 401 );

		$response = OAuthServer::instance()->add_bearer_challenge( $response, rest_get_server(), $request );
		$headers  = $response->get_headers();

		$this->assertArrayHasKey( 'WWW-Authenticate', $headers );
		$this->assertSame(
			'Bearer resource_metadata="' . OAuthServer::issuer() . '/.well-known/oauth-protected-resource"',
			$headers['WWW-Authenticate']
		);
	}

	/** Non-MCP REST responses are not modified by the OAuth challenge hook. */
	public function test_non_mcp_unauthorized_response_does_not_get_bearer_challenge(): void {
		$request  = new WP_REST_Request( 'GET', '/wp/v2/posts' );
		$response = new WP_REST_Response( array(), 401 );

		$response = OAuthServer::instance()->add_bearer_challenge( $response, rest_get_server(), $request );

		$this->assertArrayNotHasKey( 'WWW-Authenticate', $response->get_headers() );
	}

	/** An MCP permission failure that is not a 401 does not receive an authentication challenge. */
	public function test_mcp_forbidden_response_does_not_get_bearer_challenge(): void {
		$request  = new WP_REST_Request( 'POST', '/mcp/mcp-adapter-default-server' );
		$response = new WP_REST_Response( array(), 403 );

		$response = OAuthServer::instance()->add_bearer_challenge( $response, rest_get_server(), $request );

		$this->assertArrayNotHasKey( 'WWW-Authenticate', $response->get_headers() );
	}

	/** PKCE uses RFC 7636 S256 encoding. */
	public function test_pkce_s256_challenge_matches_rfc_vector(): void {
		$verifier  = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';
		$challenge = $this->invoke_private( 'pkce_challenge', array( $verifier ) );

		$this->assertSame( 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', $challenge );
	}

	/** Redirect URIs require HTTPS except for loopback development clients. */
	public function test_redirect_uri_validation_allows_https_and_loopback_only(): void {
		$this->assertTrue( $this->invoke_private( 'valid_redirect_uri', array( 'https://client.example/callback' ) ) );
		$this->assertTrue( $this->invoke_private( 'valid_redirect_uri', array( 'http://127.0.0.1:8080/callback' ) ) );
		$this->assertTrue( $this->invoke_private( 'valid_redirect_uri', array( 'http://localhost:8080/callback' ) ) );
		$this->assertFalse( $this->invoke_private( 'valid_redirect_uri', array( 'http://client.example/callback' ) ) );
		$this->assertFalse( $this->invoke_private( 'valid_redirect_uri', array( 'javascript:alert(1)' ) ) );
	}

	/** Redirect metadata drops invalid and duplicate values. */
	public function test_redirect_uri_sanitization_filters_invalid_values(): void {
		$redirects = $this->invoke_private(
			'sanitize_redirect_uris',
			array(
				array(
					'https://client.example/callback',
					'https://client.example/callback',
					'http://client.example/insecure',
					123,
				),
			)
		);

		$this->assertSame( array( 'https://client.example/callback' ), $redirects );
	}

	/**
	 * Save and replace the Authorization header.
	 */
	private function set_authorization_header( string $value ): void {
		if ( null === $this->previous_authorization_header && isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			$this->previous_authorization_header = (string) $_SERVER['HTTP_AUTHORIZATION'];
		}

		$_SERVER['HTTP_AUTHORIZATION'] = $value;
	}

	/**
	 * Store an OAuth token record using the same hash-derived key as OAuthServer.
	 *
	 * @param array<string, mixed> $record Token record.
	 */
	private function store_token_record( string $token, array $record ): void {
		update_option( $this->token_option_name( $token ), $record, false );
	}

	/**
	 * Resolve the production option key without exposing token storage publicly.
	 */
	private function token_option_name( string $token ): string {
		return 'mcp_adapter_oauth_token_' . hash( 'sha256', $token );
	}

	/**
	 * Invoke a private OAuthServer helper for deterministic primitive tests.
	 *
	 * @param list<mixed> $arguments Method arguments.
	 * @return mixed
	 */
	private function invoke_private( string $method_name, array $arguments = array() ) {
		$method = new ReflectionMethod( OAuthServer::class, $method_name );
		if ( PHP_VERSION_ID < 80100 ) {
			$method->setAccessible( true );
		}

		return $method->invokeArgs( OAuthServer::instance(), $arguments );
	}
}
