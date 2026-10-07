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
	 * Request globals saved before a test mutates them.
	 *
	 * @var array<string, mixed>
	 */
	private array $saved_server = array();

	/**
	 * Query globals saved before a test mutates them.
	 *
	 * @var array<string, mixed>
	 */
	private array $saved_get = array();

	/**
	 * Save request globals before each test.
	 */
	public function setUp(): void {
		parent::setUp();

		foreach ( array( 'HTTP_AUTHORIZATION', 'REQUEST_URI', 'REMOTE_ADDR' ) as $key ) {
			if ( isset( $_SERVER[ $key ] ) ) {
				$this->saved_server[ $key ] = $_SERVER[ $key ];
			}
		}

		if ( isset( $_GET['rest_route'] ) ) {
			$this->saved_get['rest_route'] = $_GET['rest_route'];
		}
	}

	/**
	 * Restore request globals and remove OAuth test transients.
	 */
	public function tearDown(): void {
		foreach ( array( 'HTTP_AUTHORIZATION', 'REQUEST_URI', 'REMOTE_ADDR' ) as $key ) {
			if ( array_key_exists( $key, $this->saved_server ) ) {
				$_SERVER[ $key ] = $this->saved_server[ $key ];
			} else {
				unset( $_SERVER[ $key ] );
			}
		}

		if ( array_key_exists( 'rest_route', $this->saved_get ) ) {
			$_GET['rest_route'] = $this->saved_get['rest_route'];
		} else {
			unset( $_GET['rest_route'] );
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
		$this->set_mcp_request();
		$this->set_authorization_header( 'Basic dXNlcjpwYXNz' );

		$this->assertFalse( OAuthServer::instance()->authenticate_bearer_token( false ) );
	}

	/** Unknown Bearer tokens do not authenticate a WordPress user. */
	public function test_unknown_bearer_token_is_rejected(): void {
		$this->set_mcp_request();
		$this->set_authorization_header( 'Bearer definitely-not-a-valid-token' );

		$this->assertFalse( OAuthServer::instance()->authenticate_bearer_token( false ) );
	}

	/** A valid access token resolves directly to the WordPress user that authorized it. */
	public function test_valid_bearer_token_resolves_wordpress_user_on_mcp_resource(): void {
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
		$this->set_mcp_request();
		$this->set_authorization_header( 'Bearer ' . $token );

		$this->assertSame( 42, OAuthServer::instance()->authenticate_bearer_token( false ) );

		delete_transient( $this->token_option_name( $token ) );
	}

	/** MCP Bearer tokens never authenticate unrelated WordPress REST endpoints. */
	public function test_valid_mcp_bearer_token_does_not_authenticate_other_rest_routes(): void {
		$token = 'resource-scoped-access-token';
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
		$_SERVER['REQUEST_URI'] = '/wp-json/wp/v2/posts';
		$this->set_authorization_header( 'Bearer ' . $token );

		$this->assertFalse( OAuthServer::instance()->authenticate_bearer_token( false ) );

		delete_transient( $this->token_option_name( $token ) );
	}

	/** Query-style WordPress REST routing still identifies the default MCP resource. */
	public function test_bearer_auth_supports_rest_route_query_parameter(): void {
		$token = 'query-route-access-token';
		$this->store_token_record(
			$token,
			array(
				'type'      => 'access',
				'user_id'   => 43,
				'client_id' => 'test-client',
				'resource'  => OAuthServer::resource_url(),
				'scope'     => 'mcp:access',
				'expires'   => time() + HOUR_IN_SECONDS,
			)
		);
		$_SERVER['REQUEST_URI'] = '/?rest_route=/mcp/mcp-adapter-default-server';
		$_GET['rest_route']     = '/mcp/mcp-adapter-default-server';
		$this->set_authorization_header( 'Bearer ' . $token );

		$this->assertSame( 43, OAuthServer::instance()->authenticate_bearer_token( false ) );

		delete_transient( $this->token_option_name( $token ) );
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
			),
			HOUR_IN_SECONDS
		);
		$this->set_mcp_request();
		$this->set_authorization_header( 'Bearer ' . $token );

		$this->assertFalse( OAuthServer::instance()->authenticate_bearer_token( false ) );
		$this->assertFalse( get_transient( $name ) );
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
		$this->set_mcp_request();
		$this->set_authorization_header( 'Bearer ' . $token );

		$this->assertFalse( OAuthServer::instance()->authenticate_bearer_token( false ) );

		delete_transient( $this->token_option_name( $token ) );
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
		$this->set_mcp_request();
		$this->set_authorization_header( 'Bearer ' . $token );

		$this->assertFalse( OAuthServer::instance()->authenticate_bearer_token( false ) );

		delete_transient( $this->token_option_name( $token ) );
	}

	/** MCP 401 responses advertise the path-aware Protected Resource Metadata URL. */
	public function test_mcp_unauthorized_response_gets_bearer_challenge(): void {
		$request  = new WP_REST_Request( 'POST', '/mcp/mcp-adapter-default-server' );
		$response = new WP_REST_Response( array(), 401 );

		$response = OAuthServer::instance()->add_bearer_challenge( $response, rest_get_server(), $request );
		$headers  = $response->get_headers();

		$this->assertArrayHasKey( 'WWW-Authenticate', $headers );
		$this->assertSame(
			'Bearer resource_metadata="' . OAuthServer::protected_resource_metadata_url() . '"',
			$headers['WWW-Authenticate']
		);
	}

	/** Other MCP-like routes do not receive the default resource challenge. */
	public function test_other_mcp_route_does_not_get_default_resource_challenge(): void {
		$request  = new WP_REST_Request( 'POST', '/mcp/another-server' );
		$response = new WP_REST_Response( array(), 401 );

		$response = OAuthServer::instance()->add_bearer_challenge( $response, rest_get_server(), $request );

		$this->assertArrayNotHasKey( 'WWW-Authenticate', $response->get_headers() );
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

	/** Well-known URLs preserve issuer/resource paths for subdirectory installations. */
	public function test_well_known_urls_are_path_aware(): void {
		$this->assertSame(
			'https://example.com/.well-known/oauth-authorization-server/wordpress',
			$this->invoke_static_private( 'well_known_url', array( 'oauth-authorization-server', 'https://example.com/wordpress' ) )
		);
		$this->assertSame(
			'https://example.com/.well-known/oauth-protected-resource/wordpress/wp-json/mcp/server',
			$this->invoke_static_private( 'well_known_url', array( 'oauth-protected-resource', 'https://example.com/wordpress/wp-json/mcp/server' ) )
		);
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

	/** CIMD client identifiers must be secure metadata-document URLs. */
	public function test_cimd_client_id_validation_rejects_unsafe_forms(): void {
		$this->assertFalse( $this->invoke_private( 'valid_cimd_client_id', array( 'http://client.example/metadata.json' ) ) );
		$this->assertFalse( $this->invoke_private( 'valid_cimd_client_id', array( 'https://user:pass@client.example/metadata.json' ) ) );
		$this->assertFalse( $this->invoke_private( 'valid_cimd_client_id', array( 'https://client.example/metadata.json#fragment' ) ) );
		$this->assertFalse( $this->invoke_private( 'valid_cimd_client_id', array( 'https://client.example/' ) ) );
	}

	/** DCR writes are bounded per source address to prevent unbounded database growth. */
	public function test_dcr_rate_limit_is_bounded(): void {
		$_SERVER['REMOTE_ADDR'] = '192.0.2.55';
		$key                    = 'mcp_oauth_dcr_rate_' . hash( 'sha256', '192.0.2.55' );
		delete_transient( $key );

		for ( $i = 0; $i < 20; $i++ ) {
			$this->assertTrue( $this->invoke_private( 'consume_dcr_rate_limit' ) );
		}

		$this->assertFalse( $this->invoke_private( 'consume_dcr_rate_limit' ) );
		delete_transient( $key );
	}

	/**
	 * Point request globals at the canonical default MCP resource.
	 */
	private function set_mcp_request(): void {
		$_SERVER['REQUEST_URI'] = (string) wp_parse_url( OAuthServer::resource_url(), PHP_URL_PATH );
		unset( $_GET['rest_route'] );
	}

	/**
	 * Replace the Authorization header for a request.
	 */
	private function set_authorization_header( string $value ): void {
		$_SERVER['HTTP_AUTHORIZATION'] = $value;
	}

	/**
	 * Store an OAuth token record using the same transient key as OAuthServer.
	 *
	 * @param array<string, mixed> $record Token record.
	 */
	private function store_token_record( string $token, array $record, int $ttl = HOUR_IN_SECONDS ): void {
		set_transient( $this->token_option_name( $token ), $record, $ttl );
	}

	/**
	 * Resolve the production transient key without exposing token storage publicly.
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

	/**
	 * Invoke a private static OAuthServer helper.
	 *
	 * @param list<mixed> $arguments Method arguments.
	 * @return mixed
	 */
	private function invoke_static_private( string $method_name, array $arguments = array() ) {
		$method = new ReflectionMethod( OAuthServer::class, $method_name );
		if ( PHP_VERSION_ID < 80100 ) {
			$method->setAccessible( true );
		}

		return $method->invokeArgs( null, $arguments );
	}
}
