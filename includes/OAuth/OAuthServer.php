<?php
/**
 * Built-in OAuth 2.1 support for the MCP HTTP transport.
 *
 * @package WP\MCP\OAuth
 */

declare( strict_types=1 );

namespace WP\MCP\OAuth;

use WP_Error;
use WP_REST_Request;
use WP_REST_Response;

defined( 'ABSPATH' ) || exit;

/**
 * Minimal WordPress-native OAuth 2.1 authorization server for MCP.
 *
 * Authentication stays local to WordPress: users sign in with their WordPress
 * account, and bearer tokens resolve directly to WP_User IDs. WordPress
 * capabilities and Ability permission callbacks remain authoritative.
 */
final class OAuthServer {

	private const ACCESS_TTL  = HOUR_IN_SECONDS;
	private const REFRESH_TTL = 30 * DAY_IN_SECONDS;
	private const CODE_TTL    = 5 * MINUTE_IN_SECONDS;
	private const SCOPE       = 'mcp:access';

	/**
	 * Singleton.
	 *
	 * @var self|null
	 */
	private static ?self $instance = null;

	/**
	 * Get singleton.
	 */
	public static function instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}

		return self::$instance;
	}

	/**
	 * Register OAuth hooks.
	 */
	public function init(): void {
		add_filter( 'determine_current_user', array( $this, 'authenticate_bearer_token' ), 19 );
		add_action( 'parse_request', array( $this, 'maybe_handle_oauth_route' ), 1 );
		add_filter( 'rest_post_dispatch', array( $this, 'add_bearer_challenge' ), 10, 3 );
	}

	/**
	 * MCP protected resource URL.
	 */
	public static function resource_url(): string {
		return rest_url( 'mcp/mcp-adapter-default-server' );
	}

	/**
	 * OAuth issuer URL.
	 */
	public static function issuer(): string {
		return untrailingslashit( home_url( '/' ) );
	}

	/**
	 * Resolve a Bearer token to a WordPress user.
	 *
	 * Existing WordPress authentication, including Application Passwords and
	 * cookies, is left untouched.
	 *
	 * @param int|false $user_id Existing authenticated user ID.
	 * @return int|false
	 */
	public function authenticate_bearer_token( $user_id ) {
		if ( $user_id ) {
			return $user_id;
		}

		$header = $this->authorization_header();
		if ( ! preg_match( '/^Bearer\s+([^\s]+)$/i', $header, $matches ) ) {
			return $user_id;
		}

		$record = $this->get_token_record( $matches[1], 'access' );
		if ( null === $record ) {
			return $user_id;
		}

		return (int) $record['user_id'];
	}

	/**
	 * Add a Bearer challenge to unauthenticated MCP responses.
	 *
	 * @param WP_REST_Response $response REST response.
	 * @param mixed            $server   REST server.
	 * @param WP_REST_Request  $request  REST request.
	 */
	public function add_bearer_challenge( $response, $server, $request ): WP_REST_Response {
		unset( $server );

		if (
			$response instanceof WP_REST_Response
			&& 401 === $response->get_status()
			&& false !== strpos( $request->get_route(), '/mcp/' )
		) {
			$response->header(
				'WWW-Authenticate',
				'Bearer resource_metadata="' . self::issuer() . '/.well-known/oauth-protected-resource"'
			);
		}

		return $response;
	}

	/**
	 * Handle OAuth and discovery routes before template dispatch.
	 */
	public function maybe_handle_oauth_route(): void {
		$path = wp_parse_url( isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/', PHP_URL_PATH );
		$path = '/' . ltrim( (string) $path, '/' );

		switch ( untrailingslashit( $path ) ) {
			case '/.well-known/oauth-protected-resource':
				$this->protected_resource_metadata();
				break;
			case '/.well-known/oauth-authorization-server':
				$this->authorization_server_metadata();
				break;
			case '/oauth/register':
				$this->register_client();
				break;
			case '/oauth/authorize':
				$this->authorize();
				break;
			case '/oauth/token':
				$this->token();
				break;
			case '/oauth/revoke':
				$this->revoke();
				break;
		}
	}

	/**
	 * Protected Resource Metadata.
	 */
	private function protected_resource_metadata(): void {
		$this->require_method( 'GET' );

		$this->json(
			array(
				'resource'              => self::resource_url(),
				'authorization_servers' => array( self::issuer() ),
				'scopes_supported'      => array( self::SCOPE ),
			)
		);
	}

	/**
	 * Authorization Server Metadata.
	 */
	private function authorization_server_metadata(): void {
		$this->require_method( 'GET' );

		$issuer = self::issuer();

		$this->json(
			array(
				'issuer'                                         => $issuer,
				'authorization_endpoint'                         => $issuer . '/oauth/authorize',
				'token_endpoint'                                 => $issuer . '/oauth/token',
				'registration_endpoint'                          => $issuer . '/oauth/register',
				'revocation_endpoint'                            => $issuer . '/oauth/revoke',
				'response_types_supported'                       => array( 'code' ),
				'grant_types_supported'                          => array( 'authorization_code', 'refresh_token' ),
				'code_challenge_methods_supported'               => array( 'S256' ),
				'token_endpoint_auth_methods_supported'          => array( 'none' ),
				'scopes_supported'                               => array( self::SCOPE ),
				'client_id_metadata_document_supported'          => true,
				'authorization_response_iss_parameter_supported' => true,
			)
		);
	}

	/**
	 * Dynamic Client Registration for public MCP clients.
	 */
	private function register_client(): void {
		$this->require_method( 'POST' );

		$input = json_decode( (string) file_get_contents( 'php://input' ), true );
		if ( ! is_array( $input ) ) {
			$this->oauth_error( 'invalid_client_metadata', 'A JSON client metadata document is required.', 400 );
		}

		$redirect_uris = isset( $input['redirect_uris'] ) && is_array( $input['redirect_uris'] ) ? $input['redirect_uris'] : array();
		$redirect_uris = array_values( array_filter( array_map( 'esc_url_raw', $redirect_uris ), array( $this, 'valid_redirect_uri' ) ) );

		if ( empty( $redirect_uris ) ) {
			$this->oauth_error( 'invalid_redirect_uri', 'At least one valid redirect URI is required.', 400 );
		}

		$client_id = 'mcp_' . wp_generate_password( 32, false, false );
		$record    = array(
			'client_id'     => $client_id,
			'redirect_uris' => $redirect_uris,
			'client_name'   => isset( $input['client_name'] ) ? sanitize_text_field( $input['client_name'] ) : 'MCP Client',
			'created_at'    => time(),
		);

		update_option( $this->client_option_name( $client_id ), $record, false );

		$this->json(
			array(
				'client_id'                  => $client_id,
				'client_name'                => $record['client_name'],
				'redirect_uris'              => $redirect_uris,
				'token_endpoint_auth_method' => 'none',
				'grant_types'                => array( 'authorization_code', 'refresh_token' ),
				'response_types'             => array( 'code' ),
			),
			201
		);
	}

	/**
	 * Authorization endpoint.
	 */
	private function authorize(): void {
		if ( ! in_array( $this->method(), array( 'GET', 'POST' ), true ) ) {
			$this->oauth_error( 'invalid_request', 'Authorization endpoint requires GET or POST.', 405 );
		}

		$params  = 'POST' === $this->method() ? wp_unslash( $_POST ) : wp_unslash( $_GET );
		$request = $this->validate_authorization_request( $params );

		if ( is_wp_error( $request ) ) {
			$this->oauth_error( $request->get_error_code(), $request->get_error_message(), 400 );
		}

		if ( ! is_user_logged_in() ) {
			wp_safe_redirect( wp_login_url( $this->current_url() ) );
			exit;
		}

		if ( 'POST' !== $this->method() ) {
			$this->render_consent( $request );
		}

		$nonce = isset( $params['_wpnonce'] ) ? sanitize_text_field( $params['_wpnonce'] ) : '';
		if ( ! wp_verify_nonce( $nonce, 'mcp_adapter_oauth_authorize' ) ) {
			$this->oauth_error( 'access_denied', 'Invalid authorization confirmation.', 403 );
		}

		if ( 'allow' !== ( isset( $params['decision'] ) ? sanitize_key( $params['decision'] ) : '' ) ) {
			$this->redirect_authorization_error( $request, 'access_denied' );
		}

		$code = $this->random_token( 32 );
		set_transient(
			$this->code_transient_name( $code ),
			array(
				'user_id'        => get_current_user_id(),
				'client_id'      => $request['client_id'],
				'redirect_uri'   => $request['redirect_uri'],
				'resource'       => $request['resource'],
				'scope'          => self::SCOPE,
				'code_challenge' => $request['code_challenge'],
			),
			self::CODE_TTL
		);

		$redirect = add_query_arg(
			array_filter(
				array(
					'code'  => $code,
					'state' => $request['state'],
					'iss'   => self::issuer(),
				),
				static fn( $value ) => '' !== $value
			),
			$request['redirect_uri']
		);

		wp_redirect( $redirect ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- Redirect URI was validated against registered client metadata.
		exit;
	}

	/**
	 * Token endpoint.
	 */
	private function token(): void {
		$this->require_method( 'POST' );

		$params     = wp_unslash( $_POST );
		$grant_type = isset( $params['grant_type'] ) ? sanitize_text_field( $params['grant_type'] ) : '';

		if ( 'authorization_code' === $grant_type ) {
			$this->exchange_authorization_code( $params );
		}

		if ( 'refresh_token' === $grant_type ) {
			$this->exchange_refresh_token( $params );
		}

		$this->oauth_error( 'unsupported_grant_type', 'Unsupported OAuth grant type.', 400 );
	}

	/**
	 * Exchange an authorization code.
	 *
	 * @param array<string, mixed> $params Request parameters.
	 */
	private function exchange_authorization_code( array $params ): void {
		$code          = isset( $params['code'] ) ? sanitize_text_field( $params['code'] ) : '';
		$client_id     = isset( $params['client_id'] ) ? sanitize_text_field( $params['client_id'] ) : '';
		$redirect_uri  = isset( $params['redirect_uri'] ) ? esc_url_raw( $params['redirect_uri'] ) : '';
		$resource      = isset( $params['resource'] ) ? esc_url_raw( $params['resource'] ) : '';
		$code_verifier = isset( $params['code_verifier'] ) ? sanitize_text_field( $params['code_verifier'] ) : '';

		$transient = $this->code_transient_name( $code );
		$record    = get_transient( $transient );

		if ( ! is_array( $record ) ) {
			$this->oauth_error( 'invalid_grant', 'Authorization code is invalid or expired.', 400 );
		}

		delete_transient( $transient );

		if (
			! hash_equals( (string) $record['client_id'], $client_id )
			|| ! hash_equals( (string) $record['redirect_uri'], $redirect_uri )
			|| ! hash_equals( (string) $record['resource'], $resource )
			|| ! hash_equals( (string) $record['code_challenge'], $this->pkce_challenge( $code_verifier ) )
		) {
			$this->oauth_error( 'invalid_grant', 'Authorization code validation failed.', 400 );
		}

		$this->issue_token_pair(
			(int) $record['user_id'],
			(string) $record['client_id'],
			(string) $record['resource']
		);
	}

	/**
	 * Exchange and rotate a refresh token.
	 *
	 * @param array<string, mixed> $params Request parameters.
	 */
	private function exchange_refresh_token( array $params ): void {
		$refresh_token = isset( $params['refresh_token'] ) ? sanitize_text_field( $params['refresh_token'] ) : '';
		$client_id     = isset( $params['client_id'] ) ? sanitize_text_field( $params['client_id'] ) : '';
		$resource      = isset( $params['resource'] ) ? esc_url_raw( $params['resource'] ) : '';
		$record        = $this->get_token_record( $refresh_token, 'refresh' );

		if (
			null === $record
			|| ! hash_equals( (string) $record['client_id'], $client_id )
			|| ! hash_equals( (string) $record['resource'], $resource )
		) {
			$this->oauth_error( 'invalid_grant', 'Refresh token is invalid or expired.', 400 );
		}

		delete_option( $this->token_option_name( $refresh_token ) );
		$this->issue_token_pair( (int) $record['user_id'], $client_id, $resource );
	}

	/**
	 * Revoke a token.
	 */
	private function revoke(): void {
		$this->require_method( 'POST' );

		$token = isset( $_POST['token'] ) ? sanitize_text_field( wp_unslash( $_POST['token'] ) ) : '';
		if ( '' !== $token ) {
			delete_option( $this->token_option_name( $token ) );
		}

		status_header( 200 );
		exit;
	}

	/**
	 * Validate authorization request.
	 *
	 * @param array<string, mixed> $params Request params.
	 * @return array<string, string>|WP_Error
	 */
	private function validate_authorization_request( array $params ) {
		$data = array(
			'response_type'  => isset( $params['response_type'] ) ? sanitize_text_field( $params['response_type'] ) : '',
			'client_id'      => isset( $params['client_id'] ) ? sanitize_text_field( $params['client_id'] ) : '',
			'redirect_uri'   => isset( $params['redirect_uri'] ) ? esc_url_raw( $params['redirect_uri'] ) : '',
			'code_challenge' => isset( $params['code_challenge'] ) ? sanitize_text_field( $params['code_challenge'] ) : '',
			'resource'       => isset( $params['resource'] ) ? esc_url_raw( $params['resource'] ) : '',
			'scope'          => isset( $params['scope'] ) ? sanitize_text_field( $params['scope'] ) : self::SCOPE,
			'state'          => isset( $params['state'] ) ? sanitize_text_field( $params['state'] ) : '',
		);

		$method = isset( $params['code_challenge_method'] ) ? sanitize_text_field( $params['code_challenge_method'] ) : '';

		if ( 'code' !== $data['response_type'] ) {
			return new WP_Error( 'unsupported_response_type', 'Only authorization code flow is supported.' );
		}

		if ( 'S256' !== $method || ! preg_match( '/^[A-Za-z0-9_-]{43,128}$/', $data['code_challenge'] ) ) {
			return new WP_Error( 'invalid_request', 'PKCE S256 is required.' );
		}

		if ( self::resource_url() !== $data['resource'] ) {
			return new WP_Error( 'invalid_target', 'The OAuth resource does not match this MCP endpoint.' );
		}

		if ( self::SCOPE !== $data['scope'] ) {
			return new WP_Error( 'invalid_scope', 'The requested OAuth scope is not supported.' );
		}

		$client = $this->get_client( $data['client_id'] );
		if ( is_wp_error( $client ) ) {
			return $client;
		}

		if ( ! in_array( $data['redirect_uri'], $client['redirect_uris'], true ) ) {
			return new WP_Error( 'invalid_redirect_uri', 'The redirect URI is not registered for this client.' );
		}

		return $data;
	}

	/**
	 * Resolve a DCR client or a Client ID Metadata Document (CIMD).
	 *
	 * @param string $client_id Client identifier.
	 * @return array<string, mixed>|WP_Error
	 */
	private function get_client( string $client_id ) {
		$registered = get_option( $this->client_option_name( $client_id ) );
		if ( is_array( $registered ) ) {
			return $registered;
		}

		if ( ! wp_http_validate_url( $client_id ) || 'https' !== wp_parse_url( $client_id, PHP_URL_SCHEME ) ) {
			return new WP_Error( 'unauthorized_client', 'Unknown OAuth client.' );
		}

		$response = wp_safe_remote_get(
			$client_id,
			array(
				'timeout'     => 5,
				'redirection' => 2,
				'headers'     => array( 'Accept' => 'application/json' ),
			)
		);

		if ( is_wp_error( $response ) || 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new WP_Error( 'unauthorized_client', 'Unable to load client metadata.' );
		}

		$metadata      = json_decode( wp_remote_retrieve_body( $response ), true );
		$redirect_uris = is_array( $metadata ) && isset( $metadata['redirect_uris'] ) && is_array( $metadata['redirect_uris'] )
			? array_values( array_filter( array_map( 'esc_url_raw', $metadata['redirect_uris'] ), array( $this, 'valid_redirect_uri' ) ) )
			: array();

		if ( empty( $redirect_uris ) ) {
			return new WP_Error( 'unauthorized_client', 'Client metadata does not contain a valid redirect URI.' );
		}

		return array(
			'client_id'     => $client_id,
			'redirect_uris' => $redirect_uris,
			'client_name'   => isset( $metadata['client_name'] ) ? sanitize_text_field( $metadata['client_name'] ) : wp_parse_url( $client_id, PHP_URL_HOST ),
		);
	}

	/**
	 * Issue an opaque access/refresh token pair.
	 */
	private function issue_token_pair( int $user_id, string $client_id, string $resource ): void {
		$access  = $this->random_token( 32 );
		$refresh = $this->random_token( 48 );

		$this->store_token( $access, 'access', $user_id, $client_id, $resource, self::ACCESS_TTL );
		$this->store_token( $refresh, 'refresh', $user_id, $client_id, $resource, self::REFRESH_TTL );

		$this->json(
			array(
				'access_token'  => $access,
				'token_type'    => 'Bearer',
				'expires_in'    => self::ACCESS_TTL,
				'refresh_token' => $refresh,
				'scope'         => self::SCOPE,
			)
		);
	}

	/**
	 * Store a token record. Raw tokens are never persisted.
	 */
	private function store_token( string $token, string $type, int $user_id, string $client_id, string $resource, int $ttl ): void {
		update_option(
			$this->token_option_name( $token ),
			array(
				'type'      => $type,
				'user_id'   => $user_id,
				'client_id' => $client_id,
				'resource'  => $resource,
				'scope'     => self::SCOPE,
				'expires'   => time() + $ttl,
			),
			false
		);
	}

	/**
	 * Load and validate a stored token.
	 *
	 * @return array<string, mixed>|null
	 */
	private function get_token_record( string $token, string $type ): ?array {
		if ( '' === $token ) {
			return null;
		}

		$name   = $this->token_option_name( $token );
		$record = get_option( $name );

		if ( ! is_array( $record ) || $type !== ( $record['type'] ?? '' ) || time() >= (int) ( $record['expires'] ?? 0 ) ) {
			if ( is_array( $record ) ) {
				delete_option( $name );
			}
			return null;
		}

		if ( self::resource_url() !== ( $record['resource'] ?? '' ) ) {
			return null;
		}

		return $record;
	}

	/**
	 * Render a minimal WordPress-native consent page.
	 *
	 * @param array<string, string> $request Authorization request.
	 */
	private function render_consent( array $request ): void {
		$user   = wp_get_current_user();
		$client = $this->get_client( $request['client_id'] );
		$name   = is_array( $client ) ? (string) ( $client['client_name'] ?? $request['client_id'] ) : $request['client_id'];

		status_header( 200 );
		nocache_headers();
		header( 'Content-Type: text/html; charset=' . get_option( 'blog_charset' ) );
		?>
<!doctype html>
<html <?php language_attributes(); ?>>
<head>
	<meta charset="<?php bloginfo( 'charset' ); ?>">
	<meta name="viewport" content="width=device-width, initial-scale=1">
	<title><?php esc_html_e( 'Authorize MCP Client', 'mcp-adapter' ); ?></title>
	<style>
		body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f0f0f1;margin:0;padding:40px 20px;color:#1d2327}
		.card{max-width:620px;margin:0 auto;background:#fff;border:1px solid #dcdcde;border-radius:8px;padding:28px}
		.actions{display:flex;gap:10px;margin-top:24px}.button{border:0;border-radius:4px;padding:10px 16px;font-weight:600;cursor:pointer}
		.allow{background:#2271b1;color:#fff}.deny{background:#dcdcde;color:#1d2327}
	</style>
</head>
<body>
<div class="card">
	<h1><?php esc_html_e( 'Authorize MCP Client', 'mcp-adapter' ); ?></h1>
	<p><?php echo esc_html( sprintf( __( '%1$s wants to access this WordPress MCP server as %2$s.', 'mcp-adapter' ), $name, $user->display_name ) ); ?></p>
	<p><?php esc_html_e( 'The client receives MCP access with the same WordPress capabilities as this account. WordPress capability and Ability permission checks still apply.', 'mcp-adapter' ); ?></p>
	<form method="post" action="<?php echo esc_url( self::issuer() . '/oauth/authorize' ); ?>">
		<?php foreach ( $request as $field => $value ) : ?>
			<input type="hidden" name="<?php echo esc_attr( $field ); ?>" value="<?php echo esc_attr( $value ); ?>">
		<?php endforeach; ?>
		<input type="hidden" name="code_challenge_method" value="S256">
		<?php wp_nonce_field( 'mcp_adapter_oauth_authorize' ); ?>
		<div class="actions">
			<button class="button allow" type="submit" name="decision" value="allow"><?php esc_html_e( 'Allow', 'mcp-adapter' ); ?></button>
			<button class="button deny" type="submit" name="decision" value="deny"><?php esc_html_e( 'Deny', 'mcp-adapter' ); ?></button>
		</div>
	</form>
</div>
</body>
</html>
		<?php
		exit;
	}

	/**
	 * Redirect an authorization error to the validated client redirect URI.
	 *
	 * @param array<string, string> $request Authorization request.
	 */
	private function redirect_authorization_error( array $request, string $error ): void {
		$url = add_query_arg(
			array_filter(
				array(
					'error' => $error,
					'state' => $request['state'],
					'iss'   => self::issuer(),
				),
				static fn( $value ) => '' !== $value
			),
			$request['redirect_uri']
		);

		wp_redirect( $url ); // phpcs:ignore WordPress.Security.SafeRedirect.wp_redirect_wp_redirect -- Redirect URI was validated against registered client metadata.
		exit;
	}

	/**
	 * Validate redirect URI.
	 */
	private function valid_redirect_uri( string $uri ): bool {
		if ( ! wp_http_validate_url( $uri ) ) {
			return false;
		}

		$scheme = wp_parse_url( $uri, PHP_URL_SCHEME );
		$host   = wp_parse_url( $uri, PHP_URL_HOST );

		if ( 'https' === $scheme ) {
			return true;
		}

		return 'http' === $scheme && in_array( $host, array( '127.0.0.1', 'localhost', '::1' ), true );
	}

	/**
	 * Authorization header.
	 */
	private function authorization_header(): string {
		if ( isset( $_SERVER['HTTP_AUTHORIZATION'] ) ) {
			return trim( sanitize_text_field( wp_unslash( $_SERVER['HTTP_AUTHORIZATION'] ) ) );
		}

		if ( function_exists( 'getallheaders' ) ) {
			$headers = getallheaders();
			if ( isset( $headers['Authorization'] ) ) {
				return trim( sanitize_text_field( $headers['Authorization'] ) );
			}
		}

		return '';
	}

	/**
	 * Current request URL.
	 */
	private function current_url(): string {
		$scheme = is_ssl() ? 'https' : 'http';
		$host   = isset( $_SERVER['HTTP_HOST'] ) ? sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) : (string) wp_parse_url( home_url(), PHP_URL_HOST );
		$uri    = isset( $_SERVER['REQUEST_URI'] ) ? wp_unslash( $_SERVER['REQUEST_URI'] ) : '/';

		return $scheme . '://' . $host . $uri;
	}

	/**
	 * PKCE S256 challenge.
	 */
	private function pkce_challenge( string $verifier ): string {
		return rtrim( strtr( base64_encode( hash( 'sha256', $verifier, true ) ), '+/', '-_' ), '=' );
	}

	/**
	 * Generate an opaque URL-safe token.
	 */
	private function random_token( int $bytes ): string {
		return rtrim( strtr( base64_encode( random_bytes( $bytes ) ), '+/', '-_' ), '=' );
	}

	/**
	 * Hash-derived option key for token storage.
	 */
	private function token_option_name( string $token ): string {
		return 'mcp_adapter_oauth_token_' . hash( 'sha256', $token );
	}

	/**
	 * Hash-derived transient key for authorization codes.
	 */
	private function code_transient_name( string $code ): string {
		return 'mcp_oauth_code_' . hash( 'sha256', $code );
	}

	/**
	 * Hash-derived option key for dynamically registered clients.
	 */
	private function client_option_name( string $client_id ): string {
		return 'mcp_adapter_oauth_client_' . hash( 'sha256', $client_id );
	}

	/**
	 * Request method.
	 */
	private function method(): string {
		return isset( $_SERVER['REQUEST_METHOD'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ) ) ) : 'GET';
	}

	/**
	 * Enforce an HTTP method.
	 */
	private function require_method( string $method ): void {
		if ( $method !== $this->method() ) {
			$this->oauth_error( 'invalid_request', 'Unsupported HTTP method.', 405 );
		}
	}

	/**
	 * Emit a JSON response.
	 *
	 * @param array<string, mixed> $data Response data.
	 */
	private function json( array $data, int $status = 200 ): void {
		status_header( $status );
		nocache_headers();
		header( 'Content-Type: application/json; charset=UTF-8' );
		echo wp_json_encode( $data );
		exit;
	}

	/**
	 * Emit an OAuth JSON error.
	 */
	private function oauth_error( string $error, string $description, int $status ): void {
		$this->json(
			array(
				'error'             => $error,
				'error_description' => $description,
			),
			$status
		);
	}
}
