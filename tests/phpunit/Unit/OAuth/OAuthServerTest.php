<?php
/**
 * OAuth server tests.
 *
 * @package WP\MCP\Tests
 */

declare( strict_types=1 );

namespace WP\MCP\Tests\Unit\OAuth;

use WP\MCP\OAuth\OAuthServer;
use WP\MCP\Tests\TestCase;

/**
 * Covers the built-in WordPress OAuth primitives without replacing WordPress
 * capability authorization.
 */
final class OAuthServerTest extends TestCase {

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

	/** A request without a Bearer token does not interfere with existing auth. */
	public function test_bearer_auth_does_not_replace_existing_wordpress_authentication(): void {
		$server = OAuthServer::instance();
		$this->assertSame( 123, $server->authenticate_bearer_token( 123 ) );
	}

	/** Non-Bearer Authorization headers are ignored so Application Passwords remain available. */
	public function test_basic_authorization_header_is_ignored(): void {
		$_SERVER['HTTP_AUTHORIZATION'] = 'Basic dXNlcjpwYXNz';

		$server = OAuthServer::instance();
		$this->assertFalse( $server->authenticate_bearer_token( false ) );

		unset( $_SERVER['HTTP_AUTHORIZATION'] );
	}
}
