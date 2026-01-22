/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import * as ipaddr from 'ipaddr.js';
import type { MCPOAuthConfig } from './oauth-provider.js';
import { getErrorMessage } from '../utils/errors.js';
import { debugLogger } from '../utils/debugLogger.js';

/**
 * Error thrown when the discovered resource metadata does not match the expected resource.
 */
export class ResourceMismatchError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ResourceMismatchError';
  }
}

/**
 * OAuth authorization server metadata as per RFC 8414.
 */
export interface OAuthAuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  token_endpoint_auth_methods_supported?: string[];
  revocation_endpoint?: string;
  revocation_endpoint_auth_methods_supported?: string[];
  registration_endpoint?: string;
  response_types_supported?: string[];
  grant_types_supported?: string[];
  code_challenge_methods_supported?: string[];
  scopes_supported?: string[];
}

/**
 * OAuth protected resource metadata as per RFC 9728.
 */
export interface OAuthProtectedResourceMetadata {
  resource: string;
  authorization_servers?: string[];
  bearer_methods_supported?: string[];
  resource_documentation?: string;
  resource_signing_alg_values_supported?: string[];
  resource_encryption_alg_values_supported?: string[];
  resource_encryption_enc_values_supported?: string[];
}

export const FIVE_MIN_BUFFER_MS = 5 * 60 * 1000;

/**
 * Normalizes a URL by removing trailing slashes.
 * Used for flexible URL comparison per RFC 9728.
 *
 * @param url The URL to normalize
 * @returns The normalized URL without trailing slash
 */
function normalizeUrl(url: string): string {
  return url.replace(/\/$/, '');
}

/**
 * Classifies a hostname's IP address range.
 * @returns The range type, or null if not an IP address (e.g., domain name)
 */
function classifyHostname(
  hostname: string,
): 'private' | 'public' | 'multicast' | 'broadcast' | 'reserved' | null {
  if (hostname === 'localhost') {
    return 'private';
  }

  try {
    const addr = ipaddr.process(hostname);
    const range = addr.range();

    // Group private/local ranges together
    if (
      range === 'private' ||
      range === 'loopback' ||
      range === 'linkLocal' ||
      range === 'uniqueLocal'
    ) {
      return 'private';
    }

    // Return specific dangerous ranges
    if (
      range === 'multicast' ||
      range === 'broadcast' ||
      range === 'reserved'
    ) {
      return range;
    }

    // Everything else is public
    return 'public';
  } catch {
    // Not an IP address (domain name)
    return null;
  }
}

/**
 * Validates a URL to prevent SSRF attacks.
 * If the source URL (e.g., MCP server) is public, only allows public HTTPS URLs.
 * If the source URL is local/private, allows local/private URLs as well.
 *
 * @param url The URL to validate
 * @param sourceUrl The source URL (e.g., MCP server URL) to determine context
 * @returns Error message if validation fails, null if valid
 */
function validateUrlForSSRF(url: string, sourceUrl?: string): string | null {
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    return `Invalid URL: ${url}`;
  }

  // Only allow HTTP/HTTPS protocols
  if (parsedUrl.protocol !== 'https:' && parsedUrl.protocol !== 'http:') {
    return `Only HTTP/HTTPS protocols are allowed: ${url}`;
  }

  // Classify target and source
  const targetClass = classifyHostname(parsedUrl.hostname);
  const sourceClass = sourceUrl
    ? classifyHostname(new URL(sourceUrl).hostname)
    : null;

  // Block dangerous ranges immediately
  if (
    targetClass === 'multicast' ||
    targetClass === 'broadcast' ||
    targetClass === 'reserved'
  ) {
    return `${targetClass} address not allowed: ${parsedUrl.hostname}`;
  }

  // If target is private, only allow if source is also private
  if (targetClass === 'private' && sourceClass !== 'private') {
    return `Cannot fetch from local/private URL ${url} when source is public`;
  }

  // Allow HTTP only for local/private IPs (for development servers)
  // Require HTTPS for public IPs and domain names
  if (targetClass !== 'private' && parsedUrl.protocol !== 'https:') {
    return `HTTPS is required for non-local URLs: ${url}`;
  }

  return null;
}

/**
 * Utility class for common OAuth operations.
 */
export class OAuthUtils {
  /**
   * Construct well-known OAuth endpoint URLs.
   * By default, uses standard root-based well-known URLs.
   * If includePathSuffix is true, appends any path from the base URL to the well-known endpoints.
   */
  static buildWellKnownUrls(baseUrl: string, includePathSuffix = false) {
    const serverUrl = new URL(baseUrl);
    const base = `${serverUrl.protocol}//${serverUrl.host}`;

    if (!includePathSuffix) {
      // Standard discovery: use root-based well-known URLs
      return {
        protectedResource: new URL(
          '/.well-known/oauth-protected-resource',
          base,
        ).toString(),
        authorizationServer: new URL(
          '/.well-known/oauth-authorization-server',
          base,
        ).toString(),
      };
    }

    // Path-based discovery: append path suffix to well-known URLs
    const pathSuffix = serverUrl.pathname.replace(/\/$/, ''); // Remove trailing slash
    return {
      protectedResource: new URL(
        `/.well-known/oauth-protected-resource${pathSuffix}`,
        base,
      ).toString(),
      authorizationServer: new URL(
        `/.well-known/oauth-authorization-server${pathSuffix}`,
        base,
      ).toString(),
    };
  }

  /**
   * Fetch OAuth protected resource metadata.
   *
   * @param resourceMetadataUrl The protected resource metadata URL
   * @param sourceUrl Optional source URL for SSRF validation context
   * @returns The protected resource metadata or null if not available
   */
  static async fetchProtectedResourceMetadata(
    resourceMetadataUrl: string,
    sourceUrl?: string,
  ): Promise<OAuthProtectedResourceMetadata | null> {
    // Validate URL to prevent SSRF
    const ssrfError = validateUrlForSSRF(resourceMetadataUrl, sourceUrl);
    if (ssrfError) {
      debugLogger.error(
        `SSRF validation failed for protected resource metadata: ${ssrfError}`,
      );
      return null;
    }

    try {
      const response = await fetch(resourceMetadataUrl);
      if (!response.ok) {
        return null;
      }
      return (await response.json()) as OAuthProtectedResourceMetadata;
    } catch (error) {
      debugLogger.debug(
        `Failed to fetch protected resource metadata from ${resourceMetadataUrl}: ${getErrorMessage(error)}`,
      );
      return null;
    }
  }

  /**
   * Fetch OAuth authorization server metadata.
   *
   * @param authServerMetadataUrl The authorization server metadata URL
   * @param sourceUrl Optional source URL for SSRF validation context
   * @returns The authorization server metadata or null if not available
   */
  static async fetchAuthorizationServerMetadata(
    authServerMetadataUrl: string,
    sourceUrl?: string,
  ): Promise<OAuthAuthorizationServerMetadata | null> {
    // Validate URL to prevent SSRF
    const ssrfError = validateUrlForSSRF(authServerMetadataUrl, sourceUrl);
    if (ssrfError) {
      debugLogger.error(
        `SSRF validation failed for authorization server metadata: ${ssrfError}`,
      );
      return null;
    }

    try {
      const response = await fetch(authServerMetadataUrl);
      if (!response.ok) {
        return null;
      }
      return (await response.json()) as OAuthAuthorizationServerMetadata;
    } catch (error) {
      debugLogger.debug(
        `Failed to fetch authorization server metadata from ${authServerMetadataUrl}: ${getErrorMessage(error)}`,
      );
      return null;
    }
  }

  /**
   * Convert authorization server metadata to OAuth configuration.
   * Validates all URLs to prevent SSRF attacks.
   *
   * @param metadata The authorization server metadata
   * @param sourceUrl Optional source URL for SSRF validation context
   * @returns The OAuth configuration
   * @throws Error if any URLs fail SSRF validation
   */
  static metadataToOAuthConfig(
    metadata: OAuthAuthorizationServerMetadata,
    sourceUrl?: string,
  ): MCPOAuthConfig {
    // Validate all URLs in the metadata to prevent SSRF
    const urlsToValidate = [
      { name: 'issuer', url: metadata.issuer },
      { name: 'authorization_endpoint', url: metadata.authorization_endpoint },
      { name: 'token_endpoint', url: metadata.token_endpoint },
      { name: 'registration_endpoint', url: metadata.registration_endpoint },
    ];

    for (const { name, url } of urlsToValidate) {
      if (url) {
        const error = validateUrlForSSRF(url, sourceUrl);
        if (error) {
          throw new Error(
            `Invalid ${name} in authorization server metadata: ${error}`,
          );
        }
      }
    }

    return {
      authorizationUrl: metadata.authorization_endpoint,
      issuer: metadata.issuer,
      tokenUrl: metadata.token_endpoint,
      scopes: metadata.scopes_supported || [],
      registrationUrl: metadata.registration_endpoint,
    };
  }

  /**
   * Discover OAuth Authorization server metadata given an Auth server URL, by
   * trying the standard well-known endpoints.
   *
   * @param authServerUrl The authorization server URL
   * @param sourceUrl Optional source URL for SSRF validation context
   * @returns The authorization server metadata or null if not found
   */
  static async discoverAuthorizationServerMetadata(
    authServerUrl: string,
    sourceUrl?: string,
  ): Promise<OAuthAuthorizationServerMetadata | null> {
    const authServerUrlObj = new URL(authServerUrl);
    const base = `${authServerUrlObj.protocol}//${authServerUrlObj.host}`;

    const endpointsToTry: string[] = [];

    // With issuer URLs with path components, try the following well-known
    // endpoints in order:
    if (authServerUrlObj.pathname !== '/') {
      // 1. OAuth 2.0 Authorization Server Metadata with path insertion
      endpointsToTry.push(
        new URL(
          `/.well-known/oauth-authorization-server${authServerUrlObj.pathname}`,
          base,
        ).toString(),
      );

      // 2. OpenID Connect Discovery 1.0 with path insertion
      endpointsToTry.push(
        new URL(
          `/.well-known/openid-configuration${authServerUrlObj.pathname}`,
          base,
        ).toString(),
      );

      // 3. OpenID Connect Discovery 1.0 with path appending
      endpointsToTry.push(
        new URL(
          `${authServerUrlObj.pathname}/.well-known/openid-configuration`,
          base,
        ).toString(),
      );
    }

    // With issuer URLs without path components, and those that failed previous
    // discoveries, try the following well-known endpoints in order:

    // 1. OAuth 2.0 Authorization Server Metadata
    endpointsToTry.push(
      new URL('/.well-known/oauth-authorization-server', base).toString(),
    );

    // 2. OpenID Connect Discovery 1.0
    endpointsToTry.push(
      new URL('/.well-known/openid-configuration', base).toString(),
    );

    for (const endpoint of endpointsToTry) {
      const authServerMetadata = await this.fetchAuthorizationServerMetadata(
        endpoint,
        sourceUrl,
      );
      if (authServerMetadata) {
        return authServerMetadata;
      }
    }

    debugLogger.debug(
      `Metadata discovery failed for authorization server ${authServerUrl}`,
    );
    return null;
  }

  /**
   * Discover OAuth configuration using the standard well-known endpoints.
   *
   * @param serverUrl The base URL of the server (MCP server)
   * @returns The discovered OAuth configuration or null if not available
   */
  static async discoverOAuthConfig(
    serverUrl: string,
  ): Promise<MCPOAuthConfig | null> {
    try {
      // First try standard root-based discovery
      const wellKnownUrls = this.buildWellKnownUrls(serverUrl, false);

      // Try to get the protected resource metadata at root
      let resourceMetadata = await this.fetchProtectedResourceMetadata(
        wellKnownUrls.protectedResource,
        serverUrl,
      );

      // If root discovery fails and we have a path, try path-based discovery
      if (!resourceMetadata) {
        const url = new URL(serverUrl);
        if (url.pathname && url.pathname !== '/') {
          const pathBasedUrls = this.buildWellKnownUrls(serverUrl, true);
          resourceMetadata = await this.fetchProtectedResourceMetadata(
            pathBasedUrls.protectedResource,
            serverUrl,
          );
        }
      }

      if (resourceMetadata) {
        // RFC 9728 Section 7.3: The client MUST ensure that the resource identifier URL
        // it is using as the prefix for the metadata request exactly matches the value
        // of the resource metadata parameter in the protected resource metadata document.
        // Note: We normalize trailing slashes to be flexible with server implementations
        const expectedResource = this.buildResourceParameter(serverUrl);
        if (
          normalizeUrl(resourceMetadata.resource) !==
          normalizeUrl(expectedResource)
        ) {
          throw new ResourceMismatchError(
            `Protected resource ${resourceMetadata.resource} does not match expected ${expectedResource}`,
          );
        }
      }

      if (resourceMetadata?.authorization_servers?.length) {
        // Use the first authorization server
        const authServerUrl = resourceMetadata.authorization_servers[0];
        const authServerMetadata =
          await this.discoverAuthorizationServerMetadata(
            authServerUrl,
            serverUrl,
          );

        if (authServerMetadata) {
          const config = this.metadataToOAuthConfig(
            authServerMetadata,
            serverUrl,
          );
          if (authServerMetadata.registration_endpoint) {
            debugLogger.log(
              'Dynamic client registration is supported at:',
              authServerMetadata.registration_endpoint,
            );
          }
          return config;
        }
      }

      // Fallback: try well-known endpoints at the base URL
      debugLogger.debug(`Trying OAuth discovery fallback at ${serverUrl}`);
      const authServerMetadata = await this.discoverAuthorizationServerMetadata(
        serverUrl,
        serverUrl,
      );

      if (authServerMetadata) {
        const config = this.metadataToOAuthConfig(
          authServerMetadata,
          serverUrl,
        );
        if (authServerMetadata.registration_endpoint) {
          debugLogger.log(
            'Dynamic client registration is supported at:',
            authServerMetadata.registration_endpoint,
          );
        }
        return config;
      }

      return null;
    } catch (error) {
      if (error instanceof ResourceMismatchError) {
        throw error;
      }
      debugLogger.debug(
        `Failed to discover OAuth configuration: ${getErrorMessage(error)}`,
      );
      return null;
    }
  }

  /**
   * Parse WWW-Authenticate header to extract OAuth information.
   *
   * @param header The WWW-Authenticate header value
   * @returns The resource metadata URI if found
   */
  static parseWWWAuthenticateHeader(header: string): string | null {
    // Parse Bearer realm and resource_metadata
    const match = header.match(/resource_metadata="([^"]+)"/);
    if (match) {
      return match[1];
    }
    return null;
  }

  /**
   * Discover OAuth configuration from WWW-Authenticate header.
   *
   * @param wwwAuthenticate The WWW-Authenticate header value
   * @param mcpServerUrl Optional MCP server URL to validate against the resource metadata
   * @returns The discovered OAuth configuration or null if not available
   */
  static async discoverOAuthFromWWWAuthenticate(
    wwwAuthenticate: string,
    mcpServerUrl?: string,
  ): Promise<MCPOAuthConfig | null> {
    const resourceMetadataUri =
      this.parseWWWAuthenticateHeader(wwwAuthenticate);
    if (!resourceMetadataUri) {
      return null;
    }

    const resourceMetadata = await this.fetchProtectedResourceMetadata(
      resourceMetadataUri,
      mcpServerUrl,
    );

    if (resourceMetadata && mcpServerUrl) {
      // Validate resource parameter per RFC 9728 Section 7.3
      // Note: We normalize trailing slashes to be flexible with server implementations
      const expectedResource = this.buildResourceParameter(mcpServerUrl);
      if (
        normalizeUrl(resourceMetadata.resource) !==
        normalizeUrl(expectedResource)
      ) {
        throw new ResourceMismatchError(
          `Protected resource ${resourceMetadata.resource} does not match expected ${expectedResource}`,
        );
      }
    }

    if (!resourceMetadata?.authorization_servers?.length) {
      return null;
    }

    const authServerUrl = resourceMetadata.authorization_servers[0];
    const authServerMetadata = await this.discoverAuthorizationServerMetadata(
      authServerUrl,
      mcpServerUrl,
    );

    if (authServerMetadata) {
      return this.metadataToOAuthConfig(authServerMetadata, mcpServerUrl);
    }

    return null;
  }

  /**
   * Extract base URL from an MCP server URL.
   *
   * @param mcpServerUrl The MCP server URL
   * @returns The base URL
   */
  static extractBaseUrl(mcpServerUrl: string): string {
    const serverUrl = new URL(mcpServerUrl);
    return `${serverUrl.protocol}//${serverUrl.host}`;
  }

  /**
   * Check if a URL is an SSE endpoint.
   *
   * @param url The URL to check
   * @returns True if the URL appears to be an SSE endpoint
   */
  static isSSEEndpoint(url: string): boolean {
    return url.includes('/sse') || !url.includes('/mcp');
  }

  /**
   * Build a resource parameter for OAuth requests.
   * Per RFC 9728, the resource parameter should not include a trailing slash for root paths.
   *
   * @param endpointUrl The endpoint URL
   * @returns The resource parameter value
   */
  static buildResourceParameter(endpointUrl: string): string {
    const url = new URL(endpointUrl);
    const pathname = url.pathname === '/' ? '' : url.pathname;
    return `${url.protocol}//${url.host}${pathname}`;
  }

  /**
   * Parses a JWT string to extract its expiry time.
   * @param idToken The JWT ID token.
   * @returns The expiry time in **milliseconds**, or undefined if parsing fails.
   */
  static parseTokenExpiry(idToken: string): number | undefined {
    try {
      const payload = JSON.parse(
        Buffer.from(idToken.split('.')[1], 'base64').toString(),
      );

      if (payload && typeof payload.exp === 'number') {
        return payload.exp * 1000; // Convert seconds to milliseconds
      }
    } catch (e) {
      debugLogger.error(
        'Failed to parse ID token for expiry time with error:',
        e,
      );
    }

    // Return undefined if try block fails or 'exp' is missing/invalid
    return undefined;
  }
}
