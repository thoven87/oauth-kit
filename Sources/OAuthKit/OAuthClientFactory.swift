//===----------------------------------------------------------------------===//
//
// This source file is part of the oauth-kit open source project
//
// Copyright (c) 2025 the oauth-kit project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of oauth-kit project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import AsyncHTTPClient
import Foundation
import Logging

/// The main entry point for OAuthKit functionality.
///
/// `OAuthClientFactory` provides factory methods for creating OAuth2 and OpenID Connect clients
/// for various providers. It manages the underlying HTTP client and logging configuration
/// used by all OAuth operations.
///
/// ## Creating OAuth Clients
///
/// Use the factory methods to create provider-specific OAuth clients:
///
/// ```swift
/// let oauthKit = OAuthClientFactory()
///
/// // Google Sign-In
/// let googleProvider = try await oauthKit.googleProvider(
///     clientID: "your-client-id",
///     clientSecret: "your-client-secret",
///     redirectURI: "https://your-app.com/callback"
/// )
///
/// // Microsoft with tenant support
/// let microsoftProvider = try await oauthKit.microsoftProvider(
///     clientID: "your-client-id",
///     clientSecret: "your-client-secret",
///     redirectURI: "https://your-app.com/callback",
///     tenantKind: .organizations
/// )
/// ```
///
/// ## Custom Configuration
///
/// You can customize the HTTP client and logger used by all OAuth operations:
///
/// ```swift
/// let customLogger = Logger(label: "my-oauth-app")
/// let oauthKit = OAuthClientFactory(
///     httpClient: HTTPClient.shared,
///     logger: customLogger
/// )
/// ```
///
/// ## Supported Providers
///
/// OAuthKit includes built-in support for 15+ OAuth providers:
/// - Google (with Service Account support)
/// - Microsoft 365 / Azure AD (with multi-tenant support)
/// - Auth0 (with Management API)
/// - Discord (with bot permissions)
/// - LinkedIn (professional networking)
/// - GitLab (with self-hosted support)
/// - Dropbox (file storage)
/// - Apple (Sign in with Apple)
/// - GitHub (developer platform)
/// - Facebook (social platform)
/// - Slack (workspace integration)
/// - AWS Cognito (serverless auth)
/// - Okta (enterprise identity)
/// - KeyCloak (self-hosted identity)
///
/// ## Thread Safety
///
/// `OAuthClientFactory` is `Sendable` and thread-safe. You can safely share instances
/// across multiple tasks and actors.
public struct OAuthClientFactory: Sendable {
    /// The HTTP client used for making requests
    internal let httpClient: HTTPClient

    /// Logger used for OAuth operations
    public let logger: Logger

    /// Create a new OAuthKit instance with optional custom configuration.
    ///
    /// - Parameters:
    ///   - httpClient: The HTTP client used for making OAuth requests. Defaults to `HTTPClient.shared`.
    ///   - logger: Logger used for OAuth operations and debugging. Defaults to a logger labeled "com.oauthkit.OAuthKit".
    ///
    /// ## Example
    ///
    /// ```swift
    /// // Use default configuration
    /// let oauthKit = OAuthClientFactory()
    ///
    /// // Custom configuration
    /// let customLogger = Logger(label: "my-app.oauth")
    /// let oauthKit = OAuthClientFactory(
    ///     httpClient: HTTPClient.shared,
    ///     logger: customLogger
    /// )
    /// ```
    public init(httpClient: HTTPClient = HTTPClient.shared, logger: Logger = Logger(label: "com.oauthkit.OAuthKit")) {
        self.httpClient = httpClient
        self.logger = logger
    }

    /// Creates a generic OAuth2 client for custom or unsupported providers.
    ///
    /// Use this method when you need to integrate with an OAuth2 provider that doesn't have
    /// a built-in provider in OAuthKit, or when you need custom OAuth2 client configuration.
    ///
    /// - Parameters:
    ///   - clientID: The client ID provided by the OAuth2 provider
    ///   - clientSecret: The client secret provided by the OAuth2 provider
    ///   - tokenEndpoint: The token endpoint URL for exchanging authorization codes
    ///   - authorizationEndpoint: Optional authorization endpoint URL for generating auth URLs
    ///   - redirectURI: Optional redirect URI registered with the OAuth2 provider
    /// - Returns: A configured OAuth2 client instance
    ///
    /// ## Example
    ///
    /// ```swift
    /// let oauth2Client = oauthKit.oauth2Client(
    ///     clientID: "your-client-id",
    ///     clientSecret: "your-client-secret",
    ///     tokenEndpoint: "https://provider.com/oauth/token",
    ///     authorizationEndpoint: "https://provider.com/oauth/authorize",
    ///     redirectURI: "https://your-app.com/callback"
    /// )
    /// ```
    public func oauth2Client(
        clientID: String,
        clientSecret: String,
        tokenEndpoint: String,
        authorizationEndpoint: String? = nil,
        redirectURI: String? = nil
    ) -> OAuth2Client {
        OAuth2Client(
            httpClient: httpClient,
            clientID: clientID,
            clientSecret: clientSecret,
            tokenEndpoint: tokenEndpoint,
            authorizationEndpoint: authorizationEndpoint,
            redirectURI: redirectURI,
            logger: logger
        )
    }

    /// Creates an OpenID Connect client with automatic discovery configuration.
    ///
    /// This method automatically discovers the OIDC provider's configuration using the
    /// `.well-known/openid-configuration` endpoint and creates a fully configured client.
    ///
    /// - Parameters:
    ///   - discoveryURL: The base URL for OpenID Connect discovery (e.g., "https://accounts.google.com")
    ///   - clientID: The client ID provided by the OIDC provider
    ///   - clientSecret: The client secret provided by the OIDC provider
    ///   - redirectURI: Optional redirect URI registered with the OIDC provider
    /// - Returns: A configured OpenID Connect client
    /// - Throws: `OAuth2Error` if discovery fails or configuration is invalid
    ///
    /// ## Example
    ///
    /// ```swift
    /// let oidcClient = try await oauthKit.openIDConnectClient(
    ///     discoveryURL: "https://login.microsoftonline.com/common/v2.0",
    ///     clientID: "your-client-id",
    ///     clientSecret: "your-client-secret",
    ///     redirectURI: "https://your-app.com/callback"
    /// )
    /// ```
    public func openIDConnectClient(
        discoveryURL: String,
        clientID: String,
        clientSecret: String,
        redirectURI: String? = nil
    ) async throws -> OpenIDConnectClient {
        // offline_access is also important as it will provide a refresh token
        let discovery = OpenIDDiscoveryService(httpClient: httpClient, logger: logger)
        let configuration = try await discovery.discover(url: discoveryURL)

        return try await OpenIDConnectClient(
            httpClient: self.httpClient,
            clientID: clientID,
            clientSecret: clientSecret,
            configuration: configuration,
            redirectURI: redirectURI,
            logger: self.logger
        )
    }

    /// Creates a Google OAuth provider for Google Sign-In and Service Account authentication.
    ///
    /// Google's OAuth provider supports both user authentication via OpenID Connect and
    /// service account authentication for server-to-server scenarios.
    ///
    /// - Parameters:
    ///   - clientID: The client ID from Google Cloud Console
    ///   - clientSecret: The client secret from Google Cloud Console
    ///   - redirectURI: The redirect URI registered with Google Cloud Console
    /// - Returns: A Google OAuth provider with full Google API integration
    /// - Throws: `OAuth2Error` if OIDC discovery fails
    ///
    /// ## Example
    ///
    /// ```swift
    /// let googleProvider = try await oauthKit.googleProvider(
    ///     clientID: "your-google-client-id",
    ///     clientSecret: "your-google-client-secret",
    ///     redirectURI: "https://your-app.com/auth/google/callback"
    /// )
    ///
    /// // Generate authorization URL
    /// let (authURL, codeVerifier) = try googleProvider.generateAuthURL(
    ///     state: UUID().uuidString,
    ///     scopes: ["openid", "profile", "email"]
    /// )
    /// ```
    ///
    /// ## Service Account Support
    ///
    /// The Google provider also supports service account authentication:
    ///
    /// ```swift
    /// let tokenResponse = try await googleProvider.authenticateWithServiceAccount(
    ///     credentialsFilePath: "/path/to/service-account.json",
    ///     scopes: ["https://www.googleapis.com/auth/cloud-platform"]
    /// )
    /// ```
    public func googleProvider(
        clientID: String,
        clientSecret: String,
        redirectURI: String
    ) async throws -> GoogleOAuthProvider {
        GoogleOAuthProvider(
            oauthKit: self,
            openIDConnectClient: try await openIDConnectClient(
                discoveryURL: GoogleOAuthProvider.discoveryURL,
                clientID: clientID,
                clientSecret: clientSecret,
                redirectURI: redirectURI
            )
        )
    }

    /// Create a Microsoft OAuth provider for Microsoft 365 / Azure AD Sign-In
    /// - Parameters:
    ///   - clientID: The client/application ID from Azure portal
    ///   - clientSecret: The client secret from Azure portal
    ///   - redirectURI: The redirect URI registered with Azure
    ///   - tenantKind: The type of Microsoft tenant to authenticate against (defaults to .common for multi-tenant)
    /// - Returns: A Microsoft OAuth provider
    public func microsoftProvider(
        clientID: String,
        clientSecret: String,
        redirectURI: String,
        tenantKind: MicrosoftTenantIDKind = .common
    ) async throws -> MicrosoftOAuthProvider {
        MicrosoftOAuthProvider(
            oauthKit: self,
            openIDConnectClient: try await openIDConnectClient(
                discoveryURL: MicrosoftOAuthProvider.discoveryURL(for: tenantKind),
                clientID: clientID,
                clientSecret: clientSecret,
                redirectURI: redirectURI
            ),
            tenantKind: tenantKind
        )
    }

    /// Create a GitHub OAuth provider for GitHub Sign-In
    /// - Parameters:
    ///   - clientID: The client ID from GitHub
    ///   - clientSecret: The client secret from GitHub
    ///   - redirectURI: The redirect URI registered with GitHub
    ///   - scope: The requested scopes (space-separated)
    /// - Returns: A GitHub OAuth provider
    public func githubProvider(
        clientID: String,
        clientSecret: String,
        redirectURI: String
    ) -> GitHubOAuthProvider {
        GitHubOAuthProvider(
            oauthKit: self,
            oauth2Client: oauth2Client(
                clientID: clientID,
                clientSecret: clientSecret,
                tokenEndpoint: GitHubOAuthProvider.Endpoints.token,
                authorizationEndpoint: GitHubOAuthProvider.Endpoints.authorization,
                redirectURI: redirectURI
            )
        )
    }

    /// Create an Auth0 OAuth provider for Auth0 Sign-In
    /// - Parameters:
    ///   - domain: The Auth0 domain (e.g., "dev-123456.us.auth0.com" or "example.auth0.com")
    ///   - clientID: The client ID from Auth0 dashboard
    ///   - clientSecret: The client secret from Auth0 dashboard
    ///   - redirectURI: The redirect URI registered with Auth0
    /// - Returns: An Auth0 OAuth provider
    public func auth0Provider(
        domain: String,
        clientID: String,
        clientSecret: String,
        redirectURI: String
    ) async throws -> Auth0OAuthProvider {
        Auth0OAuthProvider(
            oauthKit: self,
            openIDConnectClient: try await openIDConnectClient(
                discoveryURL: Auth0OAuthProvider.discoveryURL(for: domain),
                clientID: clientID,
                clientSecret: clientSecret,
                redirectURI: redirectURI
            ),
            domain: domain
        )
    }

    /// Create a Discord OAuth provider for Discord Sign-In
    /// - Parameters:
    ///   - clientID: The client ID from Discord Developer Portal
    ///   - clientSecret: The client secret from Discord Developer Portal
    ///   - redirectURI: The redirect URI registered with Discord
    /// - Returns: A Discord OAuth provider
    public func discordProvider(
        clientID: String,
        clientSecret: String,
        redirectURI: String
    ) -> DiscordOAuthProvider {
        DiscordOAuthProvider(
            oauthKit: self,
            oauth2Client: oauth2Client(
                clientID: clientID,
                clientSecret: clientSecret,
                tokenEndpoint: DiscordOAuthProvider.tokenEndpoint,
                authorizationEndpoint: DiscordOAuthProvider.authorizationEndpoint,
                redirectURI: redirectURI
            )
        )
    }

    /// Create a LinkedIn OAuth provider for LinkedIn Sign-In
    /// - Parameters:
    ///   - clientID: The client ID from LinkedIn Developer Console
    ///   - clientSecret: The client secret from LinkedIn Developer Console
    ///   - redirectURI: The redirect URI registered with LinkedIn
    /// - Returns: A LinkedIn OAuth provider
    public func linkedinProvider(
        clientID: String,
        clientSecret: String,
        redirectURI: String
    ) -> LinkedInOAuthProvider {
        LinkedInOAuthProvider(
            oauthKit: self,
            oauth2Client: oauth2Client(
                clientID: clientID,
                clientSecret: clientSecret,
                tokenEndpoint: LinkedInOAuthProvider.tokenEndpoint,
                authorizationEndpoint: LinkedInOAuthProvider.authorizationEndpoint,
                redirectURI: redirectURI
            )
        )
    }

    /// Create a GitLab OAuth provider for GitLab Sign-In
    /// - Parameters:
    ///   - clientID: The client ID from GitLab application settings
    ///   - clientSecret: The client secret from GitLab application settings
    ///   - redirectURI: The redirect URI registered with GitLab
    ///   - customInstance: Custom GitLab instance configuration for self-hosted instances
    /// - Returns: A GitLab OAuth provider
    public func gitlabProvider(
        clientID: String,
        clientSecret: String,
        redirectURI: String,
        customInstance: GitLabOAuthProvider.CustomInstance? = nil
    ) -> GitLabOAuthProvider {
        let authEndpoint = customInstance?.authorizationEndpoint ?? GitLabOAuthProvider.authorizationEndpoint
        let tokenEndpoint = customInstance?.tokenEndpoint ?? GitLabOAuthProvider.tokenEndpoint

        return GitLabOAuthProvider(
            oauthKit: self,
            oauth2Client: oauth2Client(
                clientID: clientID,
                clientSecret: clientSecret,
                tokenEndpoint: tokenEndpoint,
                authorizationEndpoint: authEndpoint,
                redirectURI: redirectURI
            ),
            customInstance: customInstance
        )
    }

    /// Create a Dropbox OAuth provider for Dropbox Sign-In
    /// - Parameters:
    ///   - clientID: The app key from Dropbox App Console
    ///   - clientSecret: The app secret from Dropbox App Console
    ///   - redirectURI: The redirect URI registered with Dropbox
    /// - Returns: A Dropbox OAuth provider
    public func dropboxProvider(
        clientID: String,
        clientSecret: String,
        redirectURI: String
    ) -> DropboxOAuthProvider {
        DropboxOAuthProvider(
            oauthKit: self,
            oauth2Client: oauth2Client(
                clientID: clientID,
                clientSecret: clientSecret,
                tokenEndpoint: DropboxOAuthProvider.tokenEndpoint,
                authorizationEndpoint: DropboxOAuthProvider.authorizationEndpoint,
                redirectURI: redirectURI
            )
        )
    }

    /// Create an Apple OAuth provider for Sign in with Apple
    /// - Returns: An Apple OAuth provider
    public func appleProvider(
        clientID: String,
        teamID: String,
        keyID: String,
        privateKey: String,
        clientSecret: String,
        redirectURI: String
    ) async throws -> AppleOAuthProvider {
        AppleOAuthProvider(
            oauthKit: self,
            client: try await AppleOAuth2Client(
                httpClient: httpClient,
                clientID: clientID,
                clientSecret: clientSecret,
                teamID: teamID,
                keyID: keyID,
                privateKey: privateKey,
                redirectURI: redirectURI,
                jwksURL: AppleOAuthProvider.Endpoints.jwks,
                logger: logger
            )
        )
    }

    /// Create a Slack OAuth provider for Sign in with Slack
    /// - Parameters:
    ///   - clientID: The Slack  client ID
    ///   - clientSecret: The  Slack client secret
    ///   - redirectURI: The redirect URI registered with Slack
    /// - Returns: A Slack OAuth provider
    public func slackProvider(
        clientID: String,
        clientSecret: String,
        redirectURI: String
    ) -> SlackOAuthProvider {
        SlackOAuthProvider(
            oauthKit: self,
            client: SlackOAuth2Client(
                httpClient: httpClient,
                clientID: clientID,
                clientSecret: clientSecret,
                redirectURI: redirectURI,
            )
        )
    }

    /// Create a Facebook OAuth provider for Sign in with Facebook
    /// - Parameters:
    ///   - appID: The application ID from Facebook
    ///   - appSecret: The application secret from Facebook
    ///   - redirectURI: The redirect URI registered with Facebook
    /// - Returns: A Facebook OAuth provider
    public func facebookProvider(
        appID: String,
        appSecret: String,
        redirectURI: String,
    ) -> FacebookOAuthProvider {
        FacebookOAuthProvider(
            oauthKit: self,
            client: OAuth2Client(
                httpClient: httpClient,
                clientID: appID,
                clientSecret: appSecret,
                tokenEndpoint: FacebookOAuthProvider.Endpoints.token,
                authorizationEndpoint: FacebookOAuthProvider.Endpoints.authorization,
                redirectURI: redirectURI
            )
        )
    }

    /// Create an Okta OAuth provider for Sign in with Okta
    /// - Parameters:
    ///   - domain: The Okta domain (e.g., "dev-123456.okta.com" or "example.okta.com")
    ///   - clientID: The client ID from Okta
    ///   - clientSecret: The client secret from Okta
    ///   - redirectURI: The redirect URI registered with Okta
    ///   - scopes: The requested scopes
    ///   - useCustomAuth: Whether to use the custom authorization server (default: false)
    ///   - authServerId: The authorization server ID for custom auth server (default: "default")
    /// - Returns: An Okta OAuth provider
    public func oktaProvider(
        domain: String,
        clientID: String,
        clientSecret: String,
        redirectURI: String,
        useCustomAuth: Bool = false,
        authServerId: String = "default"
    ) async throws -> OktaOAuthProvider {

        let discoveryURL = OktaOAuthProvider.buildDiscoveryURL(domain: domain, useCustomAuth: useCustomAuth, authServerId: authServerId)
        return OktaOAuthProvider(
            oauthKit: self,
            client: try await openIDConnectClient(
                discoveryURL: discoveryURL,
                clientID: clientID,
                clientSecret: clientSecret,
                redirectURI: redirectURI
            )
        )
    }

    /// Create an AWS Cognito OAuth provider for Sign in with AWS Cognito
    /// - Parameters:
    ///   - region: The AWS region where your user pool is located (e.g., us-east-1)
    ///   - userPoolID: The Cognito User Pool ID (e.g., us-east-1_abcdefg)
    ///   - clientID: The client ID from Cognito (App client ID)
    ///   - clientSecret: The client secret from Cognito (optional, as not all app clients have secrets)
    ///   - redirectURI: The redirect URI registered with Cognito
    ///   - scopes: The requested scopes (space-separated)
    ///   - domain: Optional custom domain for your Cognito user pool (if you've set one up)
    /// - Returns: An AWS Cognito OAuth provider
    public func awsCognitoProvider(
        region: String,
        userPoolID: String,
        clientID: String,
        clientSecret: String? = nil,
        redirectURI: String,
        domain: String? = nil
    ) async throws -> AWSCognitoOAuthProvider {

        let discoveryURL = AWSCognitoOAuthProvider.buildDiscoveryURL(region: region, userPoolID: userPoolID, domain: domain)

        // AWS Cognito works with an empty client secret if none is configured
        let effectiveSecret = clientSecret ?? ""

        let client = try await openIDConnectClient(
            discoveryURL: discoveryURL,
            clientID: clientID,
            clientSecret: effectiveSecret,
            redirectURI: redirectURI
        )

        return AWSCognitoOAuthProvider(oauthKit: self, openIDConnectClient: client)
    }

    /// Create a KeyCloak OAuth provider for Sign in with KeyCloak
    /// - Returns: A KeyCloak OAuth provider
    public func keycloakProvider(
        endpoints: KeyCloakOAuthProvider.Endpoints,
        clientID: String,
        clientSecret: String,
        redirectURI: String
    ) -> KeyCloakOAuthProvider {
        KeyCloakOAuthProvider(
            oauthKit: self,
            endpoints: endpoints,
            client: OAuth2Client(
                httpClient: httpClient,
                clientID: clientID,
                clientSecret: clientSecret,
                tokenEndpoint: endpoints.token,
                authorizationEndpoint: endpoints.authorization,
                redirectURI: redirectURI
            )
        )
    }
}
