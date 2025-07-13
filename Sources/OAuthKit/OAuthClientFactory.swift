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

/// Main entry point for OAuthKit functionality
public struct OAuthClientFactory: Sendable {
    /// The HTTP client used for making requests
    internal let httpClient: HTTPClient

    /// Logger used for OAuth operations
    public let logger: Logger

    /// Create a new OAuthKit instance
    /// - Parameters:
    ///   - httpClient: The HTTP client used for making requests
    ///   - logger: Logger used for OAuth operations
    public init(httpClient: HTTPClient = HTTPClient.shared, logger: Logger = Logger(label: "com.oauthkit.OAuthKit")) {
        self.httpClient = httpClient
        self.logger = logger
    }

    /// Create an OAuth2 client for interacting with an OAuth2 provider
    /// - Parameters:
    ///   - clientID: The client ID provided by the OAuth2 provider
    ///   - clientSecret: The client secret provided by the OAuth2 provider
    ///   - tokenEndpoint: The token endpoint URL
    ///   - authorizationEndpoint: The authorization endpoint URL
    ///   - redirectURI: The redirect URI registered with the OAuth2 provider
    ///   - scopes: The requested scopes (space-separated)
    /// - Returns: An OAuth2 client instance
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

    /// Create an OpenID Connect client for interacting with an OIDC provider
    /// - Parameters:
    ///   - discoveryURL: The OpenID Connect discovery URL (.well-known/openid-configuration)
    ///   - clientID: The client ID provided by the OIDC provider
    ///   - clientSecret: The client secret provided by the OIDC provider
    ///   - redirectURI: The redirect URI registered with the OIDC provider
    /// - Returns: An OpenID Connect client
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

    /// Create a Google OAuth provider for Google Sign-In
    /// - Parameters:
    ///   - clientID: The client ID from Google Developer Console
    ///   - clientSecret: The client secret from Google Developer Console
    ///   - redirectURI: The redirect URI registered with Google
    ///   - scope: The requested scopes (defaults to basic profile)
    /// - Returns: A Google OAuth provider
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
    /// for multi-tenant applications
    /// - Parameters:
    ///   - clientID: The client/application ID from Azure portal
    ///   - clientSecret: The client secret from Azure portal
    ///   - redirectURI: The redirect URI registered with Azure
    /// - Returns: A Microsoft OAuth provider
    public func microsoftMultiTenantProvider(
        clientID: String,
        clientSecret: String,
        redirectURI: String
    ) async throws -> MicrosoftOAuthProvider {
        MicrosoftOAuthProvider(
            oauthKit: self,
            openIDConnectClient: try await openIDConnectClient(
                discoveryURL: MicrosoftOAuthProvider.commonDiscoveryURL,
                clientID: clientID,
                clientSecret: clientSecret,
                redirectURI: redirectURI
            )
        )
    }

    /// Create a Microsoft OpenID Connect client for a specific tenant
    /// - Parameters:
    ///   - clientID: The client/application ID from Azure portal
    ///   - clientSecret: The client secret from Azure portal
    ///   - tenantID: The Azure AD tenant ID
    ///   - redirectURI: The redirect URI registered with Azure
    /// - Returns: An OpenID Connect client configured for Microsoft
    public func microsoftProvider(
        clientID: String,
        clientSecret: String,
        tenantID: String,
        redirectURI: String
    ) async throws -> MicrosoftOAuthProvider {
        MicrosoftOAuthProvider(
            oauthKit: self,
            openIDConnectClient: try await openIDConnectClient(
                discoveryURL: MicrosoftOAuthProvider.tenantDiscoveryURL(tenantID: tenantID),
                clientID: clientID,
                clientSecret: clientSecret,
                redirectURI: redirectURI
            )
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
