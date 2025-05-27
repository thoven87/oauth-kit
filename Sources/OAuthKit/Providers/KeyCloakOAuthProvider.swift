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
import NIOCore
import NIOFoundationCompat

/// Provider for KeyCloak OAuth authentication
public struct KeyCloakOAuthProvider: Sendable {
    /// KeyCloak's OAuth endpoints structure
    /// Note: KeyCloak is self-hosted, so the base URL will vary
    public struct Endpoints: Sendable {
        /// The base URL of your KeyCloak instance
        let baseURL: String

        /// The realm name in KeyCloak
        let realm: String

        /// The full base URL including the realm
        var realmURL: String {
            "\(baseURL)/realms/\(realm)"
        }

        /// The authorization endpoint URL
        var authorization: String {
            "\(realmURL)/protocol/openid-connect/auth"
        }

        /// The token endpoint URL
        var token: String {
            "\(realmURL)/protocol/openid-connect/token"
        }

        /// The user info endpoint URL
        var userinfo: String {
            "\(realmURL)/protocol/openid-connect/userinfo"
        }

        /// The logout endpoint URL
        var logout: String {
            "\(realmURL)/protocol/openid-connect/logout"
        }

        /// The OpenID Connect configuration endpoint
        var openIDConfiguration: String {
            "\(realmURL)/.well-known/openid-configuration"
        }

        public init(baseURL: String, realm: String) {
            self.baseURL = baseURL
            self.realm = realm
        }
    }

    /// The OAuthKit instance
    private let oauthKit: OAuthKit

    /// KeyCloakBaseURL configured
    private let endpoints: Endpoints

    /// An OAuth2 client configured for KeyCloak
    private let client: OAuth2Client

    /// Initialize a new KeyCloak OAuth provider
    /// - Parameters:
    ///   - oauthKit: The OAuthKit instance
    ///   - endpoints: The Enpoints instance with base url
    ///   - client: An Oauth2Client
    internal init(
        oauthKit: OAuthKit,
        endpoints: Endpoints,
        client: OAuth2Client
    ) {
        self.oauthKit = oauthKit
        self.endpoints = endpoints
        self.client = client
    }

    /// Create an OpenID Connect client for KeyCloak
    /// - Parameters:
    ///   - clientID: The client ID registered in KeyCloak
    ///   - clientSecret: The client secret from KeyCloak
    ///   - redirectURI: The redirect URI registered with KeyCloak
    ///   - scopes: The requested scopes (default: "openid profile email")
    /// - Returns: An OpenID Connect client configured for KeyCloak
    public func createOpenIDConnectClient(
        clientID: String,
        clientSecret: String,
        redirectURI: String,
        scopes: [String] = ["openid", "profile", "email"]
    ) async throws -> OpenIDConnectClient {

        // Fetch OpenID configuration from KeyCloak discovery endpoint
        let config = try await fetchOpenIDConfiguration()

        return try await OpenIDConnectClient(
            httpClient: oauthKit.httpClient,
            clientID: clientID,
            clientSecret: clientSecret,
            configuration: config,
            redirectURI: redirectURI,
            scopes: scopes,
            logger: oauthKit.logger
        )
    }

    /// Generate a sign-in URL for KeyCloak
    /// - Parameters:
    ///   - state: Optional state parameter for security
    ///   - usePKCE: Whether to use PKCE (recommended, default: true)
    ///   - loginHint: Optional email/username hint for pre-filling the login form
    ///   - locale: Optional locale for the KeyCloak UI (e.g., "en")
    ///   - prompt: Optional prompt behavior (login, none, consent)
    /// - Returns: A tuple containing the authorization URL and PKCE code verifier (if used)
    public func signInURL(
        state: String? = nil,
        usePKCE: Bool = true,
        loginHint: String? = nil,
        locale: String? = nil,
        prompt: String? = nil
    ) throws -> (url: URL, codeVerifier: String?) {
        var additionalParams: [String: String] = [:]

        if let loginHint = loginHint {
            additionalParams["login_hint"] = loginHint
        }

        if let locale = locale {
            additionalParams["ui_locales"] = locale
        }

        if let prompt = prompt {
            additionalParams["prompt"] = prompt
        }

        // Generate PKCE if enabled
        var codeVerifier: String? = nil
        var codeChallenge: String? = nil

        if usePKCE {
            let pkce = OAuth2Client.generatePKCE()
            codeVerifier = pkce.0
            codeChallenge = pkce.1
        }

        // Generate the authorization URL
        let url = try client.authorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            additionalParameters: additionalParams
        )

        return (url, codeVerifier)
    }

    /// Get user profile from KeyCloak
    /// - Parameter accessToken: The OAuth access token
    /// - Returns: User profile information
    public func getUserProfile(accessToken: String) async throws -> KeyCloakUserProfile {
        var request = HTTPClientRequest(url: endpoints.userinfo)
        request.method = .GET
        request.headers.add(name: "Authorization", value: "Bearer \(accessToken)")
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        let response = try await oauthKit.httpClient.execute(request, timeout: .seconds(60))

        guard response.status == .ok else {
            throw OAuth2Error.serverError("Failed to fetch user profile: HTTP \(response.status.code)")
        }

        let body = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit

        // Parse user profile
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase

        return try decoder.decode(KeyCloakUserProfile.self, from: body)
    }

    /// Logout the user from KeyCloak
    /// - Parameters:
    ///   - idToken: The ID token received during login
    ///   - clientID: The client ID registered in KeyCloak
    ///   - redirectURI: Where to redirect after logout
    /// - Returns: The logout URL to redirect the user to
    public func logoutURL(
        idToken: String,
        clientID: String,
        redirectURI: String,
    ) throws -> URL {
        var components = URLComponents(string: endpoints.logout)

        components?.queryItems = [
            URLQueryItem(name: "id_token_hint", value: idToken),
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "post_logout_redirect_uri", value: redirectURI),
        ]

        guard let url = components?.url else {
            throw OAuth2Error.invalidRequest("Failed to create logout URL")
        }

        return url
    }

    /// Fetch OpenID Connect configuration from KeyCloak
    /// - Returns: OpenID Connect configuration
    private func fetchOpenIDConfiguration() async throws -> OpenIDConfiguration {
        var request = HTTPClientRequest(url: endpoints.openIDConfiguration)
        request.method = .GET
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        let response = try await oauthKit.httpClient.execute(request, timeout: .seconds(60))

        guard response.status == .ok else {
            throw OAuth2Error.serverError("Failed to fetch OpenID configuration: HTTP \(response.status.code)")
        }

        let body = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit

        // Parse the OpenID configuration
        let json = try JSONSerialization.jsonObject(with: body, options: []) as? [String: Any] ?? [:]

        guard let authEndpoint = json["authorization_endpoint"] as? String,
            let tokenEndpoint = json["token_endpoint"] as? String,
            let userinfoEndpoint = json["userinfo_endpoint"] as? String,
            let jwksUri = json["jwks_uri"] as? String,
            let issuer = json["issuer"] as? String
        else {
            throw OAuth2Error.invalidResponse("Missing required fields in OpenID configuration")
        }

        return OpenIDConfiguration(
            authorizationEndpoint: authEndpoint,
            tokenEndpoint: tokenEndpoint,
            userinfoEndpoint: userinfoEndpoint,
            jwksUri: jwksUri,
            scopesSupported: json["scopes_supported"] as? [String] ?? ["openid", "profile", "email"],
            responseTypesSupported: json["response_types_supported"] as? [String] ?? ["code"],
            grantTypesSupported: json["grant_types_supported"] as? [String] ?? ["authorization_code", "refresh_token"],
            subjectTypesSupported: json["subject_types_supported"] as? [String] ?? ["public"],
            idTokenSigningAlgValuesSupported: json["id_token_signing_alg_values_supported"] as? [String] ?? ["RS256"],
            issuer: issuer,
            endSessionEndpoint: json["end_session_endpoint"] as? String,
            introspectionEndpoint: json["introspection_endpoint"] as? String,
            revocationEndpoint: json["revocation_endpoint"] as? String
        )
    }
}

/// KeyCloak user profile information
public struct KeyCloakUserProfile: Codable {
    /// The user's ID (subject)
    public let id: String

    /// The user's username
    public let preferredUsername: String?

    /// The user's full name
    public let name: String?

    /// The user's given name (first name)
    public let givenName: String?

    /// The user's family name (last name)
    public let familyName: String?

    /// The user's email address
    public let email: String?

    /// Whether the email is verified
    public let emailVerified: Bool?

    /// The user's roles
    public let realmAccess: RealmAccess?

    /// The user's resource access (client roles)
    public let resourceAccess: [String: ClientAccess]?

    /// Realm access structure (contains roles)
    public struct RealmAccess: Codable {
        /// The roles assigned to the user in the realm
        public let roles: [String]?
    }

    /// Client access structure (contains client-specific roles)
    public struct ClientAccess: Codable {
        /// The roles assigned to the user for this client
        public let roles: [String]?
    }

    enum CodingKeys: String, CodingKey {
        case id = "sub"
        case preferredUsername = "preferred_username"
        case name
        case givenName = "given_name"
        case familyName = "family_name"
        case email
        case emailVerified = "email_verified"
        case realmAccess = "realm_access"
        case resourceAccess = "resource_access"
    }
}
