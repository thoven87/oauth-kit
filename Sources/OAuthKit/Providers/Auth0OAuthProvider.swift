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
import NIOCore
import NIOFoundationCompat
import NIOHTTP1

/// Provider for Auth0 OAuth2/OpenID Connect authentication
public struct Auth0OAuthProvider: Sendable {
    /// Generate Auth0's discovery URL for a specific domain
    /// - Parameter domain: The Auth0 domain (e.g., "dev-123456.us.auth0.com" or "example.auth0.com")
    /// - Returns: The discovery URL for the Auth0 tenant
    public static func discoveryURL(for domain: String) -> String {
        "https://\(domain)/.well-known/openid_configuration"
    }

    /// The OAuthKit instance
    private let oauthKit: OAuthClientFactory

    /// The OpenID Connect client configured for Auth0
    private let client: OpenIDConnectClient

    /// The Auth0 domain this provider is configured for
    public let domain: String

    /// Initialize a new Auth0 OAuth provider
    /// - Parameters:
    ///   - oauthKit: The OAuthKit instance
    ///   - openIDConnectClient: The OpenID Connect client configured for Auth0
    ///   - domain: The Auth0 domain this provider is configured for
    internal init(oauthKit: OAuthClientFactory, openIDConnectClient client: OpenIDConnectClient, domain: String) {
        self.oauthKit = oauthKit
        self.client = client
        self.domain = domain
    }

    /// Generate an authorization URL for Auth0 Sign-In with recommended parameters
    /// - Parameters:
    ///   - state: An opaque value to maintain state between the request and callback
    ///   - connection: Specify a specific connection to use (optional)
    ///   - audience: API identifier that the app wants to access (optional)
    ///   - usePKCE: Whether to use PKCE (recommended and enabled by default)
    ///   - additionalParameters: Additional parameters to include in the authorization URL
    ///   - scopes: The requested scopes
    /// - Returns: A tuple containing the authorization URL and code verifier (for PKCE)
    public func generateAuthorizationURL(
        state: String? = nil,
        connection: String? = nil,
        audience: String? = nil,
        usePKCE: Bool = true,
        additionalParameters: [String: String] = [:],
        scopes: [String] = ["openid", "profile", "email"]
    ) throws -> (url: URL, codeVerifier: String?) {
        var additionalParams = additionalParameters
        var codeVerifier: String? = nil
        var codeChallenge: String? = nil

        // Generate PKCE if requested
        if usePKCE {
            let pkce = OAuth2Client.generatePKCE()
            codeVerifier = pkce.codeVerifier
            codeChallenge = pkce.codeChallenge
        }

        // Add Auth0-specific parameters
        if let connection = connection {
            additionalParams["connection"] = connection
        }

        if let audience = audience {
            additionalParams["audience"] = audience
        }

        // Auth0 recommends adding response_mode for security
        if additionalParams["response_mode"] == nil {
            additionalParams["response_mode"] = "query"
        }

        let url = try client.generateAuthorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            additionalParameters: additionalParams,
            scopes: scopes
        )

        return (url, codeVerifier)
    }

    /// Exchange an authorization code for tokens with Auth0
    /// - Parameters:
    ///   - code: The authorization code received from Auth0
    ///   - codeVerifier: The PKCE code verifier used when generating the authorization URL
    /// - Returns: The token response and ID token claims
    public func exchangeCode(
        code: String,
        codeVerifier: String?
    ) async throws -> (tokenResponse: TokenResponse, claims: IDTokenClaims) {
        try await client.exchangeCode(
            code: code,
            codeVerifier: codeVerifier
        )
    }

    /// Refresh an access token using a refresh token
    /// - Parameters:
    ///   - refreshToken: The refresh token
    ///   - additionalParameters: Additional parameters to include in the token request
    /// - Returns: The token response and ID token claims
    /// - Throws: OAuth2Error if the token refresh fails
    public func refreshAccessToken(
        refreshToken: String,
        additionalParameters: [String: String] = [:]
    ) async throws -> (tokenResponse: TokenResponse, claims: IDTokenClaims?) {
        try await client.refreshToken(
            refreshToken,
            additionalParameters: additionalParameters
        )
    }

    /// Retrieve the user's profile information from Auth0
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    /// - Returns: The user's Auth0 profile information
    public func getUserProfile(
        accessToken: String
    ) async throws -> Auth0UserProfile {
        let userInfo: Auth0UserProfile = try await client.getUserInfo(accessToken: accessToken)
        return userInfo
    }

    /// Call the Auth0 Management API
    /// - Parameters:
    ///   - accessToken: The access token from the token response (must have Management API audience)
    ///   - endpoint: The Management API endpoint to call (e.g., "/api/v2/users/USER_ID")
    ///   - httpMethod: The HTTP method to use (default: GET)
    ///   - body: Optional request body for POST/PATCH requests
    ///   - httpClient: The HTTP client to use for the request
    ///   - logger: Logger for the Management API operation
    /// - Returns: The decoded response
    public func callManagementAPI<T: Codable>(
        accessToken: String,
        endpoint: String,
        httpMethod: NIOHTTP1.HTTPMethod = .GET,
        body: ByteBuffer? = nil,
        httpClient: HTTPClient = HTTPClient.shared,
        logger: Logger = Logger(label: "com.oauthkit.Auth0OAuthProvider.callManagementAPI")
    ) async throws -> T {
        let apiEndpoint =
            endpoint.hasPrefix("/")
            ? "https://\(domain)\(endpoint)"
            : "https://\(domain)/\(endpoint)"

        var request = HTTPClientRequest(url: apiEndpoint)
        request.method = httpMethod
        request.headers.add(name: "Authorization", value: "Bearer \(accessToken)")
        request.headers.add(name: "Accept", value: "application/json")
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        if let body = body {
            request.body = .bytes(body)
            request.headers.add(name: "Content-Type", value: "application/json")
        }

        do {
            let response = try await httpClient.execute(request, timeout: .seconds(60))

            guard response.status.code >= 200 && response.status.code < 300 else {
                logger.error("Management API request failed with status: \(response.status)")
                throw OAuth2Error.responseError("Management API request failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
            let decoder = JSONDecoder()

            return try decoder.decode(T.self, from: responseBody)
        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("Management API request failed with error: \(error)")
            throw OAuth2Error.networkError("Management API request failed: \(error)")
        }
    }
}

/// Auth0 connection types for social and enterprise connections
public enum Auth0Connection: String {
    // Social connections
    case google = "google-oauth2"
    case facebook = "facebook"
    case twitter = "twitter"
    case github = "github"
    case linkedin = "linkedin"
    case microsoft = "windowslive"
    case amazon = "amazon"
    case yahoo = "yahoo"
    case paypal = "paypal"
    case salesforce = "salesforce"
    case fitbit = "fitbit"
    case baidu = "baidu"
    case renren = "renren"
    case weibo = "weibo"
    case yandex = "yandex"
    case vkontakte = "vkontakte"
    case dwolla = "dwolla"
    case shopify = "shopify"
    case thirtysevensignals = "thirtysevensignals"
    case wordpress = "wordpress"
    case yammer = "yammer"
    case instagram = "instagram"
    case soundcloud = "soundcloud"
    case line = "line"
    case apple = "apple"
    case discord = "discord"
    case slack = "slack"

    // Enterprise connections (these are typically customized per tenant)
    case googleApps = "google-apps"
    case office365 = "office365"
    case windowsAzureAd = "waad"
    case adldap = "ad"
    case samlp = "samlp"
    case oidc = "oidc"

    // Database connections
    case usernamePassword = "Username-Password-Authentication"

    // Passwordless
    case email = "email"
    case sms = "sms"
}

/// Auth0 user profile information
public struct Auth0UserProfile: Codable {
    /// The user's unique Auth0 ID
    public let sub: String

    /// The user's email address
    public let email: String?

    /// Whether the user's email is verified
    public let emailVerified: Bool?

    /// The user's full name
    public let name: String?

    /// The user's given name
    public let givenName: String?

    /// The user's family name
    public let familyName: String?

    /// The user's middle name
    public let middleName: String?

    /// The user's nickname
    public let nickname: String?

    /// The user's preferred username
    public let preferredUsername: String?

    /// URL of the user's profile picture
    public let picture: String?

    /// The user's website URL
    public let website: String?

    /// The user's gender
    public let gender: String?

    /// The user's birthdate
    public let birthdate: String?

    /// The user's timezone
    public let zoneinfo: String?

    /// The user's locale
    public let locale: String?

    /// The user's phone number
    public let phoneNumber: String?

    /// Whether the user's phone number is verified
    public let phoneNumberVerified: Bool?

    /// The user's address
    public let address: Auth0Address?

    /// When the user's profile was last updated
    public let updatedAt: String?

    /// Custom user metadata (app-specific) - raw JSON data
    public let userMetadata: [String: String]?

    /// App metadata (managed by Auth0 rules/hooks) - raw JSON data
    public let appMetadata: [String: String]?

    enum CodingKeys: String, CodingKey {
        case sub
        case email
        case emailVerified = "email_verified"
        case name
        case givenName = "given_name"
        case familyName = "family_name"
        case middleName = "middle_name"
        case nickname
        case preferredUsername = "preferred_username"
        case picture
        case website
        case gender
        case birthdate
        case zoneinfo
        case locale
        case phoneNumber = "phone_number"
        case phoneNumberVerified = "phone_number_verified"
        case address
        case updatedAt = "updated_at"
        case userMetadata = "user_metadata"
        case appMetadata = "app_metadata"
    }
}

/// Auth0 user address information
public struct Auth0Address: Codable {
    public let formatted: String?
    public let streetAddress: String?
    public let locality: String?
    public let region: String?
    public let postalCode: String?
    public let country: String?

    enum CodingKeys: String, CodingKey {
        case formatted
        case streetAddress = "street_address"
        case locality
        case region
        case postalCode = "postal_code"
        case country
    }
}

/// Auth0 Management API User response
public struct Auth0ManagementUser: Codable {
    /// The user's unique Auth0 ID
    public let userId: String

    /// The user's email address
    public let email: String?

    /// Whether the email is verified
    public let emailVerified: Bool?

    /// The user's name
    public let name: String?

    /// The user's given name
    public let givenName: String?

    /// The user's family name
    public let familyName: String?

    /// The user's nickname
    public let nickname: String?

    /// The user's picture URL
    public let picture: String?

    /// The connection used for this user
    public let connection: String?

    /// The user's provider
    public let provider: String?

    /// Whether the user is blocked
    public let blocked: Bool?

    /// When the user was created
    public let createdAt: String?

    /// When the user was last updated
    public let updatedAt: String?

    /// User's metadata
    public let userMetadata: [String: String]?

    /// App metadata
    public let appMetadata: [String: String]?

    /// User's identities
    public let identities: [Auth0Identity]?

    enum CodingKeys: String, CodingKey {
        case userId = "user_id"
        case email
        case emailVerified = "email_verified"
        case name
        case givenName = "given_name"
        case familyName = "family_name"
        case nickname
        case picture
        case connection
        case provider
        case blocked
        case createdAt = "created_at"
        case updatedAt = "updated_at"
        case userMetadata = "user_metadata"
        case appMetadata = "app_metadata"
        case identities
    }
}

/// Auth0 user identity
public struct Auth0Identity: Codable {
    /// The identity provider
    public let provider: String

    /// The user ID at the provider
    public let userId: String

    /// The connection name
    public let connection: String

    /// Whether this is the primary identity
    public let isSocial: Bool?

    enum CodingKeys: String, CodingKey {
        case provider
        case userId = "user_id"
        case connection
        case isSocial = "isSocial"
    }
}

/// Auth0 Management API generic response wrapper
public struct Auth0ManagementResponse<T: Codable>: Codable {
    /// The response data
    public let data: T

    /// Total count (for paginated responses)
    public let total: Int?

    /// Start index (for paginated responses)
    public let start: Int?

    /// Limit (for paginated responses)
    public let limit: Int?
}
