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

/// Provider for Okta OAuth2/OpenID Connect authentication
public struct OktaOAuthProvider {
    /// The OAuthKit instance
    private let oauthKit: OAuthKit

    /// An OpenID Connect client configured for Okta
    private let client: OpenIDConnectClient

    /// Initialize a new Okta OAuth provider
    /// - Parameter oauthKit: The OAuthKit instance
    internal init(oauthKit: OAuthKit, client: OpenIDConnectClient) {
        self.oauthKit = oauthKit
        self.client = client
    }

    /// Build the Okta OpenID Connect discovery URL
    /// - Parameters:
    ///   - domain: The Okta domain
    ///   - useCustomAuth: Whether to use the custom authorization server
    ///   - authServerId: The authorization server ID for custom auth server
    /// - Returns: The discovery URL
    internal static func buildDiscoveryURL(domain: String, useCustomAuth: Bool, authServerId: String) -> String {
        let sanitizedDomain = domain.trimmingCharacters(in: .whitespaces).lowercased()
        let baseURL = sanitizedDomain.hasPrefix("https://") ? sanitizedDomain : "https://\(sanitizedDomain)"

        if useCustomAuth {
            // Custom auth server format
            return "\(baseURL)/oauth2/\(authServerId)/.well-known/openid-configuration"
        } else {
            // Org authorization server format
            return "\(baseURL)/.well-known/openid-configuration"
        }
    }

    /// Generate an authorization URL for Okta sign-in
    /// - Parameters:
    ///   - state: An opaque value to maintain state between the request and callback
    ///   - nonce: A random value for additional security
    ///   - prompt: Controls the Okta sign-in prompt behavior
    ///   - idpID: The identity provider ID to bypass the Okta sign-in page and go directly to the specified IdP
    ///   - usePKCE: Whether to use PKCE (recommended and enabled by default)
    /// - Returns: A tuple containing the authorization URL and code verifier (for PKCE)
    public func signInURL(
        state: String? = nil,
        nonce: String? = nil,
        prompt: OktaPrompt? = nil,
        idpID: String? = nil,
        usePKCE: Bool = true
    ) async throws -> (url: URL, codeVerifier: String?) {
        var codeVerifier: String? = nil
        var codeChallenge: String? = nil

        // Generate PKCE if requested
        if usePKCE {
            let pkce = OAuth2Client.generatePKCE()
            codeVerifier = pkce.codeVerifier
            codeChallenge = pkce.codeChallenge
        }

        // Prepare additional parameters for Okta
        var additionalParams: [String: String] = [:]

        if let nonce = nonce {
            additionalParams["nonce"] = nonce
        }

        if let prompt = prompt {
            additionalParams["prompt"] = prompt.rawValue
        }

        // Add idp parameter to bypass Okta and go directly to the specified IdP
        if let idpID = idpID {
            additionalParams["idp"] = idpID
        }

        // Okta uses OIDC standard flow, so we can leverage the OpenIDConnectClient
        let url = try client.authorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            additionalParameters: additionalParams
        )

        return (url, codeVerifier)
    }

    /// Exchange an authorization code for tokens with Okta
    /// - Parameters:
    ///   - code: The authorization code received from Okta
    ///   - codeVerifier: The PKCE code verifier used when generating the authorization URL
    /// - Returns: A tuple containing the token response and ID token claims
    public func exchangeCode(
        code: String,
        codeVerifier: String? = nil
    ) async throws -> (tokenResponse: TokenResponse, claims: IDTokenClaims) {
        try await client.exchangeCode(
            code: code,
            codeVerifier: codeVerifier
        )
    }

    /// Get user information from Okta
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    /// - Returns: The user information as a dictionary
    public func getUserInfo(
        accessToken: String
    ) async throws -> OktaUserProfile {
        let userInfo: OktaUserProfile = try await client.getUserInfo(accessToken: accessToken)
        return userInfo
    }

    /// Get the Okta token introspection information
    /// - Parameters:
    ///   - token: The token to introspect
    ///   - tokenTypeHint: The token type hint (optional)
    /// - Returns: The token introspection information
    public func introspectToken(
        token: String,
        tokenTypeHint: String? = nil
    ) async throws -> OktaTokenIntrospection {
        // Get the token introspection endpoint
        let endpoints = client.configuration.introspectionEndpoint
        guard let introspectionEndpoint = endpoints else {
            throw OAuth2Error.configurationError("Introspection endpoint not found in Okta configuration")
        }

        var parameters = ["token": token]
        if let tokenTypeHint = tokenTypeHint {
            parameters["token_type_hint"] = tokenTypeHint
        }

        var request = HTTPClientRequest(url: introspectionEndpoint)
        request.method = .POST

        // Use client authentication
        let credentials = "\(client.clientID):\(client.clientSecret)"
        let credentialsData = credentials.data(using: .utf8)!
        let base64Credentials = credentialsData.base64EncodedString()
        request.headers.add(name: "Authorization", value: "Basic \(base64Credentials)")
        request.headers.add(name: "Content-Type", value: "application/x-www-form-urlencoded")
        request.headers.add(name: "Accept", value: "application/json")
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        // Add form parameters
        let formBody = parameters.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? $0.value)" }.joined(
            separator: "&"
        )
        request.body = .bytes(ByteBuffer(string: formBody))

        let response = try await oauthKit.httpClient.execute(request, timeout: .seconds(60))

        guard response.status == .ok else {
            throw OAuth2Error.responseError("Token introspection failed with status code \(response.status.code)")
        }

        let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
        let data = Data(buffer: responseBody)

        let decoder = JSONDecoder()
        return try decoder.decode(OktaTokenIntrospection.self, from: data)
    }

    /// Revoke an Okta token
    /// - Parameters:
    ///   - token: The token to revoke
    ///   - tokenTypeHint: The token type hint (optional)
    /// - Returns: True if the token was successfully revoked
    public func revokeToken(
        token: String,
        tokenTypeHint: String? = nil
    ) async throws -> Bool {
        // Get the token revocation endpoint
        let endpoints = client.configuration.revocationEndpoint
        guard let revocationEndpoint = endpoints else {
            throw OAuth2Error.configurationError("Revocation endpoint not found in Okta configuration")
        }

        var parameters = ["token": token]
        if let tokenTypeHint = tokenTypeHint {
            parameters["token_type_hint"] = tokenTypeHint
        }

        var request = HTTPClientRequest(url: revocationEndpoint)
        request.method = .POST

        // Use client authentication
        let credentials = "\(client.clientID):\(client.clientSecret)"
        let credentialsData = credentials.data(using: .utf8)!
        let base64Credentials = credentialsData.base64EncodedString()
        request.headers.add(name: "Authorization", value: "Basic \(base64Credentials)")
        request.headers.add(name: "Content-Type", value: "application/x-www-form-urlencoded")
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        // Add form parameters
        let formBody = parameters.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? $0.value)" }.joined(
            separator: "&"
        )
        request.body = .bytes(ByteBuffer(string: formBody))

        let response = try await oauthKit.httpClient.execute(request, timeout: .seconds(60))

        // A successful revocation returns a 200 OK with an empty response body
        return response.status == .ok
    }
}

/// Okta sign-in prompt behavior
public enum OktaPrompt: String {
    /// Do not prompt the user for reauthentication or consent
    case none = "none"

    /// Always prompt the user for reauthentication
    case login = "login"

    /// Always prompt the user for consent
    case consent = "consent"

    /// Always prompt the user for reauthentication and consent
    case loginConsent = "login consent"
}

/// Okta user profile information
public struct OktaUserProfile: Codable {
    /// The user's unique Okta ID (subject identifier)
    public let id: String

    /// The user's email address
    public let email: String?

    /// Whether the user's email is verified
    public let emailVerified: Bool?

    /// The user's preferred username
    public let preferredUsername: String?

    /// The user's full name
    public let name: String?

    /// The user's given name (first name)
    public let givenName: String?

    /// The user's family name (last name)
    public let familyName: String?

    /// The user's middle name
    public let middleName: String?

    /// The user's nickname
    public let nickname: String?

    /// The user's phone number
    public let phoneNumber: String?

    /// Whether the user's phone number is verified
    public let phoneNumberVerified: Bool?

    /// The user's preferred locale
    public let locale: String?

    /// The user's timezone
    public let zoneinfo: String?

    /// The user's profile picture URL
    public let picture: String?

    /// The user's address information
    public let address: IDTokenClaims.AddressClaim?

    /// Additional claims from the Okta ID token or UserInfo endpoint
    //public let additionalClaims: [String: Any]?

    // Implement Codable protocol for JSON serialization
    private enum CodingKeys: String, CodingKey {
        case id = "sub"
        case email
        case emailVerified = "email_verified"
        case preferredUsername = "preferred_username"
        case name
        case givenName = "given_name"
        case familyName = "family_name"
        case middleName = "middle_name"
        case nickname
        case phoneNumber = "phone_number"
        case phoneNumberVerified = "phone_number_verified"
        case locale
        case zoneinfo
        case picture
        case address
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        email = try container.decodeIfPresent(String.self, forKey: .email)
        emailVerified = try container.decodeIfPresent(Bool.self, forKey: .emailVerified)
        preferredUsername = try container.decodeIfPresent(String.self, forKey: .preferredUsername)
        name = try container.decodeIfPresent(String.self, forKey: .name)
        givenName = try container.decodeIfPresent(String.self, forKey: .givenName)
        familyName = try container.decodeIfPresent(String.self, forKey: .familyName)
        middleName = try container.decodeIfPresent(String.self, forKey: .middleName)
        nickname = try container.decodeIfPresent(String.self, forKey: .nickname)
        phoneNumber = try container.decodeIfPresent(String.self, forKey: .phoneNumber)
        phoneNumberVerified = try container.decodeIfPresent(Bool.self, forKey: .phoneNumberVerified)
        locale = try container.decodeIfPresent(String.self, forKey: .locale)
        zoneinfo = try container.decodeIfPresent(String.self, forKey: .zoneinfo)
        picture = try container.decodeIfPresent(String.self, forKey: .picture)
        address = try container.decodeIfPresent(IDTokenClaims.AddressClaim.self, forKey: .address)
        //additionalClaims = nil  // Not decoded from JSON
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encodeIfPresent(email, forKey: .email)
        try container.encodeIfPresent(emailVerified, forKey: .emailVerified)
        try container.encodeIfPresent(preferredUsername, forKey: .preferredUsername)
        try container.encodeIfPresent(name, forKey: .name)
        try container.encodeIfPresent(givenName, forKey: .givenName)
        try container.encodeIfPresent(familyName, forKey: .familyName)
        try container.encodeIfPresent(middleName, forKey: .middleName)
        try container.encodeIfPresent(nickname, forKey: .nickname)
        try container.encodeIfPresent(phoneNumber, forKey: .phoneNumber)
        try container.encodeIfPresent(phoneNumberVerified, forKey: .phoneNumberVerified)
        try container.encodeIfPresent(locale, forKey: .locale)
        try container.encodeIfPresent(zoneinfo, forKey: .zoneinfo)
        try container.encodeIfPresent(picture, forKey: .picture)
        try container.encodeIfPresent(address, forKey: .address)
        // additionalClaims not encoded to JSON
    }
}

/// Okta token introspection response
public struct OktaTokenIntrospection: Codable {
    /// Whether the token is active
    public let active: Bool

    /// The client ID the token was issued to
    public let clientID: String?

    /// The username of the resource owner who authorized the token
    public let username: String?

    /// The token type
    public let tokenType: String?

    /// The expiration time as a timestamp
    public let exp: Int?

    /// The issuance time as a timestamp
    public let iat: Int?

    /// The unique identifier for the token
    public let jti: String?

    /// The subject of the token
    public let sub: String?

    /// The audience the token is intended for
    public let aud: String?

    /// The issuer of the token
    public let iss: String?

    /// The device ID associated with the token
    public let deviceID: String?

    /// The scopes associated with the token
    public let scope: String?

    /// Coding keys for mapping JSON fields to properties
    enum CodingKeys: String, CodingKey {
        case active
        case clientID = "client_id"
        case username
        case tokenType = "token_type"
        case exp, iat, jti, sub, aud, iss
        case deviceID = "device_id"
        case scope
    }
}
