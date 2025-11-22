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
import NIOHTTP1

/// Provider for Okta OAuth2/OpenID Connect authentication
public struct OktaOAuthProvider: Sendable {
    /// The OAuthKit instance
    private let oauthKit: OAuthClientFactory

    /// An OpenID Connect client configured for Okta
    private let client: OpenIDConnectClient

    /// Initialize a new Okta OAuth provider
    /// - Parameter oauthKit: The OAuthKit instance
    internal init(oauthKit: OAuthClientFactory, client: OpenIDConnectClient) {
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
    ///   - prompt: Controls the Okta sign-in prompt behavior
    ///   - idpID: The identity provider ID to bypass the Okta sign-in page and go directly to the specified IdP
    ///   - usePKCE: Whether to use PKCE (recommended and enabled by default)
    ///   - scopes: The requested scopes
    /// - Returns: A tuple containing the authorization URL and code verifier (for PKCE)
    public func generateAuthorizationURL(
        state: String? = nil,
        prompt: OktaPrompt? = nil,
        idpID: String? = nil,
        usePKCE: Bool = true,
        additionalParameters: [String: String] = [:],
        scopes: [String] = ["openid", "profile", "email", "offline_access"]
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
        var additionalParams = additionalParameters

        if let prompt = prompt {
            additionalParams["prompt"] = prompt.rawValue
        }

        // Add idp parameter to bypass Okta and go directly to the specified IdP
        if let idpID = idpID {
            additionalParams["idp"] = idpID
        }

        // Okta uses OIDC standard flow, so we can leverage the OpenIDConnectClient
        let url = try client.generateAuthorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            additionalParameters: additionalParams,
            scopes: scopes
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

    // MARK: - MFA Challenge Flow Support

    /// Authenticate with username and password to initiate MFA challenge
    /// - Parameters:
    ///   - username: User's username or email
    ///   - password: User's password
    /// - Returns: MFA challenge response with available factors
    /// - Throws: OktaMFAError or OAuth2Error if authentication fails
    public func authenticateWithPassword(
        username: String,
        password: String
    ) async throws -> OktaMFAChallenge {
        let baseURL = extractBaseURL()
        let authURL = "\(baseURL)/api/v1/authn"

        let request = [
            "username": username,
            "password": password,
        ]

        return try await makeOktaAPIRequest(
            url: authURL,
            method: HTTPMethod.POST,
            body: request,
            responseType: OktaMFAChallenge.self
        )
    }

    /// Verify an MFA factor
    /// - Parameters:
    ///   - factorId: The ID of the MFA factor to verify
    ///   - stateToken: The state token from the MFA challenge
    ///   - verifyRequest: The verification request with code or other data
    /// - Returns: MFA verification response
    /// - Throws: OktaMFAError if verification fails
    public func verifyMFAFactor(
        factorId: String,
        stateToken: String,
        verifyRequest: OktaMFAVerifyRequest
    ) async throws -> OktaMFAVerifyResponse {
        let baseURL = extractBaseURL()
        let verifyURL = "\(baseURL)/api/v1/authn/factors/\(factorId)/verify"

        return try await makeOktaAPIRequest(
            url: verifyURL,
            method: HTTPMethod.POST,
            body: verifyRequest,
            responseType: OktaMFAVerifyResponse.self
        )
    }

    /// Initiate push notification for Okta Verify
    /// - Parameters:
    ///   - factorId: The ID of the push factor
    ///   - stateToken: The state token from the MFA challenge
    /// - Returns: MFA verification response with challenge context
    /// - Throws: OktaMFAError if push initiation fails
    public func initiateOktaVerifyPush(
        factorId: String,
        stateToken: String
    ) async throws -> OktaMFAVerifyResponse {
        let verifyRequest = OktaMFAVerifyRequest(
            stateToken: stateToken,
            autoPush: true
        )

        return try await verifyMFAFactor(
            factorId: factorId,
            stateToken: stateToken,
            verifyRequest: verifyRequest
        )
    }

    /// Poll for push notification completion
    /// - Parameters:
    ///   - factorId: The ID of the push factor
    ///   - stateToken: The state token from the MFA challenge
    ///   - timeout: Maximum time to wait in seconds (default 60)
    ///   - interval: Polling interval in seconds (default 2)
    /// - Returns: MFA poll result when push is approved or denied
    /// - Throws: OktaMFAError if polling fails or times out
    public func pollForPushApproval(
        factorId: String,
        stateToken: String,
        timeout: TimeInterval = 60,
        interval: TimeInterval = 2
    ) async throws -> OktaMFAPollResult {
        let baseURL = extractBaseURL()
        let pollURL = "\(baseURL)/api/v1/authn/factors/\(factorId)/poll"

        let startTime = Date()

        while Date().timeIntervalSince(startTime) < timeout {
            do {
                let pollRequest = ["stateToken": stateToken]
                let result = try await makeOktaAPIRequest(
                    url: pollURL,
                    method: HTTPMethod.POST,
                    body: pollRequest,
                    responseType: OktaMFAPollResult.self
                )

                // Check if push was approved or denied
                if result.status == .success || result.factorResult == "SUCCESS" {
                    return result
                } else if result.factorResult == "REJECTED" || result.factorResult == "TIMEOUT" {
                    throw OktaMFAError.userDenied
                }

                // Continue polling
                try await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))

            } catch OktaMFAError.userDenied {
                throw OktaMFAError.userDenied
            } catch {
                // Continue polling on other errors
                try await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
            }
        }

        throw OktaMFAError.challengeTimeout
    }

    /// Complete MFA flow and get session token
    /// - Parameters:
    ///   - stateToken: The state token from successful MFA verification
    /// - Returns: Session token for completing OAuth flow
    /// - Throws: OktaMFAError if session token exchange fails
    public func getSessionToken(stateToken: String) async throws -> String {
        let baseURL = extractBaseURL()
        let sessionURL = "\(baseURL)/api/v1/sessions"

        let request = ["sessionToken": stateToken]

        struct SessionResponse: Codable {
            let id: String
        }

        let response = try await makeOktaAPIRequest(
            url: sessionURL,
            method: HTTPMethod.POST,
            body: request,
            responseType: SessionResponse.self
        )

        return response.id
    }

    /// Generate authorization URL with MFA session token for OAuth flow completion
    /// - Parameters:
    ///   - sessionToken: Session token from completed MFA flow
    ///   - state: State parameter for OAuth flow (defaults to UUID if not provided)
    ///   - scopes: OAuth scopes to request
    /// - Returns: Authorization URL and code verifier for OAuth flow completion
    /// - Throws: OAuth2Error if URL generation fails
    public func generateAuthURLWithSession(
        sessionToken: String,
        state: String? = nil,
        scopes: [String] = ["openid", "profile", "email"]
    ) async throws -> (url: URL, codeVerifier: String?) {
        try await generateAuthorizationURL(
            state: state ?? UUID().uuidString,
            additionalParameters: ["sessionToken": sessionToken],
            scopes: scopes
        )
    }

    // MARK: - Helper Methods

    /// Extract base URL from OpenID Connect configuration
    private func extractBaseURL() -> String {
        let issuer = client.configuration.issuer
        // Remove /.well-known/openid_configuration or /oauth2/default if present
        if issuer.contains("/oauth2/") {
            return String(issuer.prefix(while: { $0 != "/" }) + "://" + issuer.drop(while: { $0 != "/" }).dropFirst().prefix(while: { $0 != "/" }))
        }
        return issuer
    }

    /// Make authenticated API request to Okta
    private func makeOktaAPIRequest<T: Codable, U: Codable>(
        url: String,
        method: HTTPMethod,
        body: T,
        responseType: U.Type
    ) async throws -> U {
        var request = HTTPClientRequest(url: url)
        request.method = method
        request.headers.add(name: "Content-Type", value: "application/json")
        request.headers.add(name: "Accept", value: "application/json")
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        // Encode request body
        let encoder = JSONEncoder()
        let bodyData = try encoder.encode(body)
        request.body = .bytes(bodyData)

        let response = try await oauthKit.httpClient.execute(request, timeout: .seconds(60))

        let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
        let responseData = Data(buffer: responseBody)

        guard response.status.code >= 200 && response.status.code < 300 else {
            // Try to parse error response
            if let errorString = String(data: responseData, encoding: .utf8) {
                throw OktaMFAError.apiError("HTTP \(response.status.code): \(errorString)")
            } else {
                throw OktaMFAError.apiError("HTTP \(response.status.code)")
            }
        }

        let decoder = JSONDecoder()
        do {
            return try decoder.decode(responseType, from: responseData)
        } catch {
            throw OktaMFAError.apiError("Failed to decode response: \(error)")
        }
    }

    /// Complete Okta MFA authentication flow with push notification
    /// - Parameters:
    ///   - username: User's username or email
    ///   - password: User's password
    ///   - preferredFactorType: Preferred MFA factor type (default: push)
    ///   - state: OAuth state parameter (optional, defaults to UUID)
    ///   - scopes: OAuth scopes to request
    /// - Returns: Authorization URL and code verifier for OAuth flow completion
    /// - Throws: OktaMFAError or OAuth2Error if authentication fails
    public func authenticateWithMFA(
        username: String,
        password: String,
        preferredFactorType: OktaMFAFactorType = .push,
        state: String? = nil,
        scopes: [String] = ["openid", "profile", "email"]
    ) async throws -> (url: URL, codeVerifier: String?) {
        // Step 1: Authenticate with username/password
        let mfaChallenge = try await authenticateWithPassword(username: username, password: password)

        // Step 2: Find preferred factor
        guard let factor = mfaChallenge.factors.first(where: { $0.factorType == preferredFactorType }) else {
            throw OktaMFAError.factorNotFound
        }

        // Step 3: Handle different factor types
        let verifyResponse: OktaMFAVerifyResponse

        switch preferredFactorType {
        case .push:
            // Initiate push notification
            verifyResponse = try await initiateOktaVerifyPush(
                factorId: factor.id,
                stateToken: mfaChallenge.stateToken
            )

            // Show challenge number to user if available
            if let challengeNumber = verifyResponse.challengeContext?.challengeNumber {
                print("Okta Verify Push: Please approve the notification and verify the number: \(challengeNumber)")
            }

            // Poll for approval
            let pollResult = try await pollForPushApproval(
                factorId: factor.id,
                stateToken: mfaChallenge.stateToken,
                timeout: 60
            )

            guard let sessionToken = pollResult.sessionToken else {
                throw OktaMFAError.factorVerificationFailed("No session token received")
            }

            // Generate OAuth URL with session token for flow completion
            return try await generateAuthURLWithSession(
                sessionToken: sessionToken,
                state: state,
                scopes: scopes
            )

        default:
            throw OktaMFAError.invalidFactorType("Factor type \(preferredFactorType.rawValue) not yet implemented")
        }
    }

    /// Get available MFA factors for a user
    /// - Parameters:
    ///   - username: User's username or email
    ///   - password: User's password
    /// - Returns: List of available MFA factors
    /// - Throws: OktaMFAError if authentication fails
    public func getAvailableMFAFactors(
        username: String,
        password: String
    ) async throws -> [OktaMFAFactor] {
        let mfaChallenge = try await authenticateWithPassword(username: username, password: password)
        return mfaChallenge.factors
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
