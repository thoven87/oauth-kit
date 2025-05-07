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

/// Provider for AWS Cognito OAuth2/OpenID Connect authentication
public struct AWSCognitoOAuthProvider {
    /// The OAuthKit instance
    private let oauthKit: OAuthKit

    /// An OpenID Connect client configured for AWS Cognito
    private let client: OpenIDConnectClient

    /// Initialize a new AWS Cognito OAuth provider
    /// - Parameter oauthKit: The OAuthKit instance
    /// - Parameter openIDConnectClient: The OpenID Connect client configured for AWS Cognito
    internal init(
        oauthKit: OAuthKit,
        openIDConnectClient client: OpenIDConnectClient
    ) {
        self.oauthKit = oauthKit
        self.client = client
    }

    /// Build the AWS Cognito OpenID Connect discovery URL
    /// - Parameters:
    ///   - region: The AWS region where your user pool is located
    ///   - userPoolID: The Cognito User Pool ID
    ///   - domain: Optional custom domain for your Cognito user pool
    /// - Returns: The discovery URL
    internal static func buildDiscoveryURL(region: String, userPoolID: String, domain: String?) -> String {
        if let domain = domain {
            // Custom domain format
            let sanitizedDomain = domain.trimmingCharacters(in: .whitespaces).lowercased()
            let baseURL = sanitizedDomain.hasPrefix("https://") ? sanitizedDomain : "https://\(sanitizedDomain)"
            return "\(baseURL)/.well-known/openid-configuration"
        } else {
            // Default Cognito domain format
            return "https://cognito-idp.\(region).amazonaws.com/\(userPoolID)/.well-known/openid-configuration"
        }
    }

    /// Generate an authorization URL for AWS Cognito sign-in
    /// - Parameters:
    ///   - state: An opaque value to maintain state between the request and callback
    ///   - nonce: A random value for additional security
    ///   - identityProvider: The name of an identity provider configured in your user pool to bypass the Cognito UI
    ///   - idpIdentifier: The identity provider identifier (alternative to identityProvider)
    ///   - usePKCE: Whether to use PKCE (recommended and enabled by default)
    ///   - cognitoDomain: Custom or default domain for login UI (required when using hosted UI)
    /// - Returns: A tuple containing the authorization URL and code verifier (for PKCE)
    public func signInURL(
        state: String? = nil,
        nonce: String? = nil,
        identityProvider: String? = nil,
        idpIdentifier: String? = nil,
        usePKCE: Bool = true,
        cognitoDomain: String? = nil,
    ) throws -> (url: URL, codeVerifier: String?) {

        var codeVerifier: String? = nil
        var codeChallenge: String? = nil

        // Generate PKCE if requested
        if usePKCE {
            let pkce = OAuth2Client.generatePKCE()
            codeVerifier = pkce.codeVerifier
            codeChallenge = pkce.codeChallenge
        }

        // Prepare additional parameters for AWS Cognito
        var additionalParams: [String: String] = [:]

        if let nonce = nonce {
            additionalParams["nonce"] = nonce
        }

        // Identity Provider selection - used to bypass the Cognito UI
        if let identityProvider = identityProvider {
            additionalParams["identity_provider"] = identityProvider
        }

        // Identity Provider identifier - alternative to identity_provider
        if let idpIdentifier = idpIdentifier {
            additionalParams["idp_identifier"] = idpIdentifier
        }

        // Choose which authorization URL to use
        if let cognitoDomain = cognitoDomain {
            // If a specific Cognito domain is provided, use it (for hosted UI)
            let sanitizedDomain = cognitoDomain.trimmingCharacters(in: .whitespaces).lowercased()
            let baseURL = sanitizedDomain.hasPrefix("https://") ? sanitizedDomain : "https://\(sanitizedDomain)"

            // Build custom URL for Cognito hosted UI
            var urlComponents = URLComponents(string: "\(baseURL)/oauth2/authorize")!

            // Required parameters
            var queryItems = [
                URLQueryItem(name: "client_id", value: client.clientID),
                URLQueryItem(name: "response_type", value: "code"),
                URLQueryItem(name: "redirect_uri", value: client.redirectURI),
            ]

            // Optional parameters
            if !client.scope.isEmpty {
                queryItems.append(URLQueryItem(name: "scope", value: client.scope))
            }

            if let state = state {
                queryItems.append(URLQueryItem(name: "state", value: state))
            }

            if codeChallenge != nil {
                queryItems.append(URLQueryItem(name: "code_challenge", value: codeChallenge))
                queryItems.append(URLQueryItem(name: "code_challenge_method", value: "S256"))
            }

            // Add additional parameters
            for (key, value) in additionalParams {
                queryItems.append(URLQueryItem(name: key, value: value))
            }

            urlComponents.queryItems = queryItems

            guard let url = urlComponents.url else {
                throw OAuth2Error.configurationError("Failed to create authorization URL from components")
            }

            return (url, codeVerifier)
        } else {
            // Use standard OIDC flow if no Cognito domain provided
            let url = try client.authorizationURL(
                state: state,
                codeChallenge: codeChallenge,
                additionalParameters: additionalParams
            )

            return (url, codeVerifier)
        }
    }

    /// Exchange an authorization code for tokens with AWS Cognito
    /// - Parameters:
    ///   - code: The authorization code received from Cognito
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

    /// Get user information from AWS Cognito
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    /// - Returns: The user profile information
    public func getUserInfo(
        accessToken: String
    ) async throws -> AWSCognitoUserProfile {
        let userInfo: AWSCognitoUserProfile = try await client.getUserInfo(accessToken: accessToken)
        return userInfo
    }

    /// Revoke an AWS Cognito token
    /// - Parameters:
    ///   - token: The token to revoke
    ///   - tokenTypeHint: The token type hint (access_token or refresh_token)
    /// - Returns: True if the token was successfully revoked
    public func revokeToken(
        token: String,
        tokenTypeHint: String? = nil
    ) async throws -> Bool {
        // Check if revocation endpoint is available
        guard let revocationEndpoint = client.configuration.revocationEndpoint else {
            throw OAuth2Error.configurationError("Revocation endpoint not found in AWS Cognito configuration")
        }

        var parameters = ["token": token]
        if let tokenTypeHint = tokenTypeHint {
            parameters["token_type_hint"] = tokenTypeHint
        }

        var request = HTTPClientRequest(url: revocationEndpoint)
        request.method = .POST
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        // Use client authentication if client secret is available
        if !client.clientSecret.isEmpty {
            let credentials = "\(client.clientID):\(client.clientSecret)"
            let credentialsData = credentials.data(using: .utf8)!
            let base64Credentials = credentialsData.base64EncodedString()
            request.headers.add(name: "Authorization", value: "Basic \(base64Credentials)")
        } else {
            // If no client secret, add client_id as a parameter
            parameters["client_id"] = client.clientID
        }

        request.headers.add(name: "Content-Type", value: "application/x-www-form-urlencoded")

        // Add form parameters
        let formBody = parameters.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? $0.value)" }.joined(
            separator: "&"
        )
        request.body = .bytes(ByteBuffer(string: formBody))

        let response = try await oauthKit.httpClient.execute(request, timeout: .seconds(60))

        // A successful revocation returns a 200 OK
        return response.status == .ok
    }
}

/// AWS Cognito user profile information
public struct AWSCognitoUserProfile: Codable {
    /// The user's unique Cognito ID (subject identifier)
    public let id: String

    /// The user's email address
    public let email: String?

    /// Whether the user's email is verified
    public let emailVerified: Bool?

    /// The user's preferred username
    public let username: String?

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

    /// The user's address information
    public let address: IDTokenClaims.AddressClaim?

    /// The user's birth date
    public let birthdate: String?

    /// The user's locale
    public let locale: String?

    /// The user's gender
    public let gender: String?

    /// The user's profile URL
    public let profile: String?

    /// The user's picture URL
    public let picture: String?

    /// The user's website URL
    public let website: String?

    // Implement Codable protocol for JSON serialization
    private enum CodingKeys: String, CodingKey {
        case id = "sub"
        case email
        case emailVerified = "email_verified"
        case username = "cognito:username"
        case name
        case givenName = "given_name"
        case familyName = "family_name"
        case middleName = "middle_name"
        case nickname
        case phoneNumber = "phone_number"
        case phoneNumberVerified = "phone_number_verified"
        case address
        case birthdate
        case locale
        case gender
        case profile
        case picture
        case website
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        email = try container.decodeIfPresent(String.self, forKey: .email)
        emailVerified = try container.decodeIfPresent(Bool.self, forKey: .emailVerified)
        username = try container.decodeIfPresent(String.self, forKey: .username)
        name = try container.decodeIfPresent(String.self, forKey: .name)
        givenName = try container.decodeIfPresent(String.self, forKey: .givenName)
        familyName = try container.decodeIfPresent(String.self, forKey: .familyName)
        middleName = try container.decodeIfPresent(String.self, forKey: .middleName)
        nickname = try container.decodeIfPresent(String.self, forKey: .nickname)
        phoneNumber = try container.decodeIfPresent(String.self, forKey: .phoneNumber)
        phoneNumberVerified = try container.decodeIfPresent(Bool.self, forKey: .phoneNumberVerified)
        address = try container.decodeIfPresent(IDTokenClaims.AddressClaim.self, forKey: .address)
        birthdate = try container.decodeIfPresent(String.self, forKey: .birthdate)
        locale = try container.decodeIfPresent(String.self, forKey: .locale)
        gender = try container.decodeIfPresent(String.self, forKey: .gender)
        profile = try container.decodeIfPresent(String.self, forKey: .profile)
        picture = try container.decodeIfPresent(String.self, forKey: .picture)
        website = try container.decodeIfPresent(String.self, forKey: .website)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encodeIfPresent(email, forKey: .email)
        try container.encodeIfPresent(emailVerified, forKey: .emailVerified)
        try container.encodeIfPresent(username, forKey: .username)
        try container.encodeIfPresent(name, forKey: .name)
        try container.encodeIfPresent(givenName, forKey: .givenName)
        try container.encodeIfPresent(familyName, forKey: .familyName)
        try container.encodeIfPresent(middleName, forKey: .middleName)
        try container.encodeIfPresent(nickname, forKey: .nickname)
        try container.encodeIfPresent(phoneNumber, forKey: .phoneNumber)
        try container.encodeIfPresent(phoneNumberVerified, forKey: .phoneNumberVerified)
        try container.encodeIfPresent(address, forKey: .address)
        try container.encodeIfPresent(birthdate, forKey: .birthdate)
        try container.encodeIfPresent(locale, forKey: .locale)
        try container.encodeIfPresent(gender, forKey: .gender)
        try container.encodeIfPresent(profile, forKey: .profile)
        try container.encodeIfPresent(picture, forKey: .picture)
        try container.encodeIfPresent(website, forKey: .website)
    }
}
