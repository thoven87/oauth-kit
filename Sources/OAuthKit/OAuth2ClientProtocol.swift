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
import Crypto
import Foundation
import JWTKit
import Logging
import NIOFoundationCompat

/// Client for interacting with OAuth2 providers
public protocol OAuth2ClientProtocol: Sendable {
    /// HTTP client for making requests
    var httpClient: HTTPClient { get set }

    /// Client ID provided by the OAuth2 provider
    var clientID: String { get set }

    /// Client secret provided by the OAuth2 provider
    var clientSecret: String { get set }

    /// Token endpoint URL
    var tokenEndpoint: String { get set }

    /// Authorization endpoint URL (optional)
    var authorizationEndpoint: String? { get set }

    /// Redirect URI registered with the OAuth2 provider
    var redirectURI: String? { get set }

    /// Requested scopes (space-separated)
    var scope: String { get set }

    /// Logger used for OAuth operations
    var logger: Logger { get set }

    init(
        httpClient: HTTPClient,
        clientID: String,
        clientSecret: String,
        tokenEndpoint: String,
        authorizationEndpoint: String?,
        redirectURI: String?,
        scope: String,
        logger: Logger
    )
}

extension OAuth2ClientProtocol {

    /// Initialize a new OAuth2Client client
    /// - Parameters:
    ///   - httpClient: The HTTP client used for making requests
    ///   - clientID: The client ID provided by the OAuth2 provider
    ///   - clientSecret: The client secret provided by the OAuth2 provider
    ///   - tokenEndpoint: The OAuth2 token endpoint
    ///   - authorizationEndpoint:The OAuth2 authorization endpoint
    ///   - redirectURI: The redirect URI registered with the OAuth2 provider
    ///   - scope: The requested scopes (space-separated)
    ///   - logger: Logger used for OAuth2Client operations
    public init(
        httpClient: HTTPClient = HTTPClient.shared,
        clientID: String,
        clientSecret: String,
        tokenEndpoint: String,
        authorizationEndpoint: String? = nil,
        redirectURI: String? = nil,
        scope: String = "",
        logger: Logger = Logger(label: "com.oauthkit.OAuth2Client")
    ) {
        self.init(
            httpClient: httpClient,
            clientID: clientID,
            clientSecret: clientSecret,
            tokenEndpoint: tokenEndpoint,
            authorizationEndpoint: authorizationEndpoint,
            redirectURI: redirectURI,
            scope: scope,
            logger: logger
        )
    }

    /// Generate an authorization URL for the authorization code flow
    /// - Parameters:
    ///   - state: An opaque value used to maintain state between the request and callback
    ///   - codeChallenge: PKCE code challenge (if using PKCE)
    ///   - codeChallengeMethod: PKCE code challenge method (e.g., "S256")
    ///   - additionalParameters: Additional query parameters to include in the URL
    /// - Returns: The authorization URL
    /// - Throws: OAuth2Error if the authorization endpoint is not configured
    public func authorizationURL(
        state: String? = nil,
        codeChallenge: String? = nil,
        codeChallengeMethod: String? = nil,
        additionalParameters: [String: String] = [:]
    ) throws -> URL {
        guard let authorizationEndpoint = authorizationEndpoint else {
            throw OAuth2Error.configurationError("Authorization endpoint is required but not configured")
        }

        guard let redirectURI = redirectURI else {
            throw OAuth2Error.configurationError("Redirect URI is required for authorization flow but not configured")
        }

        guard var components = URLComponents(string: authorizationEndpoint) else {
            throw OAuth2Error.configurationError("Invalid authorization endpoint URL: \(authorizationEndpoint)")
        }

        var queryItems = [
            URLQueryItem(name: "client_id", value: clientID),
            URLQueryItem(name: "redirect_uri", value: redirectURI),
            URLQueryItem(name: "response_type", value: "code"),
        ]

        if !scope.isEmpty {
            queryItems.append(URLQueryItem(name: "scope", value: scope))
        }

        if let state = state {
            queryItems.append(URLQueryItem(name: "state", value: state))
        }

        if let codeChallenge = codeChallenge {
            queryItems.append(URLQueryItem(name: "code_challenge", value: codeChallenge))

            if let codeChallengeMethod = codeChallengeMethod {
                queryItems.append(URLQueryItem(name: "code_challenge_method", value: codeChallengeMethod))
            } else {
                queryItems.append(URLQueryItem(name: "code_challenge_method", value: "S256"))
            }
        }

        // Add any additional parameters
        for (key, value) in additionalParameters {
            queryItems.append(URLQueryItem(name: key, value: value))
        }

        components.queryItems = queryItems

        guard let url = components.url else {
            throw OAuth2Error.configurationError("Failed to create authorization URL from components")
        }

        return url
    }

    /// Exchange an authorization code for tokens
    /// - Parameters:
    ///   - code: The authorization code received from the authorization server
    ///   - codeVerifier: PKCE code verifier (if using PKCE)
    ///   - additionalParameters: Additional parameters to include in the token request
    /// - Returns: The token response
    /// - Throws: OAuth2Error if the token exchange fails
    public func getToken(
        code: String,
        codeVerifier: String? = nil,
        additionalParameters: [String: String] = [:]
    ) async throws -> TokenResponse {
        guard let redirectURI = redirectURI else {
            throw OAuth2Error.configurationError("Redirect URI is required for authorization code exchange but not configured")
        }

        var parameters = [
            "grant_type": "authorization_code",
            "code": code,
            "client_id": clientID,
            "client_secret": clientSecret,
            "redirect_uri": redirectURI,
        ]

        if let codeVerifier = codeVerifier {
            parameters["code_verifier"] = codeVerifier
        }

        // Add any additional parameters
        for (key, value) in additionalParameters {
            parameters[key] = value
        }

        return try await requestToken(parameters: parameters)
    }

    /// Request a token using client credentials grant
    /// - Parameter additionalParameters: Additional parameters to include in the token request
    /// - Returns: The token response
    /// - Throws: OAuth2Error if the token request fails
    public func clientCredentials(
        additionalParameters: [String: String] = [:]
    ) async throws -> TokenResponse {
        var parameters = [
            "grant_type": "client_credentials",
            "client_id": clientID,
            "client_secret": clientSecret,
        ]

        if !scope.isEmpty {
            parameters["scope"] = scope
        }

        // Add any additional parameters
        for (key, value) in additionalParameters {
            parameters[key] = value
        }

        return try await requestToken(parameters: parameters)
    }

    /// Refresh an access token using a refresh token
    /// - Parameters:
    ///   - refreshToken: The refresh token
    ///   - additionalParameters: Additional parameters to include in the token request
    /// - Returns: The token response
    /// - Throws: OAuth2Error if the token refresh fails
    public func refreshToken(
        _ refreshToken: String,
        additionalParameters: [String: String] = [:]
    ) async throws -> TokenResponse {
        var parameters = [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "client_id": clientID,
            "client_secret": clientSecret,
        ]

        // Add any additional parameters
        for (key, value) in additionalParameters {
            parameters[key] = value
        }

        return try await requestToken(parameters: parameters)
    }

    /// Makes a request to the token endpoint
    /// - Parameter parameters: The parameters to include in the token request
    /// - Returns: The token response
    /// - Throws: OAuth2Error if the token request fails
    internal func requestToken(parameters: [String: String]) async throws -> TokenResponse {
        guard let url = URL(string: tokenEndpoint) else {
            throw OAuth2Error.configurationError("Invalid token endpoint URL: \(tokenEndpoint)")
        }

        // Convert parameters to form-urlencoded body
        let formBody =
            parameters
            .map { key, value in
                "\(key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? key)=\(value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value)"
            }
            .joined(separator: "&")

        guard let bodyData = formBody.data(using: .utf8) else {
            throw OAuth2Error.configurationError("Failed to encode request parameters")
        }

        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .POST
        request.headers.add(name: "Content-Type", value: "application/x-www-form-urlencoded")
        request.headers.add(name: "Accept", value: "application/json")
        request.headers.add(name: "User-Agent", value: USER_AGENT)
        request.body = .bytes(bodyData)

        do {
            let response = try await httpClient.execute(request, timeout: .seconds(60))

            guard response.status == .ok else {
                // Try to get error details from the response body
                let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
                let responseString = String(buffer: responseBody)

                logger.error("Token request failed with status: \(response.status), body: \(responseString)")
                throw OAuth2Error.tokenExchangeError("Token request failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
            let decoder = JSONDecoder()
            return try decoder.decode(TokenResponse.self, from: responseBody)
        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("Token request failed with error: \(error)")
            throw OAuth2Error.networkError("Token request failed: \(error)")
        }
    }

    /// Generate PKCE code challenge and verifier
    /// - Returns: A tuple containing the code verifier and code challenge
    public static func generatePKCE() -> (codeVerifier: String, codeChallenge: String) {
        // Generate a random code verifier
        let codeVerifier = generateRandomString(length: 64)

        // Generate the code challenge using SHA256
        guard let verifierData = codeVerifier.data(using: .ascii) else {
            fatalError("Failed to encode code verifier")
        }

        let challengeData = Data(SHA256.hash(data: verifierData))
        let codeChallenge = challengeData.base64URLEncodedString()

        return (codeVerifier, codeChallenge)
    }

    /// Generate a random string for PKCE
    /// - Parameter length: The length of the random string
    /// - Returns: A random string using URL-safe characters
    private static func generateRandomString(length: Int) -> String {
        let characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
        var randomString = ""

        for _ in 0..<length {
            let randomIndex = Int.random(in: 0..<characters.count)
            let randomCharacter = characters[characters.index(characters.startIndex, offsetBy: randomIndex)]
            randomString.append(randomCharacter)
        }

        return randomString
    }

    internal static func getJWKS(httpClient: HTTPClient, jwksURL: String) async throws -> JWKS {
        let request = HTTPClientRequest(url: jwksURL)
        let response = try await httpClient.execute(request, timeout: .seconds(60))
        let jwks = try await response.body.collect(upTo: 1024 * 1024)  // 1MB
        return try JSONDecoder().decode(JWKS.self, from: jwks)
    }
}

/// Extension for base64URL encoding
extension Data {
    /// Encode data as base64URL string (base64 without padding, replacing '+' with '-' and '/' with '_')
    /// - Returns: The base64URL encoded string
    fileprivate func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
