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

    /// Logger used for OAuth operations
    var logger: Logger { get set }

    init(
        httpClient: HTTPClient,
        clientID: String,
        clientSecret: String,
        tokenEndpoint: String,
        authorizationEndpoint: String?,
        redirectURI: String?,
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
    ///   - scopes: The requested scopes
    ///   - logger: Logger used for OAuth2Client operations
    public init(
        httpClient: HTTPClient = HTTPClient.shared,
        clientID: String,
        clientSecret: String,
        tokenEndpoint: String,
        authorizationEndpoint: String?,
        redirectURI: String?,
        logger: Logger = Logger(label: "com.oauthkit.OAuth2Client")
    ) {
        self.init(
            httpClient: httpClient,
            clientID: clientID,
            clientSecret: clientSecret,
            tokenEndpoint: tokenEndpoint,
            authorizationEndpoint: authorizationEndpoint,
            redirectURI: redirectURI,
            logger: logger
        )
    }

    /// Generate an authorization URL for the authorization code flow
    /// - Parameters:
    ///   - state: An opaque value used to maintain state between the request and callback
    ///   - codeChallenge: PKCE code challenge (if using PKCE)
    ///   - codeChallengeMethod: PKCE code challenge method (e.g., "S256")
    ///   - additionalParameters: Additional query parameters to include in the URL
    ///   - scopes: The requested scopes
    /// - Returns: The authorization URL
    /// - Throws: OAuth2Error if the authorization endpoint is not configured
    public func generateAuthorizationURL(
        state: String?,
        codeChallenge: String?,
        codeChallengeMethod: OAuthCodeChallengeMethod? = .s256,
        additionalParameters: [String: String],
        scopes: [String]
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

        if !scopes.isEmpty {
            queryItems.append(URLQueryItem(name: "scope", value: scopesToString(scopes)))
        }

        if let state = state {
            queryItems.append(URLQueryItem(name: "state", value: state))
        }

        if let codeChallenge = codeChallenge {
            queryItems.append(URLQueryItem(name: "code_challenge", value: codeChallenge))

            if let codeChallengeMethod = codeChallengeMethod {
                queryItems.append(URLQueryItem(name: "code_challenge_method", value: codeChallengeMethod.rawValue))
            } else {
                queryItems.append(URLQueryItem(name: "code_challenge_method", value: OAuthCodeChallengeMethod.s256.rawValue))
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
        codeVerifier: String?,
        additionalParameters: [String: String]
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
        additionalParameters: [String: String],
        scopes: [String]
    ) async throws -> TokenResponse {
        var parameters = [
            "grant_type": "client_credentials",
            "client_id": clientID,
            "client_secret": clientSecret,
        ]

        if !scopes.isEmpty {
            parameters["scope"] = scopesToString(scopes)
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
        additionalParameters: [String: String]
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

    /// Request device authorization for device flow (RFC 8628)
    /// - Parameters:
    ///   - scopes: The requested scopes
    ///   - additionalParameters: Additional parameters to include in the device authorization request
    /// - Returns: Device authorization response containing device code, user code, and verification URI
    /// - Throws: OAuth2Error if the device authorization request fails
    public func requestDeviceAuthorization(
        scopes: [String],
        additionalParameters: [String: String] = [:]
    ) async throws -> DeviceAuthorizationResponse {
        guard let authorizationEndpoint = authorizationEndpoint else {
            throw OAuth2Error.configurationError("Authorization endpoint is required for device flow but not configured")
        }

        // Construct device authorization endpoint
        let deviceAuthEndpoint: String
        if authorizationEndpoint.hasSuffix("/") {
            deviceAuthEndpoint = authorizationEndpoint + "device_authorization"
        } else {
            deviceAuthEndpoint = authorizationEndpoint + "/device_authorization"
        }

        guard let url = URL(string: deviceAuthEndpoint) else {
            throw OAuth2Error.configurationError("Invalid device authorization endpoint URL: \(deviceAuthEndpoint)")
        }

        var parameters = [
            "client_id": clientID
        ]

        if !scopes.isEmpty {
            parameters["scope"] = scopesToString(scopes)
        }

        // Add any additional parameters
        for (key, value) in additionalParameters {
            parameters[key] = value
        }

        return try await requestDeviceAuthorization(url: url, parameters: parameters)
    }

    /// Exchange device code for tokens (device flow polling)
    /// - Parameters:
    ///   - deviceCode: The device code from device authorization response
    ///   - additionalParameters: Additional parameters to include in the token request
    /// - Returns: The token response
    /// - Throws: OAuth2Error or DeviceFlowError if the token exchange fails
    public func exchangeDeviceCode(
        _ deviceCode: String,
        additionalParameters: [String: String] = [:]
    ) async throws -> TokenResponse {
        var parameters = [
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": deviceCode,
            "client_id": clientID,
        ]

        // Add client secret if available (for confidential clients)
        if !clientSecret.isEmpty {
            parameters["client_secret"] = clientSecret
        }

        // Add any additional parameters
        for (key, value) in additionalParameters {
            parameters[key] = value
        }

        do {
            return try await requestToken(parameters: parameters)
        } catch OAuth2Error.tokenError(let message) {
            // Check if this is a device flow specific error
            if message.contains("authorization_pending") {
                throw DeviceFlowError.authorizationPending
            } else if message.contains("slow_down") {
                throw DeviceFlowError.slowDown
            } else if message.contains("expired_token") {
                throw DeviceFlowError.expiredToken
            } else if message.contains("access_denied") {
                throw DeviceFlowError.accessDenied
            } else {
                throw OAuth2Error.tokenError(message)
            }
        }
    }

    /// Poll for device authorization completion with automatic retry logic
    /// - Parameters:
    ///   - deviceCode: The device code from device authorization response
    ///   - interval: Polling interval in seconds (default from device auth response)
    ///   - timeout: Maximum time to wait in seconds (default 300)
    ///   - additionalParameters: Additional parameters to include in token requests
    /// - Returns: The token response when authorization is complete
    /// - Throws: DeviceFlowError or OAuth2Error if polling fails or times out
    public func pollForDeviceAuthorization(
        deviceCode: String,
        interval: Int = 5,
        timeout: TimeInterval = 300,
        additionalParameters: [String: String] = [:]
    ) async throws -> TokenResponse {
        let startTime = Date()
        var currentInterval = interval

        while Date().timeIntervalSince(startTime) < timeout {
            do {
                return try await exchangeDeviceCode(deviceCode, additionalParameters: additionalParameters)
            } catch DeviceFlowError.authorizationPending {
                // Continue polling
                try await Task.sleep(nanoseconds: UInt64(currentInterval * 1_000_000_000))
            } catch DeviceFlowError.slowDown {
                // Increase polling interval and continue
                currentInterval = max(currentInterval + 5, 10)
                logger.debug("Slowing down device flow polling to \(currentInterval) seconds")
                try await Task.sleep(nanoseconds: UInt64(currentInterval * 1_000_000_000))
            } catch {
                // Other errors should be propagated immediately
                throw error
            }
        }

        throw DeviceFlowError.expiredToken
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
                throw OAuth2Error.tokenError("Token request failed with status: \(response.status)")
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
        let maxRetries = 5
        let baseDelay: UInt64 = 1_000_000_000  // 1 second in nanoseconds
        var lastError: Error?

        for attempt in 1...maxRetries {
            do {
                var request = HTTPClientRequest(url: jwksURL)
                request.headers.add(name: "User-Agent", value: USER_AGENT)

                let response = try await httpClient.execute(request, timeout: .seconds(60))

                guard response.status == .ok else {
                    let statusError = OAuth2Error.jwksError("JWKS request failed with status: \(response.status)")
                    if attempt == maxRetries {
                        throw statusError
                    }
                    lastError = statusError
                    try await Task.sleep(nanoseconds: baseDelay * UInt64(attempt))
                    continue
                }

                let jwks = try await response.body.collect(upTo: 1024 * 1024)  // 1MB
                return try JSONDecoder().decode(JWKS.self, from: jwks)
            } catch let error as OAuth2Error {
                if attempt == maxRetries {
                    throw error
                }
                lastError = error
                try await Task.sleep(nanoseconds: baseDelay * UInt64(attempt))
            } catch {
                if attempt == maxRetries {
                    throw OAuth2Error.jwksError("JWKS request failed: \(error)")
                }
                lastError = error
                try await Task.sleep(nanoseconds: baseDelay * UInt64(attempt))
            }
        }

        // This should never be reached
        if let lastError = lastError {
            if let oauth2Error = lastError as? OAuth2Error {
                throw oauth2Error
            } else {
                throw OAuth2Error.jwksError("JWKS request failed after all retry attempts: \(lastError)")
            }
        } else {
            throw OAuth2Error.jwksError("JWKS request failed after all retry attempts")
        }
    }

    /// Internal method for making device authorization requests
    /// - Parameters:
    ///   - url: The device authorization endpoint URL
    ///   - parameters: The parameters to include in the request
    /// - Returns: Device authorization response
    /// - Throws: OAuth2Error if the request fails
    internal func requestDeviceAuthorization(url: URL, parameters: [String: String]) async throws -> DeviceAuthorizationResponse {
        // Convert parameters to form-urlencoded body
        let formBody =
            parameters
            .map { key, value in
                "\(key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? key)=\(value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value)"
            }
            .joined(separator: "&")

        guard let bodyData = formBody.data(using: .utf8) else {
            throw OAuth2Error.configurationError("Failed to encode device authorization parameters")
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

                logger.error("Device authorization request failed with status: \(response.status), body: \(responseString)")
                throw OAuth2Error.configurationError("Device authorization request failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
            let decoder = JSONDecoder()
            return try decoder.decode(DeviceAuthorizationResponse.self, from: responseBody)
        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("Device authorization request failed with error: \(error)")
            throw OAuth2Error.networkError("Device authorization request failed: \(error)")
        }
    }

    /// Perform OAuth 2.0 Token Exchange (RFC 8693)
    /// - Parameter request: The token exchange request containing all parameters
    /// - Returns: The token exchange response
    /// - Throws: OAuth2Error if the exchange fails
    public func exchangeToken(_ request: TokenExchangeRequest) async throws -> TokenResponse {
        logger.debug("Performing token exchange")

        var parameters = request.toParameters()

        // Add client authentication
        parameters["client_id"] = clientID
        parameters["client_secret"] = clientSecret

        do {
            let response = try await requestTokenExchange(parameters: parameters)
            logger.debug("Token exchange successful")
            return response
        } catch let error as OAuth2Error {
            logger.error("Token exchange failed: \(error.errorDescription ?? "Unknown error")")
            throw error
        } catch {
            logger.error("Token exchange failed with error: \(error)")
            throw OAuth2Error.tokenError("Token exchange failed: \(error)")
        }
    }

    /// Convenience method for token exchange with individual parameters
    /// - Parameters:
    ///   - subjectToken: The token being exchanged
    ///   - subjectTokenType: The type of the subject token
    ///   - requestedTokenType: The type of token being requested (optional)
    ///   - resource: The target resource for the token (optional)
    ///   - audience: The logical name of the target service (optional)
    ///   - scope: The requested scope (optional)
    ///   - actorToken: Token representing the acting party (optional)
    ///   - actorTokenType: The type of the actor token (optional)
    /// - Returns: The token exchange response
    /// - Throws: OAuth2Error if the exchange fails
    public func exchangeToken(
        subjectToken: String,
        subjectTokenType: TokenType,
        requestedTokenType: TokenType? = nil,
        resource: [String]? = nil,
        audience: [String]? = nil,
        scope: [String]? = nil,
        actorToken: String? = nil,
        actorTokenType: TokenType? = nil
    ) async throws -> TokenResponse {
        let request = TokenExchangeRequest(
            subjectToken: subjectToken,
            subjectTokenType: subjectTokenType,
            requestedTokenType: requestedTokenType,
            resource: resource,
            audience: audience,
            scope: scope,
            actorToken: actorToken,
            actorTokenType: actorTokenType
        )

        return try await exchangeToken(request)
    }

    /// Internal method to make the token exchange HTTP request
    /// - Parameter parameters: Form parameters for the token exchange request
    /// - Returns: The token exchange response
    /// - Throws: OAuth2Error if the request fails
    internal func requestTokenExchange(parameters: [String: String]) async throws -> TokenResponse {
        guard let url = URL(string: tokenEndpoint) else {
            throw OAuth2Error.configurationError("Invalid token endpoint URL: \(tokenEndpoint)")
        }

        let body = parameters.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? $0.value)" }
            .joined(separator: "&")

        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .POST
        request.headers.add(name: "Content-Type", value: "application/x-www-form-urlencoded")
        request.headers.add(name: "Accept", value: "application/json")
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        guard let bodyData = body.data(using: .utf8) else {
            throw OAuth2Error.configurationError("Failed to encode request parameters")
        }
        request.body = .bytes(bodyData)

        logger.debug("Making token exchange request to: \(tokenEndpoint)")

        do {
            let response = try await httpClient.execute(request, timeout: .seconds(30))

            guard response.status == .ok else {
                let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
                let responseString = String(buffer: responseBody)

                logger.error("Token exchange failed with status: \(response.status), body: \(responseString)")
                throw OAuth2Error.tokenError("Token exchange failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
            return try JSONDecoder().decode(TokenResponse.self, from: responseBody)

        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("Token exchange request failed with error: \(error)")
            throw OAuth2Error.networkError("Token exchange request failed: \(error)")
        }
    }

    /// Perform OAuth 2.0 Token Introspection (RFC 7662)
    /// - Parameter request: The token introspection request containing the token and optional hint
    /// - Returns: The token introspection response
    /// - Throws: OAuth2Error if the introspection fails
    public func introspectToken(_ request: TokenIntrospectionRequest) async throws -> TokenIntrospectionResponse {
        logger.debug("Performing token introspection")

        var parameters = request.toParameters()

        // Add client authentication
        parameters["client_id"] = clientID
        parameters["client_secret"] = clientSecret

        do {
            let response = try await requestTokenIntrospection(parameters: parameters)
            logger.debug("Token introspection successful")
            return response
        } catch let error as OAuth2Error {
            logger.error("Token introspection failed: \(error.errorDescription ?? "Unknown error")")
            throw error
        } catch {
            logger.error("Token introspection failed with error: \(error)")
            throw OAuth2Error.tokenError("Token introspection failed: \(error)")
        }
    }

    /// Convenience method for token introspection with individual parameters
    /// - Parameters:
    ///   - token: The token to introspect
    ///   - tokenTypeHint: A hint about the type of token being introspected (optional)
    /// - Returns: The token introspection response
    /// - Throws: OAuth2Error if the introspection fails
    public func introspectToken(
        token: String,
        tokenTypeHint: String? = nil
    ) async throws -> TokenIntrospectionResponse {
        let request = TokenIntrospectionRequest(token: token, tokenTypeHint: tokenTypeHint)
        return try await introspectToken(request)
    }

    /// Internal method to make the token introspection HTTP request
    /// - Parameter parameters: Form parameters for the token introspection request
    /// - Returns: The token introspection response
    /// - Throws: OAuth2Error if the request fails
    internal func requestTokenIntrospection(parameters: [String: String]) async throws -> TokenIntrospectionResponse {
        // Use conventional introspection endpoint pattern
        let baseURL = tokenEndpoint.replacingOccurrences(of: "/token", with: "")
        let introspectionEndpoint = "\(baseURL)/introspect"

        guard let url = URL(string: introspectionEndpoint) else {
            throw OAuth2Error.configurationError("Invalid introspection endpoint URL: \(introspectionEndpoint)")
        }

        let body = parameters.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? $0.value)" }
            .joined(separator: "&")

        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .POST
        request.headers.add(name: "Content-Type", value: "application/x-www-form-urlencoded")
        request.headers.add(name: "Accept", value: "application/json")
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        guard let bodyData = body.data(using: .utf8) else {
            throw OAuth2Error.configurationError("Failed to encode request parameters")
        }
        request.body = .bytes(bodyData)

        logger.debug("Making token introspection request to: \(introspectionEndpoint)")

        do {
            let response = try await httpClient.execute(request, timeout: .seconds(30))

            guard response.status == .ok else {
                let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
                let responseString = String(buffer: responseBody)

                logger.error("Token introspection failed with status: \(response.status), body: \(responseString)")
                throw OAuth2Error.tokenError("Token introspection failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
            return try JSONDecoder().decode(TokenIntrospectionResponse.self, from: responseBody)

        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("Token introspection request failed with error: \(error)")
            throw OAuth2Error.networkError("Token introspection request failed: \(error)")
        }
    }

    /// Perform OAuth 2.0 Token Revocation (RFC 7009)
    /// - Parameter request: The token revocation request containing the token and optional hint
    /// - Returns: The token revocation response
    /// - Throws: OAuth2Error if the revocation fails
    public func revokeToken(_ request: TokenRevocationRequest) async throws -> TokenRevocationResponse {
        logger.debug("Performing token revocation")

        var parameters = request.toParameters()

        // Add client authentication
        parameters["client_id"] = clientID
        parameters["client_secret"] = clientSecret

        do {
            let response = try await requestTokenRevocation(parameters: parameters)
            logger.debug("Token revocation successful")
            return response
        } catch let error as OAuth2Error {
            logger.error("Token revocation failed: \(error.errorDescription ?? "Unknown error")")
            throw error
        } catch {
            logger.error("Token revocation failed with error: \(error)")
            throw OAuth2Error.tokenError("Token revocation failed: \(error)")
        }
    }

    /// Convenience method for token revocation with individual parameters
    /// - Parameters:
    ///   - token: The token to revoke
    ///   - tokenTypeHint: A hint about the type of token being revoked (optional)
    /// - Returns: The token revocation response
    /// - Throws: OAuth2Error if the revocation fails
    public func revokeToken(
        token: String,
        tokenTypeHint: String? = nil
    ) async throws -> TokenRevocationResponse {
        let request = TokenRevocationRequest(token: token, tokenTypeHint: tokenTypeHint)
        return try await revokeToken(request)
    }

    /// Internal method to make the token revocation HTTP request
    /// - Parameter parameters: Form parameters for the token revocation request
    /// - Returns: The token revocation response
    /// - Throws: OAuth2Error if the request fails
    internal func requestTokenRevocation(parameters: [String: String]) async throws -> TokenRevocationResponse {
        // Use conventional revocation endpoint pattern
        let baseURL = tokenEndpoint.replacingOccurrences(of: "/token", with: "")
        let revocationEndpoint = "\(baseURL)/revoke"

        guard let url = URL(string: revocationEndpoint) else {
            throw OAuth2Error.configurationError("Invalid revocation endpoint URL: \(revocationEndpoint)")
        }

        let body = parameters.map { "\($0.key)=\($0.value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? $0.value)" }
            .joined(separator: "&")

        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .POST
        request.headers.add(name: "Content-Type", value: "application/x-www-form-urlencoded")
        request.headers.add(name: "Accept", value: "application/json")
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        guard let bodyData = body.data(using: .utf8) else {
            throw OAuth2Error.configurationError("Failed to encode request parameters")
        }
        request.body = .bytes(bodyData)

        logger.debug("Making token revocation request to: \(revocationEndpoint)")

        do {
            let response = try await httpClient.execute(request, timeout: .seconds(30))

            if response.status == .ok {
                // RFC 7009 allows empty response for successful revocation
                return TokenRevocationResponse.success()
            } else {
                let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
                let responseString = String(buffer: responseBody)

                logger.error("Token revocation failed with status: \(response.status), body: \(responseString)")

                // Try to parse error response
                if let data = responseString.data(using: .utf8),
                    let errorResponse = try? JSONDecoder().decode(TokenRevocationResponse.self, from: data)
                {
                    return errorResponse
                }

                throw OAuth2Error.tokenError("Token revocation failed with status: \(response.status)")
            }

        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("Token revocation request failed with error: \(error)")
            throw OAuth2Error.networkError("Token revocation request failed: \(error)")
        }
    }

    internal func scopesToString(_ scopes: [String]) -> String {
        scopes.joined(separator: " ")
    }
}

/// Extension for base64URL encoding
extension Data {
    /// Encode data as base64URL string (base64 without padding, replacing '+' with '-' and '/' with '_')
    /// - Returns: The base64URL encoded string
    fileprivate func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacing("+", with: "-")
            .replacing("/", with: "_")
            .replacing("=", with: "")
    }
}
