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

/// Provider for Slack OAuth authentication
public struct SlackOAuthProvider {
    /// Slack's OAuth2 endpoints
    public struct Endpoints {
        /// The authorization endpoint URL
        public static let authorization = "https://slack.com/oauth/v2/authorize"

        /// The token endpoint URL
        public static let token = "https://slack.com/api/oauth.v2.access"

        /// The user identity endpoint URL
        public static let identity = "https://slack.com/api/users.identity"
    }

    /// The OAuthKit instance
    private let oauthKit: OAuthKit

    /// SlackOAuthClient
    private let client: SlackOAuth2Client

    /// Initialize a new Slack OAuth provider
    /// - Parameter oauthKit: The OAuthKit instance
    /// - Parameter client: A SlackOAuth2Client instance
    internal init(oauthKit: OAuthKit, client: SlackOAuth2Client) {
        self.oauthKit = oauthKit
        self.client = client
    }

    /// Generate an authorization URL for Slack login
    /// - Parameters:
    ///   - state: An opaque value to maintain state between the request and callback
    ///   - usePKCE: Whether to use PKCE (supported by Slack)
    ///   - userScope: Additional user scopes for Slack user tokens
    /// - Returns: A tuple containing the authorization URL and code verifier (for PKCE)
    public func signInURL(
        state: String? = nil,
        usePKCE: Bool = true,
        userScope: [String]? = nil
    ) throws -> (url: URL, codeVerifier: String?) {
        var codeVerifier: String? = nil
        var codeChallenge: String? = nil

        // Generate PKCE if requested
        if usePKCE {
            let pkce = OAuth2Client.generatePKCE()
            codeVerifier = pkce.codeVerifier
            codeChallenge = pkce.codeChallenge
        }

        // Prepare additional parameters for Slack
        var additionalParams: [String: String] = [:]

        // Add user_scope if provided (for Slack user tokens)
        if let userScope = userScope, !userScope.isEmpty {
            additionalParams["user_scope"] = userScope.joined(separator: ",")
        }

        let url = try client.authorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            additionalParameters: additionalParams
        )

        return (url, codeVerifier)
    }

    /// Exchange an authorization code for tokens with Slack
    /// - Parameters:
    ///   - code: The authorization code received from Slack
    ///   - codeVerifier: The PKCE code verifier used when generating the authorization URL
    /// - Returns: The Slack token response with additional Slack-specific data
    public func exchangeCode(
        code: String,
        codeVerifier: String? = nil
    ) async throws -> TokenResponse {  // we should be returning SlackTokenResponse
        let tokenResponse = try await client.exchangeCode(
            code: code,
            codeVerifier: codeVerifier
        )

        return tokenResponse
    }

    /// Retrieve the user's profile information from Slack
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    /// - Returns: The user's Slack profile information
    public func getUserProfile(
        accessToken: String
    ) async throws -> SlackUserProfile {
        let userInfo = try await fetchSlackAPI(
            endpoint: Endpoints.identity,
            accessToken: accessToken
        )

        return try SlackUserProfile(userInfo: userInfo)
    }

    /// Make a request to the Slack API
    /// - Parameters:
    ///   - endpoint: The API endpoint to call
    ///   - accessToken: The access token to use for authentication
    ///   - method: The HTTP method to use (default: GET)
    ///   - parameters: Additional parameters to include in the request
    /// - Returns: The response data as a dictionary
    public func fetchSlackAPI(
        endpoint: String,
        accessToken: String,
        method: HTTPMethod = .GET,
        parameters: [String: String] = [:]
    ) async throws -> [String: Any] {
        var request = HTTPClientRequest(url: endpoint)
        request.method = method
        request.headers.add(name: "Authorization", value: "Bearer \(accessToken)")
        request.headers.add(name: "User-Agent", value: USER_AGENT)
        request.headers.add(name: "Accept", value: "application/json")

        // Add parameters as query string for GET requests or body for others
        if !parameters.isEmpty {
            if method == .GET {
                // Add parameters to query string
                var urlComponents = URLComponents(string: endpoint)!
                let queryItems = parameters.map { URLQueryItem(name: $0.key, value: $0.value) }
                urlComponents.queryItems = (urlComponents.queryItems ?? []) + queryItems
                request.url = urlComponents.url!.absoluteString
            } else {
                // Add parameters to body
                let formBody =
                    parameters
                    .map { key, value in
                        "\(key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? key)=\(value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value)"
                    }
                    .joined(separator: "&")
                request.headers.add(name: "Content-Type", value: "application/x-www-form-urlencoded")
                request.body = .bytes(ByteBuffer(string: formBody))
            }
        }

        do {
            let response = try await oauthKit.httpClient.execute(request, timeout: .seconds(60))

            guard response.status == .ok else {
                oauthKit.logger.error("Slack API request failed with status: \(response.status)")
                throw OAuth2Error.responseError("Slack API request failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit

            guard let jsonObject = try JSONSerialization.jsonObject(with: responseBody) as? [String: Any] else {
                throw OAuth2Error.responseError("Invalid Slack API response format")
            }

            // Check for Slack API errors
            if let ok = jsonObject["ok"] as? Bool, !ok, let error = jsonObject["error"] as? String {
                throw OAuth2Error.responseError("Slack API error: \(error)")
            }

            return jsonObject
        } catch let error as OAuth2Error {
            throw error
        } catch {
            oauthKit.logger.error("Slack API request failed with error: \(error)")
            throw OAuth2Error.networkError("Slack API request failed: \(error)")
        }
    }
}

/// Slack-specific OAuth2 client that handles Slack's comma-separated scopes
public class SlackOAuth2Client: OAuth2Client {
    /// The scopes requested for Slack (array of strings)
    private let slackScopes: [String]

    /// Initialize a new Slack OAuth2 client
    public init(
        httpClient: HTTPClient,
        clientID: String,
        clientSecret: String,
        tokenEndpoint: String,
        authorizationEndpoint: String? = nil,
        redirectURI: String? = nil,
        scopes: [String] = [],
        logger: Logger = Logger(label: "com.oauthkit.SlackOAuth2Client")
    ) {
        self.slackScopes = scopes

        // Convert array of scopes to comma-separated string for Slack
        let scopeString = scopes.joined(separator: ",")

        super.init(
            httpClient: httpClient,
            clientID: clientID,
            clientSecret: clientSecret,
            tokenEndpoint: tokenEndpoint,
            authorizationEndpoint: authorizationEndpoint,
            redirectURI: redirectURI,
            scope: scopeString,
            logger: logger
        )
    }

    /// Exchange an authorization code for tokens with GitHub
    /// - Parameters:
    ///   - code: The authorization code received from Slack
    ///   - codeVerifier: The PKCE code verifier used when generating the authorization URL
    /// - Returns: The token response
    public func exchangeCode(
        code: String,
        codeVerifier: String? = nil
    ) async throws -> TokenResponse {
        // TODO: make getToken return a generic type
        // So that a SlackTokenResponse is returned here instead
        try await getToken(
            code: code,
            codeVerifier: codeVerifier
        )
    }

    /// Process the Slack token response to extract additional Slack-specific data
    func processTokenResponse(_ data: Data) throws -> SlackTokenResponse {
        // Parse the raw response first
        guard let jsonObject = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            throw OAuth2Error.responseError("Invalid token response format")
        }

        // Check for Slack API errors
        if let ok = jsonObject["ok"] as? Bool, !ok, let error = jsonObject["error"] as? String {
            throw OAuth2Error.tokenExchangeError("Slack API error: \(error)")
        }

        // Extract standard OAuth fields for TokenResponse
        var accessToken = ""
        var tokenType = "Bearer"
        var expiresIn: Int? = nil
        var refreshToken: String? = nil
        var scope: String? = nil
        var idToken: String? = nil

        // Extract additional Slack-specific fields
        var team: SlackTeam? = nil
        var authedUser: SlackAuthedUser? = nil
        var enterprise: SlackEnterprise? = nil
        var incomingWebhook: SlackWebhook? = nil

        // Extract standard OAuth fields
        if let token = jsonObject["access_token"] as? String {
            accessToken = token
        }

        if let type = jsonObject["token_type"] as? String {
            tokenType = type
        }

        if let expires = jsonObject["expires_in"] as? Int {
            expiresIn = expires
        }

        if let refresh = jsonObject["refresh_token"] as? String {
            refreshToken = refresh
        }

        if let scopeValue = jsonObject["scope"] as? String {
            scope = scopeValue
        }

        if let idTokenValue = jsonObject["id_token"] as? String {
            idToken = idTokenValue
        }

        // Extract Slack-specific fields
        if let teamData = jsonObject["team"] as? [String: Any] {
            team = SlackTeam(
                id: teamData["id"] as? String,
                name: teamData["name"] as? String
            )
        }

        if let userData = jsonObject["authed_user"] as? [String: Any] {
            authedUser = SlackAuthedUser(
                id: userData["id"] as? String,
                scope: userData["scope"] as? String,
                accessToken: userData["access_token"] as? String,
                tokenType: userData["token_type"] as? String
            )
        }

        if let enterpriseData = jsonObject["enterprise"] as? [String: Any] {
            enterprise = SlackEnterprise(
                id: enterpriseData["id"] as? String,
                name: enterpriseData["name"] as? String
            )
        }

        if let webhookData = jsonObject["incoming_webhook"] as? [String: Any] {
            incomingWebhook = SlackWebhook(
                url: webhookData["url"] as? String,
                channel: webhookData["channel"] as? String,
                channelId: webhookData["channel_id"] as? String,
                configurationUrl: webhookData["configuration_url"] as? String
            )
        }

        // Create a Slack-specific token response
        return SlackTokenResponse(
            accessToken: accessToken,
            tokenType: tokenType,
            expiresIn: expiresIn,
            refreshToken: refreshToken,
            scope: scope,
            idToken: idToken,
            team: team,
            authedUser: authedUser,
            enterprise: enterprise,
            incomingWebhook: incomingWebhook,
            createdAt: .init()
        )
    }
}

/// Slack token response with additional Slack-specific data
public struct SlackTokenResponse {
    /// The access token string
    public let accessToken: String

    /// The token type, typically "Bearer"
    public let tokenType: String

    /// The expiration time in seconds from when the token was issued
    public let expiresIn: Int?

    /// The refresh token, if provided
    public let refreshToken: String?

    /// The scope of the token, if returned
    public let scope: String?

    /// The ID token for OpenID Connect
    public let idToken: String?

    /// Creation timestamp, used for calculating expiration
    public let createdAt: Date

    /// Information about the Slack team/workspace
    public let team: SlackTeam?

    /// Information about the authenticated user
    public let authedUser: SlackAuthedUser?

    /// Information about the enterprise (for Enterprise Grid)
    public let enterprise: SlackEnterprise?

    /// Information about incoming webhooks (if requested)
    public let incomingWebhook: SlackWebhook?

    /// Initialize a new Slack token response
    internal init(
        accessToken: String,
        tokenType: String,
        expiresIn: Int?,
        refreshToken: String?,
        scope: String?,
        idToken: String?,
        team: SlackTeam?,
        authedUser: SlackAuthedUser?,
        enterprise: SlackEnterprise?,
        incomingWebhook: SlackWebhook?,
        createdAt: Date
    ) {
        self.accessToken = accessToken
        self.team = team
        self.authedUser = authedUser
        self.enterprise = enterprise
        self.incomingWebhook = incomingWebhook
        self.tokenType = tokenType
        self.refreshToken = refreshToken
        self.scope = scope
        self.expiresIn = expiresIn
        self.idToken = idToken
        self.createdAt = createdAt
    }

    /// Get the user OAuth token (if available)
    public var userToken: String? {
        authedUser?.accessToken
    }

    enum CodingKeys: String, CodingKey {
        case team
        case authedUser = "authed_user"
        case enterprise
        case incomingWebhook = "incoming_webhook"
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case refreshToken = "refresh_token"
        case scope
        case idToken = "id_token"
        case createdAt = "created_at"
    }
}

/// Information about a Slack team/workspace
public struct SlackTeam: Codable {
    /// The team ID
    public let id: String?

    /// The team name
    public let name: String?
}

/// Information about an authenticated Slack user
public struct SlackAuthedUser: Codable {
    /// The user ID
    public let id: String?

    /// The user's scopes
    public let scope: String?

    /// The user's access token
    public let accessToken: String?

    /// The token type
    public let tokenType: String?

    /// Coding keys for mapping JSON fields to properties
    enum CodingKeys: String, CodingKey {
        case id, scope
        case accessToken = "access_token"
        case tokenType = "token_type"
    }
}

/// Information about a Slack Enterprise Grid organization
public struct SlackEnterprise: Codable {
    /// The enterprise ID
    public let id: String?

    /// The enterprise name
    public let name: String?
}

/// Information about a Slack incoming webhook
public struct SlackWebhook: Codable {
    /// The webhook URL
    public let url: String?

    /// The channel name
    public let channel: String?

    /// The channel ID
    public let channelId: String?

    /// The configuration URL
    public let configurationUrl: String?

    /// Coding keys for mapping JSON fields to properties
    enum CodingKeys: String, CodingKey {
        case url, channel
        case channelId = "channel_id"
        case configurationUrl = "configuration_url"
    }
}

/// Slack user profile information
public struct SlackUserProfile: Codable {
    /// The user's Slack ID
    public let id: String

    /// The user's name
    public let name: String?

    /// The user's email address
    public let email: String?

    /// The user's avatar/image URL
    public let image: String?

    /// The user's team ID
    public let teamId: String?

    enum CodingKeys: String, CodingKey {
        case id
        case name
        case email
        case image
        case teamId = "team_id"
    }

    /// Initialize from user info dictionary
    public init(userInfo: [String: Any]) throws {
        guard let user = userInfo["user"] as? [String: Any] else {
            throw OAuth2Error.responseError("Missing 'user' in Slack identity response")
        }

        guard let userId = user["id"] as? String else {
            throw OAuth2Error.responseError("Missing 'id' in Slack user info")
        }

        self.id = userId
        self.name = user["name"] as? String
        self.email = user["email"] as? String

        // Extract image from nested structure
        if let imageData = user["image_512"] as? String {
            self.image = imageData
        } else if let imageData = user["image_192"] as? String {
            self.image = imageData
        } else if let imageData = user["image_72"] as? String {
            self.image = imageData
        } else if let imageData = user["image_48"] as? String {
            self.image = imageData
        } else if let imageData = user["image_32"] as? String {
            self.image = imageData
        } else if let imageData = user["image_24"] as? String {
            self.image = imageData
        } else {
            self.image = nil
        }

        self.teamId = user["team"] as? String
    }
}
