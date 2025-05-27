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

/// Provider for Facebook OAuth authentication
public struct FacebookOAuthProvider: Sendable {
    /// Facebook's OAuth2 endpoints
    public struct Endpoints {
        /// The authorization endpoint URL
        public static let authorization = "https://www.facebook.com/v17.0/dialog/oauth"

        /// The token endpoint URL
        public static let token = "https://graph.facebook.com/v17.0/oauth/access_token"

        /// The user profile endpoint URL (using Graph API)
        public static let me = "https://graph.facebook.com/v17.0/me"

        /// The debug token endpoint URL
        public static let debugToken = "https://graph.facebook.com/v17.0/debug_token"
    }

    /// The OAuthKit instance
    private let oauthKit: OAuthKit

    /// The OAuth2 client configured for Facebook
    private let client: OAuth2Client

    /// Initialize a new Facebook OAuth provider
    /// - Parameter oauthKit: The OAuthKit instance
    public init(oauthKit: OAuthKit, client: OAuth2Client) {
        self.oauthKit = oauthKit
        self.client = client
    }

    /// Generate an authorization URL for Facebook login
    /// - Parameters:
    ///   - state: An opaque value to maintain state between the request and callback
    ///   - usePKCE: Whether to use PKCE (Facebook now supports PKCE)
    ///   - displayMode: The display mode for the Facebook authentication dialog
    ///   - additionalParameters: Additional parameters to include in the authorization URL
    /// - Returns: A tuple containing the authorization URL and code verifier (for PKCE)
    public func signInURL(
        state: String? = nil,
        usePKCE: Bool = true,
        displayMode: FacebookDisplayMode? = nil,
        additionalParameters: [String: String] = [:]
    ) throws -> (url: URL, codeVerifier: String?) {
        var codeVerifier: String? = nil
        var codeChallenge: String? = nil

        // Generate PKCE if requested
        if usePKCE {
            let pkce = OAuth2Client.generatePKCE()
            codeVerifier = pkce.codeVerifier
            codeChallenge = pkce.codeChallenge
        }

        // Prepare additional parameters for Facebook
        var params = additionalParameters

        // Add display mode if provided
        if let displayMode = displayMode {
            params["display"] = displayMode.rawValue
        }

        // Facebook recommends including auth_type=rerequest to handle cases where user previously denied permissions
        params["auth_type"] = "rerequest"

        let url = try client.authorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            additionalParameters: params
        )

        return (url, codeVerifier)
    }

    /// Exchange an authorization code for tokens with Facebook
    /// - Parameters:
    ///   - code: The authorization code received from Facebook
    ///   - codeVerifier: The PKCE code verifier used when generating the authorization URL
    /// - Returns: The token response
    public func exchangeCode(
        code: String,
        codeVerifier: String? = nil
    ) async throws -> TokenResponse {
        try await client.getToken(
            code: code,
            codeVerifier: codeVerifier
        )
    }

    /// Retrieve the user's profile information from Facebook
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    ///   - fields: The fields to request from the Graph API (comma-separated)
    /// - Returns: The user's Facebook profile information
    public func getUserProfile(
        accessToken: String,
        fields: String = "id,name,email,picture,first_name,last_name"
    ) async throws -> FacebookUserProfile {
        // Construct the URL with fields parameter
        let endpoint = "\(Endpoints.me)?fields=\(fields.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? fields)"

        let userInfo = try await fetchFacebookAPI(
            endpoint: endpoint,
            accessToken: accessToken
        )

        return try FacebookUserProfile(userInfo: userInfo)
    }

    /// Debug a Facebook access token to get information about it
    /// - Parameters:
    ///   - accessToken: The access token to debug
    ///   - appID: The application ID
    ///   - appSecret: The application secret
    /// - Returns: Information about the token
    public func debugToken(
        accessToken: String,
        appID: String,
        appSecret: String
    ) async throws -> FacebookTokenInfo {
        // Facebook requires app access token for token debugging
        let appAccessToken = "\(appID)|\(appSecret)"

        let endpoint = "\(Endpoints.debugToken)?input_token=\(accessToken)"

        let debugInfo = try await fetchFacebookAPI(
            endpoint: endpoint,
            accessToken: appAccessToken
        )

        guard let data = debugInfo["data"] as? [String: Any] else {
            throw OAuth2Error.responseError("Invalid token debug response format")
        }

        return FacebookTokenInfo(
            appId: data["app_id"] as? String,
            type: data["type"] as? String,
            application: data["application"] as? String,
            dataAccessExpiresAt: (data["data_access_expires_at"] as? NSNumber)?.intValue,
            expiresAt: (data["expires_at"] as? NSNumber)?.intValue,
            isValid: data["is_valid"] as? Bool ?? false,
            issuedAt: (data["issued_at"] as? NSNumber)?.intValue,
            userId: data["user_id"] as? String,
            scopes: data["scopes"] as? [String]
        )
    }

    /// Make a request to the Facebook Graph API
    /// - Parameters:
    ///   - endpoint: The API endpoint to call
    ///   - accessToken: The access token to use for authentication
    ///   - method: The HTTP method to use (default: GET)
    ///   - parameters: Additional parameters to include in the request
    /// - Returns: The response data as a dictionary
    public func fetchFacebookAPI(
        endpoint: String,
        accessToken: String,
        method: HTTPMethod = .GET,
        parameters: [String: String] = [:]
    ) async throws -> [String: Any] {
        var requestURL = endpoint

        // Add access token if not already in the URL
        if !requestURL.contains("access_token=") {
            let separator = requestURL.contains("?") ? "&" : "?"
            requestURL =
                "\(requestURL)\(separator)access_token=\(accessToken.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? accessToken)"
        }

        var request = HTTPClientRequest(url: requestURL)
        request.method = method
        request.headers.add(name: "User-Agent", value: USER_AGENT)
        request.headers.add(name: "Accept", value: "application/json")

        // Add parameters as query string for GET requests or body for others
        if !parameters.isEmpty {
            if method == .GET {
                // Add parameters to query string
                var urlComponents = URLComponents(string: requestURL)!
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
                oauthKit.logger.error("Facebook API request failed with status: \(response.status)")
                throw OAuth2Error.responseError("Facebook API request failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
            let data = Data(buffer: responseBody)

            guard let jsonObject = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                throw OAuth2Error.responseError("Invalid Facebook API response format")
            }

            // Check for Facebook API errors
            if let error = jsonObject["error"] as? [String: Any] {
                if let message = error["message"] as? String, let code = error["code"] as? Int {
                    throw OAuth2Error.responseError("Facebook API error (\(code)): \(message)")
                } else {
                    throw OAuth2Error.responseError("Facebook API error: \(error)")
                }
            }

            return jsonObject
        } catch let error as OAuth2Error {
            throw error
        } catch {
            oauthKit.logger.error("Facebook API request failed with error: \(error)")
            throw OAuth2Error.networkError("Facebook API request failed: \(error)")
        }
    }
}

/// Facebook user profile information
public struct FacebookUserProfile: Codable {
    /// The user's Facebook ID
    public let id: String

    /// The user's full name
    public let name: String?

    /// The user's first name
    public let firstName: String?

    /// The user's last name
    public let lastName: String?

    /// The user's email address
    public let email: String?

    /// The user's profile picture URL
    public let pictureURL: String?

    /// Whether the user's email is verified (Facebook doesn't provide this directly)
    public let isVerified: Bool?

    /// Additional fields returned from the Graph API
    public let additionalFields: [String: Any]?

    /// Coding keys for mapping JSON fields to properties
    enum CodingKeys: String, CodingKey {
        case id, name, email
        case firstName = "first_name"
        case lastName = "last_name"
        case picture, isVerified
    }

    /// Initialize from user info dictionary
    public init(userInfo: [String: Any]) throws {
        guard let id = userInfo["id"] as? String else {
            throw OAuth2Error.responseError("Missing 'id' in Facebook user info")
        }

        self.id = id
        self.name = userInfo["name"] as? String
        self.firstName = userInfo["first_name"] as? String
        self.lastName = userInfo["last_name"] as? String
        self.email = userInfo["email"] as? String
        self.isVerified = userInfo["is_verified"] as? Bool

        // Extract picture URL from nested structure if available
        if let pictureData = userInfo["picture"] as? [String: Any],
            let pictureDataObj = pictureData["data"] as? [String: Any],
            let url = pictureDataObj["url"] as? String
        {
            self.pictureURL = url
        } else {
            self.pictureURL = nil
        }

        // Save all fields for potential later use
        var allFields = userInfo
        allFields.removeValue(forKey: "id")
        allFields.removeValue(forKey: "name")
        allFields.removeValue(forKey: "first_name")
        allFields.removeValue(forKey: "last_name")
        allFields.removeValue(forKey: "email")
        allFields.removeValue(forKey: "is_verified")

        self.additionalFields = allFields.isEmpty ? nil : allFields
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(String.self, forKey: .id)
        name = try container.decodeIfPresent(String.self, forKey: .name)
        firstName = try container.decodeIfPresent(String.self, forKey: .firstName)
        lastName = try container.decodeIfPresent(String.self, forKey: .lastName)
        email = try container.decodeIfPresent(String.self, forKey: .email)
        isVerified = try container.decodeIfPresent(Bool.self, forKey: .isVerified)

        // Picture handling requires custom decoding logic
        if let pictureContainer = try? container.nestedContainer(keyedBy: PictureCodingKeys.self, forKey: .picture),
            let dataContainer = try? pictureContainer.nestedContainer(keyedBy: PictureDataCodingKeys.self, forKey: .data)
        {
            pictureURL = try dataContainer.decodeIfPresent(String.self, forKey: .url)
        } else {
            pictureURL = nil
        }

        additionalFields = nil  // Not decoded from JSON
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encodeIfPresent(name, forKey: .name)
        try container.encodeIfPresent(firstName, forKey: .firstName)
        try container.encodeIfPresent(lastName, forKey: .lastName)
        try container.encodeIfPresent(email, forKey: .email)
        try container.encodeIfPresent(isVerified, forKey: .isVerified)

        // Handle picture encoding
        if let pictureURL = pictureURL {
            var pictureContainer = container.nestedContainer(keyedBy: PictureCodingKeys.self, forKey: .picture)
            var dataContainer = pictureContainer.nestedContainer(keyedBy: PictureDataCodingKeys.self, forKey: .data)
            try dataContainer.encode(pictureURL, forKey: .url)
        }

        // additionalFields not encoded to JSON
    }

    enum PictureCodingKeys: String, CodingKey {
        case data
    }

    enum PictureDataCodingKeys: String, CodingKey {
        case url
    }
}

/// Information about a Facebook token from the debug_token endpoint
public struct FacebookTokenInfo: Codable {
    /// The app ID the token was issued for
    public let appId: String?

    /// The type of token (USER, PAGE, APP, etc.)
    public let type: String?

    /// The application name
    public let application: String?

    /// When data access for this token expires (Unix timestamp)
    public let dataAccessExpiresAt: Int?

    /// When the token expires (Unix timestamp)
    public let expiresAt: Int?

    /// Whether the token is valid
    public let isValid: Bool

    /// When the token was issued (Unix timestamp)
    public let issuedAt: Int?

    /// The user ID the token was issued for (for user tokens)
    public let userId: String?

    /// The permissions/scopes granted with this token
    public let scopes: [String]?

    /// Coding keys for mapping JSON fields to properties
    enum CodingKeys: String, CodingKey {
        case appId = "app_id"
        case type
        case application
        case dataAccessExpiresAt = "data_access_expires_at"
        case expiresAt = "expires_at"
        case isValid = "is_valid"
        case issuedAt = "issued_at"
        case userId = "user_id"
        case scopes
    }
}

/// Facebook display modes for the login dialog
public enum FacebookDisplayMode: String {
    /// Full page display (default)
    case page

    /// Popup dialog display
    case popup

    /// Mobile-optimized dialog
    case touch

    /// Legacy dialog mode
    case wap
}
