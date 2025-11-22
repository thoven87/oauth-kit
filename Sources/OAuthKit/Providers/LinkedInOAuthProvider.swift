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

/// Provider for LinkedIn OAuth2 authentication
public struct LinkedInOAuthProvider: Sendable {
    /// LinkedIn OAuth2 authorization endpoint
    public static let authorizationEndpoint = "https://www.linkedin.com/oauth/v2/authorization"

    /// LinkedIn OAuth2 token endpoint
    public static let tokenEndpoint = "https://www.linkedin.com/oauth/v2/accessToken"

    /// LinkedIn API base URL (v2)
    public static let apiBaseURL = "https://api.linkedin.com/v2"

    /// The OAuthKit instance
    private let oauthKit: OAuthClientFactory

    /// The OAuth2 client configured for LinkedIn
    private let client: OAuth2Client

    /// Initialize a new LinkedIn OAuth provider
    /// - Parameters:
    ///   - oauthKit: The OAuthKit instance
    ///   - oauth2Client: The OAuth2 client configured for LinkedIn
    internal init(oauthKit: OAuthClientFactory, oauth2Client client: OAuth2Client) {
        self.oauthKit = oauthKit
        self.client = client
    }

    /// Generate an authorization URL for LinkedIn Sign-In with recommended parameters
    /// - Parameters:
    ///   - state: An opaque value to maintain state between the request and callback
    ///   - usePKCE: Whether to use PKCE (recommended and enabled by default)
    ///   - additionalParameters: Additional parameters to include in the authorization URL
    ///   - scopes: The requested scopes
    /// - Returns: A tuple containing the authorization URL and code verifier (for PKCE)
    public func generateAuthorizationURL(
        state: String? = nil,
        usePKCE: Bool = true,
        additionalParameters: [String: String] = [:],
        scopes: [String] = ["openid", "profile", "email"]
    ) throws -> (url: URL, codeVerifier: String?) {
        let additionalParams = additionalParameters
        var codeVerifier: String? = nil
        var codeChallenge: String? = nil

        // Generate PKCE if requested
        if usePKCE {
            let pkce = OAuth2Client.generatePKCE()
            codeVerifier = pkce.codeVerifier
            codeChallenge = pkce.codeChallenge
        }

        let url = try client.generateAuthorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            additionalParameters: additionalParams,
            scopes: scopes
        )

        return (url, codeVerifier)
    }

    /// Exchange an authorization code for tokens with LinkedIn
    /// - Parameters:
    ///   - code: The authorization code received from LinkedIn
    ///   - codeVerifier: The PKCE code verifier used when generating the authorization URL
    /// - Returns: The token response
    public func exchangeCode(
        code: String,
        codeVerifier: String?
    ) async throws -> TokenResponse {
        try await client.getToken(
            code: code,
            codeVerifier: codeVerifier,
            additionalParameters: [:]
        )
    }

    /// Refresh an access token using a refresh token
    /// - Parameters:
    ///   - refreshToken: The refresh token
    ///   - additionalParameters: Additional parameters to include in the token request
    /// - Returns: The token response
    /// - Throws: OAuth2Error if the token refresh fails
    public func refreshAccessToken(
        refreshToken: String,
        additionalParameters: [String: String] = [:]
    ) async throws -> (tokenResponse: TokenResponse, claims: IDTokenClaims?) {
        let tokenResponse = try await client.refreshToken(
            refreshToken,
            additionalParameters: additionalParameters
        )
        return (tokenResponse, nil)  // OAuth2 providers don't return ID token claims
    }

    /// Retrieve the user's LinkedIn profile information using the Person API
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    /// - Returns: The user's LinkedIn profile information
    public func getUserProfile(
        accessToken: String
    ) async throws -> LinkedInUser {
        try await callLinkedInAPI(
            accessToken: accessToken,
            endpoint: "/people/~:(id,firstName,lastName,profilePicture(displayImage~:playableStreams))",
            httpMethod: .GET
        )
    }

    /// Get the user's email address using the Email API
    /// - Parameters:
    ///   - accessToken: The access token from the token response (requires 'r_emailaddress' scope)
    /// - Returns: The user's email information
    public func getUserEmail(
        accessToken: String
    ) async throws -> LinkedInEmail {
        try await callLinkedInAPI(
            accessToken: accessToken,
            endpoint: "/emailAddress?q=members&projection=(elements*(handle~))",
            httpMethod: .GET
        )
    }

    /// Get the user's complete profile including email
    /// - Parameters:
    ///   - accessToken: The access token from the token response (requires appropriate scopes)
    /// - Returns: Complete user profile with email
    public func getCompleteUserProfile(
        accessToken: String
    ) async throws -> LinkedInCompleteProfile {
        async let profile = getUserProfile(accessToken: accessToken)
        async let email = getUserEmail(accessToken: accessToken)

        let userProfile = try await profile
        let userEmail = try await email

        return LinkedInCompleteProfile(
            user: userProfile,
            email: userEmail.elements.first?.handle?.emailAddress
        )
    }

    /// Call the LinkedIn API
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    ///   - endpoint: The LinkedIn API endpoint to call (e.g., "/people/~")
    ///   - httpMethod: The HTTP method to use (default: GET)
    ///   - body: Optional request body for POST/PATCH requests
    ///   - httpClient: The HTTP client to use for the request
    ///   - logger: Logger for the LinkedIn API operation
    /// - Returns: The decoded response
    public func callLinkedInAPI<T: Codable>(
        accessToken: String,
        endpoint: String,
        httpMethod: NIOHTTP1.HTTPMethod = .GET,
        body: ByteBuffer? = nil,
        httpClient: HTTPClient = HTTPClient.shared,
        logger: Logger = Logger(label: "com.oauthkit.LinkedInOAuthProvider.callLinkedInAPI")
    ) async throws -> T {
        let apiEndpoint =
            endpoint.hasPrefix("/")
            ? "\(Self.apiBaseURL)\(endpoint)"
            : "\(Self.apiBaseURL)/\(endpoint)"

        var request = HTTPClientRequest(url: apiEndpoint)
        request.method = httpMethod
        request.headers.add(name: "Authorization", value: "Bearer \(accessToken)")
        request.headers.add(name: "Accept", value: "application/json")
        request.headers.add(name: "User-Agent", value: USER_AGENT)
        request.headers.add(name: "X-Restli-Protocol-Version", value: "2.0.0")

        if let body = body {
            request.body = .bytes(body)
            request.headers.add(name: "Content-Type", value: "application/json")
        }

        do {
            let response = try await httpClient.execute(request, timeout: .seconds(60))

            guard response.status.code >= 200 && response.status.code < 300 else {
                logger.error("LinkedIn API request failed with status: \(response.status)")
                throw OAuth2Error.responseError("LinkedIn API request failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
            let decoder = JSONDecoder()

            return try decoder.decode(T.self, from: responseBody)
        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("LinkedIn API request failed with error: \(error)")
            throw OAuth2Error.networkError("LinkedIn API request failed: \(error)")
        }
    }
}

/// LinkedIn user profile information
public struct LinkedInUser: Codable {
    /// The user's unique LinkedIn ID
    public let id: String

    /// The user's first name information
    public let firstName: LinkedInLocalizedName?

    /// The user's last name information
    public let lastName: LinkedInLocalizedName?

    /// The user's profile picture information
    public let profilePicture: LinkedInProfilePicture?
}

/// LinkedIn localized name structure
public struct LinkedInLocalizedName: Codable {
    /// Localized versions of the name
    public let localized: [String: String]

    /// Preferred locale information
    public let preferredLocale: LinkedInLocale
}

/// LinkedIn locale information
public struct LinkedInLocale: Codable {
    /// Country code
    public let country: String

    /// Language code
    public let language: String
}

/// LinkedIn profile picture information
public struct LinkedInProfilePicture: Codable {
    /// Display image information with various sizes
    public let displayImage: LinkedInDisplayImage?

    enum CodingKeys: String, CodingKey {
        case displayImage = "displayImage~"
    }
}

/// LinkedIn display image information
public struct LinkedInDisplayImage: Codable {
    /// Available image streams/sizes
    public let elements: [LinkedInImageElement]
}

/// LinkedIn image element with different sizes
public struct LinkedInImageElement: Codable {
    /// Identifiers for the image
    public let identifiers: [LinkedInImageIdentifier]

    /// Data about the image
    public let data: LinkedInImageData
}

/// LinkedIn image identifier
public struct LinkedInImageIdentifier: Codable {
    /// The image identifier/URL
    public let identifier: String

    /// The file type
    public let file: String?

    /// Media type
    public let mediaType: String?

    /// Index or position
    public let index: Int?

    /// Recipe/size information
    public let recipe: String?
}

/// LinkedIn image data
public struct LinkedInImageData: Codable {
    /// Media type
    public let mediaType: String?

    /// Recipe/size information
    public let recipe: String?

    /// Image dimensions
    public let displaySize: LinkedInDisplaySize?
}

/// LinkedIn image display size
public struct LinkedInDisplaySize: Codable {
    /// Width of the image
    public let width: Int?

    /// Height of the image
    public let height: Int?

    /// Unit of measurement
    public let uom: String?
}

/// LinkedIn email response structure
public struct LinkedInEmail: Codable {
    /// Array of email elements
    public let elements: [LinkedInEmailElement]
}

/// LinkedIn email element
public struct LinkedInEmailElement: Codable {
    /// Email handle information
    public let handle: LinkedInEmailHandle?

    enum CodingKeys: String, CodingKey {
        case handle = "handle~"
    }
}

/// LinkedIn email handle
public struct LinkedInEmailHandle: Codable {
    /// The email address
    public let emailAddress: String
}

/// Complete LinkedIn profile including email
public struct LinkedInCompleteProfile: Codable {
    /// User profile information
    public let user: LinkedInUser

    /// User's email address
    public let email: String?

    /// Computed properties for easier access
    public var firstName: String? {
        guard let firstName = user.firstName?.localized.values.first else { return nil }
        return firstName
    }

    public var lastName: String? {
        guard let lastName = user.lastName?.localized.values.first else { return nil }
        return lastName
    }

    public var fullName: String? {
        let first = firstName ?? ""
        let last = lastName ?? ""
        let full = "\(first) \(last)".trimmingCharacters(in: .whitespaces)
        return full.isEmpty ? nil : full
    }

    public var profilePictureURL: String? {
        user.profilePicture?.displayImage?.elements.first?.identifiers.first?.identifier
    }
}
