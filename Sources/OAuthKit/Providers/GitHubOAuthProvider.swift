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
import NIOFoundationCompat

/// Provider for GitHub OAuth authentication
public struct GitHubOAuthProvider: Sendable {
    /// GitHub's OAuth2 endpoints
    public struct Endpoints {
        /// The authorization endpoint URL
        public static let authorization = "https://github.com/login/oauth/authorize"

        /// The token endpoint URL
        public static let token = "https://github.com/login/oauth/access_token"

        /// The user API endpoint
        public static let user = "https://api.github.com/user"

        /// The user emails API endpoint
        public static let userEmails = "https://api.github.com/user/emails"
    }

    /// The OAuthKit instance
    private let oauthKit: OAuthClientFactory

    /// An OAuth2 client configured for GitHub
    private let client: OAuth2Client

    /// Initialize a new GitHub OAuth provider
    /// - Parameter oauthKit: The OAuthKit instance
    /// - Parameter oauth2Client:  An OAuth2 client configured for GitHub
    public init(
        oauthKit: OAuthClientFactory,
        oauth2Client client: OAuth2Client
    ) {
        self.oauthKit = oauthKit
        self.client = client
    }

    /// Generate an authorization URL for GitHub login
    /// - Parameters:
    ///   - client: The OAuth2 client configured for GitHub
    ///   - state: An opaque value to maintain state between the request and callback
    ///   - usePKCE: Whether to use PKCE (GitHub now supports PKCE as of 2023)
    ///   - additionalParameters: Additional parameters to include in the authorization URL
    /// - Returns: A tuple containing the authorization URL and code verifier (for PKCE)
    public func signInURL(
        state: String? = nil,
        usePKCE: Bool = true,
        additionalParameters: [String: String] = [:],
        scopes: [String] = ["read:user", "user:email"]
    ) throws -> (url: URL, codeVerifier: String?) {
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
            additionalParameters: additionalParameters,
            scopes: scopes
        )

        return (url, codeVerifier)
    }

    /// Exchange an authorization code for tokens with GitHub
    /// - Parameters:
    ///   - code: The authorization code received from GitHub
    ///   - codeVerifier: The PKCE code verifier used when generating the authorization URL
    /// - Returns: The token response
    public func exchangeCode(
        code: String,
        codeVerifier: String? = nil,
        additionalParameters: [String: String] = [:]
    ) async throws -> TokenResponse {
        try await client.getToken(
            code: code,
            codeVerifier: codeVerifier,
            additionalParameters: additionalParameters
        )
    }

    /// Retrieve the user's profile information from GitHub
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    ///   - includeEmails: Whether to include the user's email addresses
    /// - Returns: The user's GitHub profile information
    public func getUserProfile(
        accessToken: String,
        includeEmails: Bool = true
    ) async throws -> GitHubUserProfile {
        // Fetch user profile
        var profile: GitHubUserProfile = try await fetchGitHubAPI(
            endpoint: Endpoints.user,
            accessToken: accessToken
        )

        // GitHub doesn't return email in the user profile if it's private
        // We need to make a separate request to get emails if email is private and includeEmails is true
        if includeEmails && (profile.email == nil || profile.email?.isEmpty == true) {

            let emailsInfo: [GitHubUserProfile.EmailInfo]? = try await fetchGitHubAPI(
                endpoint: Endpoints.userEmails,
                accessToken: accessToken
            )

            // Find the primary email
            if let emailsInfo = emailsInfo {
                for emailInfo in emailsInfo {
                    if let isPrimary = emailInfo.primary, isPrimary,
                        let email = emailInfo.email
                    {
                        profile.email = email
                        if let verified = emailInfo.verified {
                            profile.emailVerified = verified
                        }
                        break
                    }
                }
            }
        }

        return profile
    }

    /// Make a request to the GitHub API
    /// - Parameters:
    ///   - endpoint: The API endpoint to call
    ///   - accessToken: The access token to use for authentication
    /// - Returns: The response data as a dictionary or array
    private func fetchGitHubAPI<T: Decodable>(
        endpoint: String,
        accessToken: String
    ) async throws -> T {
        var request = HTTPClientRequest(url: endpoint)
        request.method = .GET
        request.headers.add(name: "Authorization", value: "token \(accessToken)")
        request.headers.add(name: "Accept", value: "application/json")
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        do {
            let response = try await oauthKit.httpClient.execute(request, timeout: .seconds(60))

            let expectedBytes = response.headers.first(name: "content-length").flatMap(Int.init) ?? 05 * 1024 * 1024

            guard response.status == .ok else {
                oauthKit.logger.error("GitHub API request failed with status: \(response.status)")
                throw OAuth2Error.responseError("GitHub API request failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: expectedBytes)
            return try JSONDecoder().decode(T.self, from: responseBody)
        } catch let error as OAuth2Error {
            throw error
        } catch {
            oauthKit.logger.error("GitHub API request failed with error: \(error)")
            throw OAuth2Error.networkError("GitHub API request failed: \(error)")
        }
    }
}

/// GitHub user profile information
public struct GitHubUserProfile: Codable {
    /// The user's GitHub ID
    public let id: Int

    /// The user's GitHub login/username
    public let login: String

    /// The user's full name
    public let name: String?

    /// The user's email address
    public var email: String?

    /// Whether the user's email is verified
    public var emailVerified: Bool?

    /// The user's avatar URL
    public let avatarURL: String?

    /// The user's bio/description
    public let bio: String?

    /// The user's location
    public let location: String?

    /// The user's blog/website URL
    public let blog: String?

    /// The user's company
    public let company: String?

    /// The user's Twitter username
    public let twitterUsername: String?

    /// Whether the user is a GitHub staff member
    public let isHireable: Bool?

    /// The total number of public repositories the user owns
    public let publicRepos: Int?

    /// The total number of public gists the user owns
    public let publicGists: Int?

    /// The number of followers the user has
    public let followers: Int?

    /// The number of users the user is following
    public let following: Int?

    /// The date the user account was created
    public let createdAt: String?

    /// The date the user account was last updated
    public let updatedAt: String?

    /// Coding keys for mapping JSON fields to properties
    enum CodingKeys: String, CodingKey {
        case id, login, name, email, bio, location, blog, company
        case avatarURL = "avatar_url"
        case twitterUsername = "twitter_username"
        case isHireable = "hireable"
        case publicRepos = "public_repos"
        case publicGists = "public_gists"
        case followers, following
        case createdAt = "created_at"
        case updatedAt = "updated_at"
        // emailVerified is not in GitHub's API response, it's added separately
    }

    struct EmailInfo: Codable {
        var email: String?
        var primary: Bool?
        var verified: Bool?
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(Int.self, forKey: .id)
        login = try container.decode(String.self, forKey: .login)
        name = try container.decodeIfPresent(String.self, forKey: .name)
        email = try container.decodeIfPresent(String.self, forKey: .email)
        avatarURL = try container.decodeIfPresent(String.self, forKey: .avatarURL)
        bio = try container.decodeIfPresent(String.self, forKey: .bio)
        location = try container.decodeIfPresent(String.self, forKey: .location)
        blog = try container.decodeIfPresent(String.self, forKey: .blog)
        company = try container.decodeIfPresent(String.self, forKey: .company)
        twitterUsername = try container.decodeIfPresent(String.self, forKey: .twitterUsername)
        isHireable = try container.decodeIfPresent(Bool.self, forKey: .isHireable)
        publicRepos = try container.decodeIfPresent(Int.self, forKey: .publicRepos)
        publicGists = try container.decodeIfPresent(Int.self, forKey: .publicGists)
        followers = try container.decodeIfPresent(Int.self, forKey: .followers)
        following = try container.decodeIfPresent(Int.self, forKey: .following)
        createdAt = try container.decodeIfPresent(String.self, forKey: .createdAt)
        updatedAt = try container.decodeIfPresent(String.self, forKey: .updatedAt)
        emailVerified = nil  // Will be set later if we fetch emails
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(login, forKey: .login)
        try container.encodeIfPresent(name, forKey: .name)
        try container.encodeIfPresent(email, forKey: .email)
        try container.encodeIfPresent(avatarURL, forKey: .avatarURL)
        try container.encodeIfPresent(bio, forKey: .bio)
        try container.encodeIfPresent(location, forKey: .location)
        try container.encodeIfPresent(blog, forKey: .blog)
        try container.encodeIfPresent(company, forKey: .company)
        try container.encodeIfPresent(twitterUsername, forKey: .twitterUsername)
        try container.encodeIfPresent(isHireable, forKey: .isHireable)
        try container.encodeIfPresent(publicRepos, forKey: .publicRepos)
        try container.encodeIfPresent(publicGists, forKey: .publicGists)
        try container.encodeIfPresent(followers, forKey: .followers)
        try container.encodeIfPresent(following, forKey: .following)
        try container.encodeIfPresent(createdAt, forKey: .createdAt)
        try container.encodeIfPresent(updatedAt, forKey: .updatedAt)
    }
}
