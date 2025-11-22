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

/// Provider for GitLab OAuth2 authentication
public struct GitLabOAuthProvider: Sendable {
    /// GitLab OAuth2 authorization endpoint
    public static let authorizationEndpoint = "https://gitlab.com/oauth/authorize"

    /// GitLab OAuth2 token endpoint
    public static let tokenEndpoint = "https://gitlab.com/oauth/token"

    /// GitLab API base URL (v4)
    public static let apiBaseURL = "https://gitlab.com/api/v4"

    /// Custom GitLab instance configuration
    public struct CustomInstance: Sendable {
        public let baseURL: String

        public init(baseURL: String) {
            self.baseURL = baseURL.trimmingCharacters(in: .whitespacesAndNewlines).trimmingCharacters(in: ["/"])
        }

        public var authorizationEndpoint: String {
            "\(baseURL)/oauth/authorize"
        }

        public var tokenEndpoint: String {
            "\(baseURL)/oauth/token"
        }

        public var apiBaseURL: String {
            "\(baseURL)/api/v4"
        }
    }

    /// The OAuthKit instance
    private let oauthKit: OAuthClientFactory

    /// The OAuth2 client configured for GitLab
    private let client: OAuth2Client

    /// Custom GitLab instance configuration (if using self-hosted)
    public let customInstance: CustomInstance?

    /// Initialize a new GitLab OAuth provider
    /// - Parameters:
    ///   - oauthKit: The OAuthKit instance
    ///   - oauth2Client: The OAuth2 client configured for GitLab
    ///   - customInstance: Custom GitLab instance configuration for self-hosted instances
    internal init(oauthKit: OAuthClientFactory, oauth2Client client: OAuth2Client, customInstance: CustomInstance? = nil) {
        self.oauthKit = oauthKit
        self.client = client
        self.customInstance = customInstance
    }

    /// Generate an authorization URL for GitLab Sign-In with recommended parameters
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
        scopes: [GitLabScope] = [.readUser]
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
            scopes: scopes.map { $0.rawValue }
        )

        return (url, codeVerifier)
    }

    /// Exchange an authorization code for tokens with GitLab
    /// - Parameters:
    ///   - code: The authorization code received from GitLab
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

    /// Retrieve the user's GitLab profile information
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    /// - Returns: The user's GitLab profile information
    public func getUserProfile(
        accessToken: String
    ) async throws -> GitLabUser {
        try await callGitLabAPI(
            accessToken: accessToken,
            endpoint: "/user",
            httpMethod: .GET
        )
    }

    /// Get the user's GitLab projects
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    ///   - membership: Filter projects by membership level
    ///   - owned: Show only owned projects
    ///   - starred: Show only starred projects
    ///   - archived: Include archived projects
    ///   - visibility: Filter by project visibility
    ///   - orderBy: Sort projects by field
    ///   - sort: Sort direction
    ///   - search: Search for projects by name
    ///   - simple: Return only limited fields for each project
    ///   - statistics: Include project statistics
    ///   - withIssuesEnabled: Only return projects with issues feature enabled
    ///   - withMergeRequestsEnabled: Only return projects with merge requests feature enabled
    /// - Returns: Array of GitLab projects
    public func getUserProjects(
        accessToken: String,
        membership: Bool? = nil,
        owned: Bool? = nil,
        starred: Bool? = nil,
        archived: Bool? = nil,
        visibility: GitLabProjectVisibility? = nil,
        orderBy: GitLabProjectOrderBy? = nil,
        sort: GitLabSortOrder? = nil,
        search: String? = nil,
        simple: Bool? = nil,
        statistics: Bool? = nil,
        withIssuesEnabled: Bool? = nil,
        withMergeRequestsEnabled: Bool? = nil
    ) async throws -> [GitLabProject] {
        var params: [String: String] = [:]

        if let membership = membership { params["membership"] = String(membership) }
        if let owned = owned { params["owned"] = String(owned) }
        if let starred = starred { params["starred"] = String(starred) }
        if let archived = archived { params["archived"] = String(archived) }
        if let visibility = visibility { params["visibility"] = visibility.rawValue }
        if let orderBy = orderBy { params["order_by"] = orderBy.rawValue }
        if let sort = sort { params["sort"] = sort.rawValue }
        if let search = search { params["search"] = search }
        if let simple = simple { params["simple"] = String(simple) }
        if let statistics = statistics { params["statistics"] = String(statistics) }
        if let withIssuesEnabled = withIssuesEnabled { params["with_issues_enabled"] = String(withIssuesEnabled) }
        if let withMergeRequestsEnabled = withMergeRequestsEnabled { params["with_merge_requests_enabled"] = String(withMergeRequestsEnabled) }

        let queryString = params.isEmpty ? "" : "?" + params.map { "\($0.key)=\($0.value)" }.joined(separator: "&")

        return try await callGitLabAPI(
            accessToken: accessToken,
            endpoint: "/projects\(queryString)",
            httpMethod: .GET
        )
    }

    /// Get the user's GitLab groups
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    /// - Returns: Array of GitLab groups
    public func getUserGroups(
        accessToken: String
    ) async throws -> [GitLabGroup] {
        try await callGitLabAPI(
            accessToken: accessToken,
            endpoint: "/groups",
            httpMethod: .GET
        )
    }

    /// Call the GitLab API
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    ///   - endpoint: The GitLab API endpoint to call (e.g., "/user")
    ///   - httpMethod: The HTTP method to use (default: GET)
    ///   - body: Optional request body for POST/PATCH requests
    ///   - httpClient: The HTTP client to use for the request
    ///   - logger: Logger for the GitLab API operation
    /// - Returns: The decoded response
    public func callGitLabAPI<T: Codable>(
        accessToken: String,
        endpoint: String,
        httpMethod: NIOHTTP1.HTTPMethod = .GET,
        body: ByteBuffer? = nil,
        httpClient: HTTPClient = HTTPClient.shared,
        logger: Logger = Logger(label: "com.oauthkit.GitLabOAuthProvider.callGitLabAPI")
    ) async throws -> T {
        let baseURL = customInstance?.apiBaseURL ?? Self.apiBaseURL
        let apiEndpoint = endpoint.hasPrefix("/") ? "\(baseURL)\(endpoint)" : "\(baseURL)/\(endpoint)"

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
                logger.error("GitLab API request failed with status: \(response.status)")
                throw OAuth2Error.responseError("GitLab API request failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
            let decoder = JSONDecoder()
            decoder.keyDecodingStrategy = .convertFromSnakeCase

            return try decoder.decode(T.self, from: responseBody)
        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("GitLab API request failed with error: \(error)")
            throw OAuth2Error.networkError("GitLab API request failed: \(error)")
        }
    }
}

/// GitLab OAuth scopes
public enum GitLabScope: String, CaseIterable {
    /// Read user profile information
    case readUser = "read_user"

    /// Full access to user profile
    case profile = "profile"

    /// Read user email address
    case email = "email"

    /// Read user repositories
    case readRepository = "read_repository"

    /// Write access to repositories
    case writeRepository = "write_repository"

    /// Read API access
    case readApi = "read_api"

    /// Full API access
    case api = "api"

    /// Read registry access
    case readRegistry = "read_registry"

    /// Write registry access
    case writeRegistry = "write_registry"

    /// Read-only repository access
    case readProjects = "read_projects"

    /// Write projects access
    case writeProjects = "write_projects"

    /// OpenID Connect scope
    case openid = "openid"

    /// Admin mode access
    case sudo = "sudo"

    /// Admin area access
    case adminMode = "admin_mode"
}

/// GitLab user profile information
public struct GitLabUser: Codable {
    /// User ID
    public let id: Int

    /// Username
    public let username: String

    /// Email address
    public let email: String?

    /// Full name
    public let name: String

    /// User state (active, blocked, etc.)
    public let state: String

    /// Avatar URL
    public let avatarUrl: String?

    /// Web URL to user profile
    public let webUrl: String

    /// Account creation date
    public let createdAt: String

    /// Bio/description
    public let bio: String?

    /// Location
    public let location: String?

    /// Public email
    public let publicEmail: String?

    /// Skype ID
    public let skype: String?

    /// LinkedIn profile
    public let linkedin: String?

    /// Twitter handle
    public let twitter: String?

    /// Website URL
    public let websiteUrl: String?

    /// Organization
    public let organization: String?

    /// Job title
    public let jobTitle: String?

    /// Pronouns
    public let pronouns: String?

    /// Whether user is admin
    public let isAdmin: Bool?

    /// Whether user can create groups
    public let canCreateGroup: Bool?

    /// Whether user can create projects
    public let canCreateProject: Bool?

    /// Whether 2FA is enabled
    public let twoFactorEnabled: Bool?

    /// External provider
    public let external: Bool?

    /// Private profile flag
    public let privateProfile: Bool?
}

/// GitLab project information
public struct GitLabProject: Codable {
    /// Project ID
    public let id: Int

    /// Project description
    public let description: String?

    /// Project name
    public let name: String

    /// Project name with namespace
    public let nameWithNamespace: String

    /// Project path
    public let path: String

    /// Project path with namespace
    public let pathWithNamespace: String

    /// Creation date
    public let createdAt: String

    /// Default branch
    public let defaultBranch: String?

    /// SSH URL to repository
    public let sshUrlToRepo: String

    /// HTTP URL to repository
    public let httpUrlToRepo: String

    /// Web URL to project
    public let webUrl: String

    /// README URL
    public let readmeUrl: String?

    /// Avatar URL
    public let avatarUrl: String?

    /// Forks count
    public let forksCount: Int

    /// Star count
    public let starCount: Int

    /// Last activity date
    public let lastActivityAt: String

    /// Project namespace
    public let namespace: GitLabNamespace

    /// Project visibility
    public let visibility: String

    /// Whether project is archived
    public let archived: Bool

    /// Issues enabled
    public let issuesEnabled: Bool

    /// Merge requests enabled
    public let mergeRequestsEnabled: Bool

    /// Wiki enabled
    public let wikiEnabled: Bool

    /// Jobs enabled
    public let jobsEnabled: Bool

    /// Snippets enabled
    public let snippetsEnabled: Bool

    /// Whether project is a fork
    public let forkedFromProject: GitLabForkedProject?
}

/// GitLab project namespace
public struct GitLabNamespace: Codable {
    /// Namespace ID
    public let id: Int

    /// Namespace name
    public let name: String

    /// Namespace path
    public let path: String

    /// Namespace kind
    public let kind: String

    /// Full path
    public let fullPath: String

    /// Parent ID
    public let parentId: Int?

    /// Avatar URL
    public let avatarUrl: String?

    /// Web URL
    public let webUrl: String
}

/// GitLab forked project information
public struct GitLabForkedProject: Codable {
    /// Project ID
    public let id: Int

    /// Project name
    public let name: String

    /// Project name with namespace
    public let nameWithNamespace: String

    /// Project path
    public let path: String

    /// Project path with namespace
    public let pathWithNamespace: String

    /// HTTP URL to repository
    public let httpUrlToRepo: String

    /// Web URL to project
    public let webUrl: String
}

/// GitLab group information
public struct GitLabGroup: Codable {
    /// Group ID
    public let id: Int

    /// Group name
    public let name: String

    /// Group path
    public let path: String

    /// Group description
    public let description: String

    /// Group visibility
    public let visibility: String

    /// Whether LFS is enabled
    public let lfsEnabled: Bool

    /// Avatar URL
    public let avatarUrl: String?

    /// Web URL
    public let webUrl: String

    /// Whether request access is enabled
    public let requestAccessEnabled: Bool

    /// Full name
    public let fullName: String

    /// Full path
    public let fullPath: String

    /// Parent ID
    public let parentId: Int?

    /// Creation date
    public let createdAt: String
}

/// GitLab project visibility levels
public enum GitLabProjectVisibility: String {
    case `private` = "private"
    case `internal` = "internal"
    case `public` = "public"
}

/// GitLab project ordering options
public enum GitLabProjectOrderBy: String {
    case id = "id"
    case name = "name"
    case path = "path"
    case createdAt = "created_at"
    case updatedAt = "updated_at"
    case lastActivityAt = "last_activity_at"
}

/// GitLab sort order
public enum GitLabSortOrder: String {
    case asc = "asc"
    case desc = "desc"
}
