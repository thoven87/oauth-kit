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

/// Provider for Dropbox OAuth2 authentication
public struct DropboxOAuthProvider: Sendable {
    /// Dropbox OAuth2 authorization endpoint
    public static let authorizationEndpoint = "https://www.dropbox.com/oauth2/authorize"

    /// Dropbox OAuth2 token endpoint
    public static let tokenEndpoint = "https://api.dropboxapi.com/oauth2/token"

    /// Dropbox API base URL (v2)
    public static let apiBaseURL = "https://api.dropboxapi.com/2"

    /// Dropbox Content API base URL (for file operations)
    public static let contentAPIBaseURL = "https://content.dropboxapi.com/2"

    /// The OAuthKit instance
    private let oauthKit: OAuthClientFactory

    /// The OAuth2 client configured for Dropbox
    private let client: OAuth2Client

    /// Initialize a new Dropbox OAuth provider
    /// - Parameters:
    ///   - oauthKit: The OAuthKit instance
    ///   - oauth2Client: The OAuth2 client configured for Dropbox
    internal init(oauthKit: OAuthClientFactory, oauth2Client client: OAuth2Client) {
        self.oauthKit = oauthKit
        self.client = client
    }

    /// Generate an authorization URL for Dropbox Sign-In with recommended parameters
    /// - Parameters:
    ///   - state: An opaque value to maintain state between the request and callback
    ///   - requireRole: Require a specific role for Dropbox Business users
    ///   - forceReapprove: Force user to reapprove the app
    ///   - disableSignup: Disable new user signup
    ///   - locale: User's preferred locale
    ///   - forceReauthentication: Force user to re-authenticate
    ///   - usePKCE: Whether to use PKCE (recommended and enabled by default)
    ///   - additionalParameters: Additional parameters to include in the authorization URL
    ///   - scopes: The requested scopes
    /// - Returns: A tuple containing the authorization URL and code verifier (for PKCE)
    public func generateAuthorizationURL(
        state: String? = nil,
        requireRole: DropboxRole? = nil,
        forceReapprove: Bool = false,
        disableSignup: Bool = false,
        locale: String? = nil,
        forceReauthentication: Bool = false,
        usePKCE: Bool = true,
        additionalParameters: [String: String] = [:],
        scopes: [DropboxScope] = []
    ) throws -> (url: URL, codeVerifier: String?) {
        var additionalParams = additionalParameters
        var codeVerifier: String? = nil
        var codeChallenge: String? = nil

        // Generate PKCE if requested
        if usePKCE {
            let pkce = OAuth2Client.generatePKCE()
            codeVerifier = pkce.codeVerifier
            codeChallenge = pkce.codeChallenge
        }

        // Add Dropbox-specific parameters
        if let requireRole = requireRole {
            additionalParams["require_role"] = requireRole.rawValue
        }

        if forceReapprove {
            additionalParams["force_reapprove"] = "true"
        }

        if disableSignup {
            additionalParams["disable_signup"] = "true"
        }

        if let locale = locale {
            additionalParams["locale"] = locale
        }

        if forceReauthentication {
            additionalParams["force_reauthentication"] = "true"
        }

        // Dropbox uses token_access_type parameter instead of traditional scopes for some permissions
        if !scopes.isEmpty {
            let scopeString = scopes.map { $0.rawValue }.joined(separator: " ")
            additionalParams["scope"] = scopeString
        }

        let url = try client.generateAuthorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            additionalParameters: additionalParams,
            scopes: []  // Scopes handled above in additionalParams
        )

        return (url, codeVerifier)
    }

    /// Exchange an authorization code for tokens with Dropbox
    /// - Parameters:
    ///   - code: The authorization code received from Dropbox
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

    /// Get the user's account information
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    /// - Returns: The user's Dropbox account information
    public func getCurrentAccount(
        accessToken: String
    ) async throws -> DropboxAccount {
        try await callDropboxAPI(
            accessToken: accessToken,
            endpoint: "/users/get_current_account",
            httpMethod: .POST
        )
    }

    /// Get the user's space usage information
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    /// - Returns: The user's space usage information
    public func getSpaceUsage(
        accessToken: String
    ) async throws -> DropboxSpaceUsage {
        try await callDropboxAPI(
            accessToken: accessToken,
            endpoint: "/users/get_space_usage",
            httpMethod: .POST
        )
    }

    /// List folder contents
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    ///   - path: The folder path to list (empty string for root)
    ///   - recursive: Whether to list contents recursively
    ///   - includeMediaInfo: Include media info for photo and video files
    ///   - includeDeleted: Include deleted files
    ///   - includeHasExplicitSharedMembers: Include information about shared members
    /// - Returns: Folder listing response
    public func listFolder(
        accessToken: String,
        path: String = "",
        recursive: Bool = false,
        includeMediaInfo: Bool = false,
        includeDeleted: Bool = false,
        includeHasExplicitSharedMembers: Bool = false
    ) async throws -> DropboxListFolderResult {
        let requestBody = DropboxListFolderRequest(
            path: path,
            recursive: recursive,
            includeMediaInfo: includeMediaInfo,
            includeDeleted: includeDeleted,
            includeHasExplicitSharedMembers: includeHasExplicitSharedMembers
        )

        let body = try JSONEncoder().encode(requestBody)
        let buffer = ByteBuffer(data: Data(body))

        return try await callDropboxAPI(
            accessToken: accessToken,
            endpoint: "/files/list_folder",
            httpMethod: .POST,
            body: buffer
        )
    }

    /// Create a folder
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    ///   - path: The path of the folder to create
    ///   - autorename: Automatically rename if a conflict occurs
    /// - Returns: The created folder metadata
    public func createFolder(
        accessToken: String,
        path: String,
        autorename: Bool = false
    ) async throws -> DropboxFolderMetadata {
        let requestBody = DropboxCreateFolderRequest(path: path, autorename: autorename)
        let body = try JSONEncoder().encode(requestBody)
        let buffer = ByteBuffer(data: Data(body))

        return try await callDropboxAPI(
            accessToken: accessToken,
            endpoint: "/files/create_folder_v2",
            httpMethod: .POST,
            body: buffer
        )
    }

    /// Call the Dropbox API
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    ///   - endpoint: The Dropbox API endpoint to call (e.g., "/users/get_current_account")
    ///   - httpMethod: The HTTP method to use (default: POST, as most Dropbox API endpoints use POST)
    ///   - body: Optional request body for requests
    ///   - useContentAPI: Whether to use the content API base URL instead of the regular API
    ///   - httpClient: The HTTP client to use for the request
    ///   - logger: Logger for the Dropbox API operation
    /// - Returns: The decoded response
    public func callDropboxAPI<T: Codable>(
        accessToken: String,
        endpoint: String,
        httpMethod: NIOHTTP1.HTTPMethod = .POST,
        body: ByteBuffer? = nil,
        useContentAPI: Bool = false,
        httpClient: HTTPClient = HTTPClient.shared,
        logger: Logger = Logger(label: "com.oauthkit.DropboxOAuthProvider.callDropboxAPI")
    ) async throws -> T {
        let baseURL = useContentAPI ? Self.contentAPIBaseURL : Self.apiBaseURL
        let apiEndpoint = endpoint.hasPrefix("/") ? "\(baseURL)\(endpoint)" : "\(baseURL)/\(endpoint)"

        var request = HTTPClientRequest(url: apiEndpoint)
        request.method = httpMethod
        request.headers.add(name: "Authorization", value: "Bearer \(accessToken)")
        request.headers.add(name: "Accept", value: "application/json")
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        if let body = body {
            request.body = .bytes(body)
            request.headers.add(name: "Content-Type", value: "application/json")
        } else if httpMethod == .POST {
            // Dropbox API often requires empty POST body
            request.body = .bytes(ByteBuffer(string: ""))
            request.headers.add(name: "Content-Type", value: "application/json")
        }

        do {
            let response = try await httpClient.execute(request, timeout: .seconds(60))

            guard response.status.code >= 200 && response.status.code < 300 else {
                logger.error("Dropbox API request failed with status: \(response.status)")
                throw OAuth2Error.responseError("Dropbox API request failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
            let decoder = JSONDecoder()
            decoder.keyDecodingStrategy = .convertFromSnakeCase

            return try decoder.decode(T.self, from: responseBody)
        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("Dropbox API request failed with error: \(error)")
            throw OAuth2Error.networkError("Dropbox API request failed: \(error)")
        }
    }
}

/// Dropbox OAuth scopes
public enum DropboxScope: String, CaseIterable {
    /// Read access to account information
    case accountInfoRead = "account_info.read"

    /// Write access to account information
    case accountInfoWrite = "account_info.write"

    /// Read access to files and folders
    case filesMetadataRead = "files.metadata.read"

    /// Write access to files and folders metadata
    case filesMetadataWrite = "files.metadata.write"

    /// Read access to file contents
    case filesContentRead = "files.content.read"

    /// Write access to file contents
    case filesContentWrite = "files.content.write"

    /// Access to shared folders
    case sharingRead = "sharing.read"

    /// Write access to sharing
    case sharingWrite = "sharing.write"

    /// Access to contacts
    case contactsRead = "contacts.read"

    /// Write access to contacts
    case contactsWrite = "contacts.write"

    /// File requests access
    case fileRequestsRead = "file_requests.read"

    /// Write access to file requests
    case fileRequestsWrite = "file_requests.write"
}

/// Dropbox role requirements for Business accounts
public enum DropboxRole: String {
    /// Personal account or any business role
    case personal = "personal"

    /// Work account (business user)
    case work = "work"
}

/// Dropbox account information
public struct DropboxAccount: Codable {
    /// Account ID
    public let accountId: String

    /// Account name
    public let name: DropboxAccountName

    /// Email address
    public let email: String

    /// Whether email is verified
    public let emailVerified: Bool

    /// Profile photo URL
    public let profilePhotoUrl: String?

    /// Whether account is disabled
    public let disabled: Bool

    /// Account country
    public let country: String?

    /// Account locale
    public let locale: String?

    /// Referral link
    public let referralLink: String?

    /// Team information (for business accounts)
    public let team: DropboxTeam?

    /// Account type
    public let accountType: DropboxAccountType

    /// Root info
    public let rootInfo: DropboxRootInfo?
}

/// Dropbox account name
public struct DropboxAccountName: Codable {
    /// Given name
    public let givenName: String

    /// Surname
    public let surname: String

    /// Familiar name
    public let familiarName: String

    /// Display name
    public let displayName: String

    /// Abbreviated name
    public let abbreviatedName: String
}

/// Dropbox team information
public struct DropboxTeam: Codable {
    /// Team ID
    public let id: String

    /// Team name
    public let name: String

    /// Team sharing policies
    public let sharingPolicies: DropboxSharingPolicies?

    /// Office add-in policy
    public let officeAddinPolicy: DropboxOfficeAddinPolicy?
}

/// Dropbox sharing policies
public struct DropboxSharingPolicies: Codable {
    /// Shared folder member policy
    public let sharedFolderMemberPolicy: String?

    /// Shared folder join policy
    public let sharedFolderJoinPolicy: String?

    /// Shared link create policy
    public let sharedLinkCreatePolicy: String?
}

/// Dropbox office add-in policy
public struct DropboxOfficeAddinPolicy: Codable {
    /// Whether Office add-in is enabled
    public let enabled: Bool
}

/// Dropbox account type
public struct DropboxAccountType: Codable {
    /// Account type tag
    public let tag: String

    /// Whether it's a basic account
    public var isBasic: Bool {
        tag == "basic"
    }

    /// Whether it's a pro account
    public var isPro: Bool {
        tag == "pro"
    }

    /// Whether it's a business account
    public var isBusiness: Bool {
        tag == "business"
    }
}

/// Dropbox root info
public struct DropboxRootInfo: Codable {
    /// Root namespace ID
    public let rootNamespaceId: String

    /// Home namespace ID
    public let homeNamespaceId: String
}

/// Dropbox space usage information
public struct DropboxSpaceUsage: Codable {
    /// Used space in bytes
    public let used: UInt64

    /// Allocation information
    public let allocation: DropboxSpaceAllocation
}

/// Dropbox space allocation
public struct DropboxSpaceAllocation: Codable {
    /// Allocation type tag
    public let tag: String

    /// Individual allocation (for personal accounts)
    public let individual: DropboxIndividualSpaceAllocation?

    /// Team allocation (for business accounts)
    public let team: DropboxTeamSpaceAllocation?
}

/// Individual space allocation
public struct DropboxIndividualSpaceAllocation: Codable {
    /// Allocated space in bytes
    public let allocated: UInt64
}

/// Team space allocation
public struct DropboxTeamSpaceAllocation: Codable {
    /// Used space in bytes
    public let used: UInt64

    /// Allocated space in bytes
    public let allocated: UInt64

    /// User within team allocation
    public let userWithinTeamSpaceAllocated: UInt64?

    /// User within team space limit type
    public let userWithinTeamSpaceLimitType: String?
}

/// Request structure for listing folder contents
internal struct DropboxListFolderRequest: Codable {
    let path: String
    let recursive: Bool
    let includeMediaInfo: Bool
    let includeDeleted: Bool
    let includeHasExplicitSharedMembers: Bool
}

/// Response structure for folder listing
public struct DropboxListFolderResult: Codable {
    /// Array of file and folder entries
    public let entries: [DropboxMetadata]

    /// Cursor for pagination
    public let cursor: String

    /// Whether there are more entries
    public let hasMore: Bool
}

/// Base metadata for Dropbox files and folders
public struct DropboxMetadata: Codable {
    /// Metadata type tag
    public let tag: String

    /// File name
    public let name: String

    /// Path (lower case)
    public let pathLower: String?

    /// Path (display case)
    public let pathDisplay: String?

    /// Parent shared folder ID
    public let parentSharedFolderId: String?

    /// Preview URL
    public let previewUrl: String?

    /// Whether it's a file
    public var isFile: Bool {
        tag == "file"
    }

    /// Whether it's a folder
    public var isFolder: Bool {
        tag == "folder"
    }
}

/// Request structure for creating folders
internal struct DropboxCreateFolderRequest: Codable {
    let path: String
    let autorename: Bool
}

/// Folder metadata response
public struct DropboxFolderMetadata: Codable {
    /// Metadata for the created folder
    public let metadata: DropboxMetadata
}
