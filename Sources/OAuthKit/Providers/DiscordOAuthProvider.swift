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

/// Provider for Discord OAuth2 authentication
public struct DiscordOAuthProvider: Sendable {
    /// Discord OAuth2 authorization endpoint
    public static let authorizationEndpoint = "https://discord.com/api/oauth2/authorize"

    /// Discord OAuth2 token endpoint
    public static let tokenEndpoint = "https://discord.com/api/oauth2/token"

    /// Discord API base URL
    public static let apiBaseURL = "https://discord.com/api/v10"

    /// The OAuthKit instance
    private let oauthKit: OAuthClientFactory

    /// The OAuth2 client configured for Discord
    private let client: OAuth2Client

    /// Initialize a new Discord OAuth provider
    /// - Parameters:
    ///   - oauthKit: The OAuthKit instance
    ///   - oauth2Client: The OAuth2 client configured for Discord
    internal init(oauthKit: OAuthClientFactory, oauth2Client client: OAuth2Client) {
        self.oauthKit = oauthKit
        self.client = client
    }

    /// Generate an authorization URL for Discord Sign-In with recommended parameters
    /// - Parameters:
    ///   - state: An opaque value to maintain state between the request and callback
    ///   - prompt: Controls the Discord authorization prompt behavior
    ///   - guildId: Pre-select a guild for bot authorization (optional)
    ///   - disableGuildSelect: Disable guild selection for bot authorization (optional)
    ///   - permissions: Permissions to request for bot authorization (optional)
    ///   - usePKCE: Whether to use PKCE (recommended and enabled by default)
    ///   - additionalParameters: Additional parameters to include in the authorization URL
    ///   - scopes: The requested scopes
    /// - Returns: A tuple containing the authorization URL and code verifier (for PKCE)
    public func generateAuthorizationURL(
        state: String? = nil,
        prompt: DiscordPrompt? = nil,
        guildId: String? = nil,
        disableGuildSelect: Bool? = nil,
        permissions: DiscordPermissions? = nil,
        usePKCE: Bool = true,
        additionalParameters: [String: String] = [:],
        scopes: [String] = ["identify", "email"]
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

        // Add Discord-specific parameters
        if let prompt = prompt {
            additionalParams["prompt"] = prompt.rawValue
        }

        if let guildId = guildId {
            additionalParams["guild_id"] = guildId
        }

        if let disableGuildSelect = disableGuildSelect {
            additionalParams["disable_guild_select"] = String(disableGuildSelect)
        }

        if let permissions = permissions {
            additionalParams["permissions"] = String(permissions.rawValue)
        }

        // Discord uses response_type=code by default
        let url = try client.generateAuthorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            additionalParameters: additionalParams,
            scopes: scopes
        )

        return (url, codeVerifier)
    }

    /// Exchange an authorization code for tokens with Discord
    /// - Parameters:
    ///   - code: The authorization code received from Discord
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
        // ID tokens are an OpenID Connect feature, not OAuth2
        // Use getUserProfile() to get user information via API
    }

    /// Retrieve the user's Discord profile information
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    /// - Returns: The user's Discord profile information
    public func getUserProfile(
        accessToken: String
    ) async throws -> DiscordUser {
        try await callDiscordAPI(
            accessToken: accessToken,
            endpoint: "/users/@me",
            httpMethod: .GET
        )
    }

    /// Get the user's Discord guilds (servers)
    /// - Parameters:
    ///   - accessToken: The access token from the token response (requires 'guilds' scope)
    /// - Returns: Array of Discord guilds the user is a member of
    public func getUserGuilds(
        accessToken: String
    ) async throws -> [DiscordGuild] {
        try await callDiscordAPI(
            accessToken: accessToken,
            endpoint: "/users/@me/guilds",
            httpMethod: .GET
        )
    }

    /// Get the user's connections (linked accounts)
    /// - Parameters:
    ///   - accessToken: The access token from the token response (requires 'connections' scope)
    /// - Returns: Array of Discord connections
    public func getUserConnections(
        accessToken: String
    ) async throws -> [DiscordConnection] {
        try await callDiscordAPI(
            accessToken: accessToken,
            endpoint: "/users/@me/connections",
            httpMethod: .GET
        )
    }

    /// Call the Discord API
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    ///   - endpoint: The Discord API endpoint to call (e.g., "/users/@me")
    ///   - httpMethod: The HTTP method to use (default: GET)
    ///   - body: Optional request body for POST/PATCH requests
    ///   - httpClient: The HTTP client to use for the request
    ///   - logger: Logger for the Discord API operation
    /// - Returns: The decoded response
    public func callDiscordAPI<T: Codable>(
        accessToken: String,
        endpoint: String,
        httpMethod: NIOHTTP1.HTTPMethod = .GET,
        body: ByteBuffer? = nil,
        httpClient: HTTPClient = HTTPClient.shared,
        logger: Logger = Logger(label: "com.oauthkit.DiscordOAuthProvider.callDiscordAPI")
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

        if let body = body {
            request.body = .bytes(body)
            request.headers.add(name: "Content-Type", value: "application/json")
        }

        do {
            let response = try await httpClient.execute(request, timeout: .seconds(60))

            guard response.status.code >= 200 && response.status.code < 300 else {
                logger.error("Discord API request failed with status: \(response.status)")
                throw OAuth2Error.responseError("Discord API request failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
            let decoder = JSONDecoder()
            decoder.keyDecodingStrategy = .convertFromSnakeCase

            return try decoder.decode(T.self, from: responseBody)
        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("Discord API request failed with error: \(error)")
            throw OAuth2Error.networkError("Discord API request failed: \(error)")
        }
    }
}

/// Discord bot permissions using OptionSet for bitwise operations
public struct DiscordPermissions: OptionSet, Sendable {
    public let rawValue: Int

    public init(rawValue: Int) {
        self.rawValue = rawValue
    }

    // Text Permissions
    public static let createInstantInvite = DiscordPermissions(rawValue: 1 << 0)  // 0x0000000000000001
    public static let kickMembers = DiscordPermissions(rawValue: 1 << 1)  // 0x0000000000000002
    public static let banMembers = DiscordPermissions(rawValue: 1 << 2)  // 0x0000000000000004
    public static let administrator = DiscordPermissions(rawValue: 1 << 3)  // 0x0000000000000008
    public static let manageChannels = DiscordPermissions(rawValue: 1 << 4)  // 0x0000000000000010
    public static let manageGuild = DiscordPermissions(rawValue: 1 << 5)  // 0x0000000000000020
    public static let addReactions = DiscordPermissions(rawValue: 1 << 6)  // 0x0000000000000040
    public static let viewAuditLog = DiscordPermissions(rawValue: 1 << 7)  // 0x0000000000000080
    public static let prioritySpeaker = DiscordPermissions(rawValue: 1 << 8)  // 0x0000000000000100
    public static let stream = DiscordPermissions(rawValue: 1 << 9)  // 0x0000000000000200
    public static let viewChannel = DiscordPermissions(rawValue: 1 << 10)  // 0x0000000000000400
    public static let sendMessages = DiscordPermissions(rawValue: 1 << 11)  // 0x0000000000000800
    public static let sendTtsMessages = DiscordPermissions(rawValue: 1 << 12)  // 0x0000000000001000
    public static let manageMessages = DiscordPermissions(rawValue: 1 << 13)  // 0x0000000000002000
    public static let embedLinks = DiscordPermissions(rawValue: 1 << 14)  // 0x0000000000004000
    public static let attachFiles = DiscordPermissions(rawValue: 1 << 15)  // 0x0000000000008000
    public static let readMessageHistory = DiscordPermissions(rawValue: 1 << 16)  // 0x0000000000010000
    public static let mentionEveryone = DiscordPermissions(rawValue: 1 << 17)  // 0x0000000000020000
    public static let useExternalEmojis = DiscordPermissions(rawValue: 1 << 18)  // 0x0000000000040000
    public static let viewGuildInsights = DiscordPermissions(rawValue: 1 << 19)  // 0x0000000000080000
    public static let connect = DiscordPermissions(rawValue: 1 << 20)  // 0x0000000000100000
    public static let speak = DiscordPermissions(rawValue: 1 << 21)  // 0x0000000000200000
    public static let muteMembers = DiscordPermissions(rawValue: 1 << 22)  // 0x0000000000400000
    public static let deafenMembers = DiscordPermissions(rawValue: 1 << 23)  // 0x0000000000800000
    public static let moveMembers = DiscordPermissions(rawValue: 1 << 24)  // 0x0000000001000000
    public static let useVoiceActivity = DiscordPermissions(rawValue: 1 << 25)  // 0x0000000002000000
    public static let changeNickname = DiscordPermissions(rawValue: 1 << 26)  // 0x0000000004000000
    public static let manageNicknames = DiscordPermissions(rawValue: 1 << 27)  // 0x0000000008000000
    public static let manageRoles = DiscordPermissions(rawValue: 1 << 28)  // 0x0000000010000000
    public static let manageWebhooks = DiscordPermissions(rawValue: 1 << 29)  // 0x0000000020000000
    public static let manageGuildExpressions = DiscordPermissions(rawValue: 1 << 30)  // 0x0000000040000000
    public static let useApplicationCommands = DiscordPermissions(rawValue: 1 << 31)  // 0x0000000080000000
    public static let requestToSpeak = DiscordPermissions(rawValue: 1 << 32)  // 0x0000000100000000
    public static let manageEvents = DiscordPermissions(rawValue: 1 << 33)  // 0x0000000200000000
    public static let manageThreads = DiscordPermissions(rawValue: 1 << 34)  // 0x0000000400000000
    public static let createPublicThreads = DiscordPermissions(rawValue: 1 << 35)  // 0x0000000800000000
    public static let createPrivateThreads = DiscordPermissions(rawValue: 1 << 36)  // 0x0000001000000000
    public static let useExternalStickers = DiscordPermissions(rawValue: 1 << 37)  // 0x0000002000000000
    public static let sendMessagesInThreads = DiscordPermissions(rawValue: 1 << 38)  // 0x0000004000000000
    public static let useEmbeddedActivities = DiscordPermissions(rawValue: 1 << 39)  // 0x0000008000000000
    public static let moderateMembers = DiscordPermissions(rawValue: 1 << 40)  // 0x0000010000000000
    public static let viewCreatorMonetizationAnalytics = DiscordPermissions(rawValue: 1 << 41)  // 0x0000020000000000
    public static let useSoundboard = DiscordPermissions(rawValue: 1 << 42)  // 0x0000040000000000
    public static let createGuildExpressions = DiscordPermissions(rawValue: 1 << 43)  // 0x0000080000000000
    public static let createEvents = DiscordPermissions(rawValue: 1 << 44)  // 0x0000100000000000
    public static let useExternalSounds = DiscordPermissions(rawValue: 1 << 45)  // 0x0000200000000000
    public static let sendVoiceMessages = DiscordPermissions(rawValue: 1 << 46)  // 0x0000400000000000
    public static let sendPolls = DiscordPermissions(rawValue: 1 << 47)  // 0x0000800000000000
    public static let useExternalApps = DiscordPermissions(rawValue: 1 << 48)  // 0x0001000000000000

    /// The integer value of the permission set
    public var value: Int {
        rawValue
    }
}

extension DiscordPermissions: CustomStringConvertible {
    /// Human-readable description of the permission set
    public var description: String {
        if isEmpty {
            return "No Permissions"
        }

        var descriptions: [String] = []

        if contains(.createInstantInvite) { descriptions.append("Create Instant Invite") }
        if contains(.kickMembers) { descriptions.append("Kick Members") }
        if contains(.banMembers) { descriptions.append("Ban Members") }
        if contains(.administrator) { descriptions.append("Administrator") }
        if contains(.manageChannels) { descriptions.append("Manage Channels") }
        if contains(.manageGuild) { descriptions.append("Manage Server") }
        if contains(.addReactions) { descriptions.append("Add Reactions") }
        if contains(.viewAuditLog) { descriptions.append("View Audit Log") }
        if contains(.prioritySpeaker) { descriptions.append("Priority Speaker") }
        if contains(.stream) { descriptions.append("Video") }
        if contains(.viewChannel) { descriptions.append("View Channels") }
        if contains(.sendMessages) { descriptions.append("Send Messages") }
        if contains(.sendTtsMessages) { descriptions.append("Send Text-to-Speech Messages") }
        if contains(.manageMessages) { descriptions.append("Manage Messages") }
        if contains(.embedLinks) { descriptions.append("Embed Links") }
        if contains(.attachFiles) { descriptions.append("Attach Files") }
        if contains(.readMessageHistory) { descriptions.append("Read Message History") }
        if contains(.mentionEveryone) { descriptions.append("Mention @everyone, @here, and All Roles") }
        if contains(.useExternalEmojis) { descriptions.append("Use External Emojis") }
        if contains(.viewGuildInsights) { descriptions.append("View Server Insights") }
        if contains(.connect) { descriptions.append("Connect") }
        if contains(.speak) { descriptions.append("Speak") }
        if contains(.muteMembers) { descriptions.append("Mute Members") }
        if contains(.deafenMembers) { descriptions.append("Deafen Members") }
        if contains(.moveMembers) { descriptions.append("Move Members") }
        if contains(.useVoiceActivity) { descriptions.append("Use Voice Activity") }
        if contains(.changeNickname) { descriptions.append("Change Nickname") }
        if contains(.manageNicknames) { descriptions.append("Manage Nicknames") }
        if contains(.manageRoles) { descriptions.append("Manage Roles") }
        if contains(.manageWebhooks) { descriptions.append("Manage Webhooks") }
        if contains(.manageGuildExpressions) { descriptions.append("Manage Expressions") }
        if contains(.useApplicationCommands) { descriptions.append("Use Application Commands") }
        if contains(.requestToSpeak) { descriptions.append("Request to Speak") }
        if contains(.manageEvents) { descriptions.append("Manage Events") }
        if contains(.manageThreads) { descriptions.append("Manage Threads") }
        if contains(.createPublicThreads) { descriptions.append("Create Public Threads") }
        if contains(.createPrivateThreads) { descriptions.append("Create Private Threads") }
        if contains(.useExternalStickers) { descriptions.append("Use External Stickers") }
        if contains(.sendMessagesInThreads) { descriptions.append("Send Messages in Threads") }
        if contains(.useEmbeddedActivities) { descriptions.append("Use Activities") }
        if contains(.moderateMembers) { descriptions.append("Timeout Members") }
        if contains(.viewCreatorMonetizationAnalytics) { descriptions.append("View Creator Monetization Analytics") }
        if contains(.useSoundboard) { descriptions.append("Use Soundboard") }
        if contains(.createGuildExpressions) { descriptions.append("Create Expressions") }
        if contains(.createEvents) { descriptions.append("Create Events") }
        if contains(.useExternalSounds) { descriptions.append("Use External Sounds") }
        if contains(.sendVoiceMessages) { descriptions.append("Send Voice Messages") }
        if contains(.sendPolls) { descriptions.append("Create Polls") }
        if contains(.useExternalApps) { descriptions.append("Use External Apps") }

        return descriptions.joined(separator: ", ")
    }
}

extension DiscordPermissions: ExpressibleByIntegerLiteral {
    /// Allow creating permissions from integer literals
    public init(integerLiteral value: Int) {
        self.init(rawValue: value)
    }
}

extension DiscordPermissions {
    /// Common permission combinations for different bot types
    public static var basicBot: DiscordPermissions {
        [.viewChannel, .sendMessages, .embedLinks, .readMessageHistory, .addReactions]
    }

    public static var moderationBot: DiscordPermissions {
        [
            .viewChannel, .sendMessages, .embedLinks, .readMessageHistory, .addReactions,
            .manageMessages, .kickMembers, .banMembers, .manageRoles, .moderateMembers,
        ]
    }

    public static var musicBot: DiscordPermissions {
        [
            .viewChannel, .sendMessages, .embedLinks, .readMessageHistory, .addReactions,
            .connect, .speak, .useVoiceActivity, .prioritySpeaker,
        ]
    }

    public static var adminBot: DiscordPermissions {
        [.administrator]
    }
}

/// Discord authorization prompt behavior
public enum DiscordPrompt: String {
    /// Default behavior - show consent screen if user hasn't consented
    case consent = "consent"

    /// Skip authorization screen if user has already authorized
    case none = "none"
}

/// Discord user information
public struct DiscordUser: Codable {
    /// The user's unique Discord ID
    public let id: String

    /// The user's username (not unique across the platform)
    public let username: String

    /// The user's display name (if set)
    public let globalName: String?

    /// The user's Discord tag (discriminator) - deprecated, will be "0" for new usernames
    public let discriminator: String

    /// The user's avatar hash
    public let avatar: String?

    /// Whether the user belongs to an OAuth2 application
    public let bot: Bool?

    /// Whether the user is an Official Discord System user
    public let system: Bool?

    /// Whether the user has two factor enabled
    public let mfaEnabled: Bool?

    /// The user's banner hash
    public let banner: String?

    /// The user's banner color (integer representation)
    public let accentColor: Int?

    /// The user's chosen language option
    public let locale: String?

    /// Whether the email is verified
    public let verified: Bool?

    /// The user's email address
    public let email: String?

    /// The flags on a user's account (bit field)
    public let flags: Int?

    /// The type of Nitro subscription
    public let premiumType: Int?

    /// The public flags on a user's account (bit field)
    public let publicFlags: Int?

    /// Data for the user's avatar decoration
    public let avatarDecorationData: DiscordAvatarDecoration?

    enum CodingKeys: String, CodingKey {
        case id
        case username
        case globalName = "global_name"
        case discriminator
        case avatar
        case bot
        case system
        case mfaEnabled = "mfa_enabled"
        case banner
        case accentColor = "accent_color"
        case locale
        case verified
        case email
        case flags
        case premiumType = "premium_type"
        case publicFlags = "public_flags"
        case avatarDecorationData = "avatar_decoration_data"
    }
}

/// Discord avatar decoration data
public struct DiscordAvatarDecoration: Codable {
    /// The avatar decoration hash
    public let asset: String

    /// The ID of the avatar decoration's SKU
    public let skuId: String

    enum CodingKeys: String, CodingKey {
        case asset
        case skuId = "sku_id"
    }
}

/// Discord guild (server) information
public struct DiscordGuild: Codable {
    /// Guild ID
    public let id: String

    /// Guild name
    public let name: String

    /// Icon hash
    public let icon: String?

    /// True if the user is the owner of the guild
    public let owner: Bool?

    /// Total permissions for the user in the guild
    public let permissions: String?

    /// Enabled guild features
    public let features: [String]?

    /// Approximate number of members in the guild
    public let approximateMemberCount: Int?

    /// Approximate number of non-offline members in the guild
    public let approximatePresenceCount: Int?
}

/// Discord connection (linked account) information
public struct DiscordConnection: Codable {
    /// ID of the connection account
    public let id: String

    /// The username of the connection account
    public let name: String

    /// The service of the connection (twitch, youtube, etc.)
    public let type: String

    /// Whether the connection is revoked
    public let revoked: Bool?

    /// An array of partial server integrations
    public let integrations: [DiscordIntegration]?

    /// Whether the connection is verified
    public let verified: Bool

    /// Whether friend sync is enabled for this connection
    public let friendSync: Bool

    /// Whether activities related to this connection will be shown in presence updates
    public let showActivity: Bool

    /// Whether this connection has a corresponding third party OAuth2 token
    public let twoWayLink: Bool

    /// Visibility of this connection
    public let visibility: Int
}

/// Discord integration information
public struct DiscordIntegration: Codable {
    /// Integration ID
    public let id: String

    /// Integration name
    public let name: String

    /// Integration type
    public let type: String
}
