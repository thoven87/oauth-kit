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

import Foundation

/// Response from an OAuth2 token endpoint
public struct TokenResponse: Codable, Sendable {
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

    init(
        accessToken: String,
        tokenType: String,
        expiresIn: Int? = nil,
        refreshToken: String? = nil,
        scope: String? = nil,
        idToken: String? = nil,
        createdAt: Date = Date()
    ) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.refreshToken = refreshToken
        self.scope = scope
        self.idToken = idToken
        self.createdAt = createdAt
    }

    /// Coding keys for mapping JSON fields to properties
    enum CodingKeys: String, CodingKey {
        case accessToken = "access_token"
        case tokenType = "token_type"
        case expiresIn = "expires_in"
        case refreshToken = "refresh_token"
        case scope
        case idToken = "id_token"
    }

    /// Initialize a new token response
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        accessToken = try container.decode(String.self, forKey: .accessToken)
        tokenType = try container.decode(String.self, forKey: .tokenType)
        expiresIn = try container.decodeIfPresent(Int.self, forKey: .expiresIn)
        refreshToken = try container.decodeIfPresent(String.self, forKey: .refreshToken)
        scope = try container.decodeIfPresent(String.self, forKey: .scope)
        idToken = try container.decodeIfPresent(String.self, forKey: .idToken)
        createdAt = Date()
    }

    /// Check if the token is expired
    /// - Parameter buffer: Buffer time in seconds before actual expiration to consider the token expired
    /// - Returns: True if the token is expired or will expire within the buffer time
    public func isExpired(buffer: TimeInterval = 60) -> Bool {
        guard let expiresIn = expiresIn else {
            return false
        }

        let expirationDate = createdAt.addingTimeInterval(TimeInterval(expiresIn))
        let bufferDate = Date().addingTimeInterval(buffer)

        return bufferDate >= expirationDate
    }
}
