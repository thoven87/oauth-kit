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

/// Token introspection response as defined in RFC 7662
public struct TokenIntrospectionResponse: Codable, @unchecked Sendable {
    /// Whether the token is active
    public let active: Bool

    /// The scope associated with the token
    public let scope: String?

    /// The client identifier for the OAuth 2.0 client that requested this token
    public let clientID: String?

    /// The username of the resource owner who authorized this token
    public let username: String?

    /// The token type (e.g., "Bearer")
    public let tokenType: String?

    /// The expiration time as seconds since Unix epoch
    public let exp: Int?

    /// The time when the token was issued as seconds since Unix epoch
    public let iat: Int?

    /// The time before which the token must not be accepted as seconds since Unix epoch
    public let nbf: Int?

    /// The subject of the token - usually the user identifier
    public let sub: String?

    /// The intended audience for this token
    public let aud: [String]?

    /// The issuer of this token
    public let iss: String?

    /// The unique identifier for this token
    public let jti: String?

    /// Additional custom claims (extension point)
    public let additionalClaims: [String: Any]?

    /// Initialize a token introspection response
    public init(
        active: Bool,
        scope: String? = nil,
        clientID: String? = nil,
        username: String? = nil,
        tokenType: String? = nil,
        exp: Int? = nil,
        iat: Int? = nil,
        nbf: Int? = nil,
        sub: String? = nil,
        aud: [String]? = nil,
        iss: String? = nil,
        jti: String? = nil,
        additionalClaims: [String: Any]? = nil
    ) {
        self.active = active
        self.scope = scope
        self.clientID = clientID
        self.username = username
        self.tokenType = tokenType
        self.exp = exp
        self.iat = iat
        self.nbf = nbf
        self.sub = sub
        self.aud = aud
        self.iss = iss
        self.jti = jti
        self.additionalClaims = additionalClaims
    }

    /// Coding keys for mapping JSON fields to properties
    enum CodingKeys: String, CodingKey {
        case active
        case scope
        case clientID = "client_id"
        case username
        case tokenType = "token_type"
        case exp, iat, nbf, sub, aud, iss, jti
    }

    /// Custom decoder to handle additional claims
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        active = try container.decode(Bool.self, forKey: .active)
        scope = try container.decodeIfPresent(String.self, forKey: .scope)
        clientID = try container.decodeIfPresent(String.self, forKey: .clientID)
        username = try container.decodeIfPresent(String.self, forKey: .username)
        tokenType = try container.decodeIfPresent(String.self, forKey: .tokenType)
        exp = try container.decodeIfPresent(Int.self, forKey: .exp)
        iat = try container.decodeIfPresent(Int.self, forKey: .iat)
        nbf = try container.decodeIfPresent(Int.self, forKey: .nbf)
        sub = try container.decodeIfPresent(String.self, forKey: .sub)

        // Handle audience as either string or array
        if let audString = try? container.decodeIfPresent(String.self, forKey: .aud) {
            aud = [audString]
        } else {
            aud = try container.decodeIfPresent([String].self, forKey: .aud)
        }

        iss = try container.decodeIfPresent(String.self, forKey: .iss)
        jti = try container.decodeIfPresent(String.self, forKey: .jti)

        // Capture any additional claims not covered by standard fields
        let allKeys = try decoder.container(keyedBy: AnyCodingKey.self)
        var additional: [String: Any] = [:]

        for key in allKeys.allKeys {
            // Skip standard RFC 7662 fields
            let standardFields: Set<String> = [
                "active", "scope", "client_id", "username", "token_type",
                "exp", "iat", "nbf", "sub", "aud", "iss", "jti",
            ]

            if !standardFields.contains(key.stringValue) {
                if let codableValue = try? allKeys.decode(AnyCodable.self, forKey: key) {
                    additional[key.stringValue] = codableValue.underlying
                }
            }
        }

        additionalClaims = additional.isEmpty ? nil : additional
    }

    /// Check if the token is expired
    /// - Parameter buffer: Buffer time in seconds before actual expiration to consider the token expired
    /// - Returns: True if the token is expired or will expire within the buffer time
    public func isExpired(buffer: TimeInterval = 60) -> Bool {
        guard let exp = exp else {
            return false
        }

        let expirationDate = Date(timeIntervalSince1970: TimeInterval(exp))
        let bufferDate = Date().addingTimeInterval(buffer)

        return bufferDate >= expirationDate
    }

    /// Check if the token is not yet valid
    /// - Returns: True if the token should not be accepted yet (nbf claim)
    public func isNotYetValid() -> Bool {
        guard let nbf = nbf else {
            return false
        }

        let notBeforeDate = Date(timeIntervalSince1970: TimeInterval(nbf))
        return Date() < notBeforeDate
    }

    /// Get expiration date if available
    public var expirationDate: Date? {
        guard let exp = exp else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(exp))
    }

    /// Get issued at date if available
    public var issuedAtDate: Date? {
        guard let iat = iat else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(iat))
    }

    /// Get not before date if available
    public var notBeforeDate: Date? {
        guard let nbf = nbf else { return nil }
        return Date(timeIntervalSince1970: TimeInterval(nbf))
    }
}

/// Token introspection request parameters
public struct TokenIntrospectionRequest: Sendable {
    /// The token to introspect (required)
    public let token: String

    /// A hint about the type of token being introspected (optional)
    public let tokenTypeHint: String?

    /// Initialize a token introspection request
    public init(token: String, tokenTypeHint: String? = nil) {
        self.token = token
        self.tokenTypeHint = tokenTypeHint
    }

    /// Convert to form parameters for HTTP request
    internal func toParameters() -> [String: String] {
        var parameters: [String: String] = [:]
        parameters["token"] = token

        if let tokenTypeHint = tokenTypeHint {
            parameters["token_type_hint"] = tokenTypeHint
        }

        return parameters
    }
}
