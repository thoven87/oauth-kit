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

/// Token types as defined in RFC 8693 (OAuth 2.0 Token Exchange)
public enum TokenType: Codable, Sendable, Equatable {
    /// OAuth 2.0 access token
    case accessToken

    /// OAuth 2.0 refresh token
    case refreshToken

    /// OpenID Connect ID token
    case idToken

    /// SAML 1.1 assertion
    case saml1

    /// SAML 2.0 assertion
    case saml2

    /// JWT token
    case jwt

    /// Custom token type (for extensibility)
    case custom(String)

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let stringValue = try container.decode(String.self)

        switch stringValue {
        case "urn:ietf:params:oauth:token-type:access_token":
            self = .accessToken
        case "urn:ietf:params:oauth:token-type:refresh_token":
            self = .refreshToken
        case "urn:ietf:params:oauth:token-type:id_token":
            self = .idToken
        case "urn:ietf:params:oauth:token-type:saml1":
            self = .saml1
        case "urn:ietf:params:oauth:token-type:saml2":
            self = .saml2
        case "urn:ietf:params:oauth:token-type:jwt":
            self = .jwt
        default:
            self = .custom(stringValue)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    public var rawValue: String {
        switch self {
        case .accessToken:
            return "urn:ietf:params:oauth:token-type:access_token"
        case .refreshToken:
            return "urn:ietf:params:oauth:token-type:refresh_token"
        case .idToken:
            return "urn:ietf:params:oauth:token-type:id_token"
        case .saml1:
            return "urn:ietf:params:oauth:token-type:saml1"
        case .saml2:
            return "urn:ietf:params:oauth:token-type:saml2"
        case .jwt:
            return "urn:ietf:params:oauth:token-type:jwt"
        case .custom(let value):
            return value
        }
    }

}

// TokenExchangeResponse has been consolidated into TokenResponse
// Use TokenResponse directly for token exchange operations

/// Request parameters for OAuth 2.0 Token Exchange (RFC 8693)
public struct TokenExchangeRequest: Sendable {
    /// The token being exchanged (required)
    public let subjectToken: String

    /// The type of the subject token (required)
    public let subjectTokenType: TokenType

    /// The type of token being requested (optional)
    public let requestedTokenType: TokenType?

    /// The target resource for the token (optional)
    public let resource: [String]?

    /// The logical name of the target service (optional)
    public let audience: [String]?

    /// The requested scope (optional)
    public let scope: [String]?

    /// Token representing the acting party (optional)
    public let actorToken: String?

    /// The type of the actor token (optional)
    public let actorTokenType: TokenType?

    /// Initialize a new token exchange request
    public init(
        subjectToken: String,
        subjectTokenType: TokenType,
        requestedTokenType: TokenType? = nil,
        resource: [String]? = nil,
        audience: [String]? = nil,
        scope: [String]? = nil,
        actorToken: String? = nil,
        actorTokenType: TokenType? = nil
    ) {
        self.subjectToken = subjectToken
        self.subjectTokenType = subjectTokenType
        self.requestedTokenType = requestedTokenType
        self.resource = resource
        self.audience = audience
        self.scope = scope
        self.actorToken = actorToken
        self.actorTokenType = actorTokenType
    }

    /// Convert to form parameters for HTTP request
    internal func toParameters() -> [String: String] {
        var parameters: [String: String] = [:]

        // Required parameters
        parameters["grant_type"] = "urn:ietf:params:oauth:grant-type:token-exchange"
        parameters["subject_token"] = subjectToken
        parameters["subject_token_type"] = subjectTokenType.rawValue

        // Optional parameters
        if let requestedTokenType = requestedTokenType {
            parameters["requested_token_type"] = requestedTokenType.rawValue
        }

        if let resource = resource, !resource.isEmpty {
            parameters["resource"] = resource.joined(separator: " ")
        }

        if let audience = audience, !audience.isEmpty {
            parameters["audience"] = audience.joined(separator: " ")
        }

        if let scope = scope, !scope.isEmpty {
            parameters["scope"] = scope.joined(separator: " ")
        }

        if let actorToken = actorToken {
            parameters["actor_token"] = actorToken
        }

        if let actorTokenType = actorTokenType {
            parameters["actor_token_type"] = actorTokenType.rawValue
        }

        return parameters
    }
}
