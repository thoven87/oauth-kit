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
import JWTKit

/// Token introspection response as defined in RFC 7662 using JWT-Kit claims
public struct TokenIntrospectionResponse: JWTPayload {
    /// Whether the token is active
    public let active: BoolClaim

    /// The scope associated with the token
    public let scope: StringClaim?

    /// The client identifier for the OAuth 2.0 client that requested this token
    public let clientID: StringClaim?

    /// The username of the resource owner who authorized this token
    public let username: StringClaim?

    /// The token type (e.g., "Bearer")
    public let tokenType: StringClaim?

    /// The expiration time with built-in validation
    public let exp: ExpirationClaim?

    /// The time when the token was issued with built-in validation
    public let iat: IssuedAtClaim?

    /// The time before which the token must not be accepted with built-in validation
    public let nbf: NotBeforeClaim?

    /// The subject of the token - usually the user identifier
    public let sub: SubjectClaim?

    /// The intended audience for this token with validation support
    public let aud: AudienceClaim?

    /// The issuer of this token
    public let iss: IssuerClaim?

    /// The unique identifier for this token
    public let jti: IDClaim?

    /// Initialize a token introspection response
    public init(
        active: Bool,
        scope: String? = nil,
        clientID: String? = nil,
        username: String? = nil,
        tokenType: String? = nil,
        exp: Date? = nil,
        iat: Date? = nil,
        nbf: Date? = nil,
        sub: String? = nil,
        aud: [String]? = nil,
        iss: String? = nil,
        jti: String? = nil
    ) {
        self.active = BoolClaim(value: active)
        self.scope = scope.map { StringClaim(value: $0) }
        self.clientID = clientID.map { StringClaim(value: $0) }
        self.username = username.map { StringClaim(value: $0) }
        self.tokenType = tokenType.map { StringClaim(value: $0) }
        self.exp = exp.map { ExpirationClaim(value: $0) }
        self.iat = iat.map { IssuedAtClaim(value: $0) }
        self.nbf = nbf.map { NotBeforeClaim(value: $0) }
        self.sub = sub.map { SubjectClaim(value: $0) }
        self.aud = aud.map { AudienceClaim(value: $0) }
        self.iss = iss.map { IssuerClaim(value: $0) }
        self.jti = jti.map { IDClaim(value: $0) }
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

    /// JWT validation - verifies token claims
    public func verify(using algorithm: some JWTAlgorithm) async throws {
        // Verify expiration if present
        try exp?.verifyNotExpired()

        // Verify not-before if present
        if let nbf = nbf {
            try nbf.verifyNotBefore()
        }
    }

    /// Check if the token is expired with buffer time
    /// - Parameter buffer: Buffer time in seconds before actual expiration to consider the token expired
    /// - Returns: True if the token is expired or will expire within the buffer time
    public func isExpired(buffer: TimeInterval = 60) -> Bool {
        guard let exp = exp else {
            return false
        }

        let bufferDate = Date().addingTimeInterval(buffer)
        return bufferDate >= exp.value
    }

    /// Check if the token is not yet valid
    /// - Returns: True if the token should not be accepted yet (nbf claim)
    public func isNotYetValid() -> Bool {
        guard let nbf = nbf else {
            return false
        }

        return Date() < nbf.value
    }

    /// Get expiration date if available
    public var expirationDate: Date? {
        exp?.value
    }

    /// Get issued at date if available
    public var issuedAtDate: Date? {
        iat?.value
    }

    /// Get not before date if available
    public var notBeforeDate: Date? {
        nbf?.value
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
