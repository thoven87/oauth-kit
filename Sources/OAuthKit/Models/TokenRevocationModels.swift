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

/// Token revocation request parameters as defined in RFC 7009
public struct TokenRevocationRequest: Sendable {
    /// The token to revoke (required)
    public let token: String

    /// A hint about the type of token being revoked (optional)
    /// Common values: "access_token", "refresh_token"
    public let tokenTypeHint: String?

    /// Initialize a token revocation request
    /// - Parameters:
    ///   - token: The token to revoke
    ///   - tokenTypeHint: A hint about the type of token being revoked
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

/// Token revocation response
/// RFC 7009 specifies that successful revocation returns HTTP 200 with no content
/// or an empty JSON object. Errors may return error codes.
public struct TokenRevocationResponse: Codable, Sendable {
    /// Whether the revocation was successful
    public let success: Bool

    /// Error code if revocation failed (optional)
    public let error: String?

    /// Error description if revocation failed (optional)
    public let errorDescription: String?

    /// Error URI for more information (optional)
    public let errorURI: String?

    /// Initialize a token revocation response
    /// - Parameters:
    ///   - success: Whether the revocation was successful
    ///   - error: Error code if revocation failed
    ///   - errorDescription: Error description if revocation failed
    ///   - errorURI: Error URI for more information
    public init(
        success: Bool,
        error: String? = nil,
        errorDescription: String? = nil,
        errorURI: String? = nil
    ) {
        self.success = success
        self.error = error
        self.errorDescription = errorDescription
        self.errorURI = errorURI
    }

    /// Coding keys for mapping JSON fields to properties
    enum CodingKeys: String, CodingKey {
        case error
        case errorDescription = "error_description"
        case errorURI = "error_uri"
    }

    /// Initialize from decoder
    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        error = try container.decodeIfPresent(String.self, forKey: .error)
        errorDescription = try container.decodeIfPresent(String.self, forKey: .errorDescription)
        errorURI = try container.decodeIfPresent(String.self, forKey: .errorURI)

        // Success is determined by absence of error
        success = error == nil
    }

    /// Encode to encoder
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        if let error = error {
            try container.encode(error, forKey: .error)
        }

        if let errorDescription = errorDescription {
            try container.encode(errorDescription, forKey: .errorDescription)
        }

        if let errorURI = errorURI {
            try container.encode(errorURI, forKey: .errorURI)
        }
    }

    /// Create a successful revocation response
    public static func success() -> TokenRevocationResponse {
        TokenRevocationResponse(success: true)
    }

    /// Create a failed revocation response
    public static func failure(
        error: String,
        description: String? = nil,
        uri: String? = nil
    ) -> TokenRevocationResponse {
        TokenRevocationResponse(
            success: false,
            error: error,
            errorDescription: description,
            errorURI: uri
        )
    }
}

/// Token type hint constants for revocation requests
public enum TokenRevocationHint {
    /// Access token hint
    public static let accessToken = "access_token"

    /// Refresh token hint
    public static let refreshToken = "refresh_token"
}
