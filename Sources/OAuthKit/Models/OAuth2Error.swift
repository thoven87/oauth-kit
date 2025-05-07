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

/// Represents errors that can occur during OAuth2 operations
public enum OAuth2Error: Error, LocalizedError {
    /// Error during the authorization code flow
    case authorizationError(String)

    /// Error when exchanging a code for tokens
    case tokenExchangeError(String)

    /// Error when refreshing a token
    case tokenRefreshError(String)

    /// Error when validating a token
    case tokenValidationError(String)

    /// Error with client credentials
    case clientCredentialsError(String)

    /// Network or HTTP error
    case networkError(String)

    /// Error in the OAuth2 response
    case responseError(String)

    /// Error with the server configuration
    case configurationError(String)

    /// Error with JWKS handling
    case jwksError(String)

    /// Error in the OpenID configuration
    case openIDConfigError(String)

    /// Error in request
    case invalidRequest(String)

    /// Error in response
    case invalidResponse(String)

    /// Error from the OpenID server
    case serverError(String)

    /// Human-readable error description
    public var errorDescription: String? {
        switch self {
        case .authorizationError(let message):
            return "Authorization error: \(message)"
        case .tokenExchangeError(let message):
            return "Token exchange error: \(message)"
        case .tokenRefreshError(let message):
            return "Token refresh error: \(message)"
        case .tokenValidationError(let message):
            return "Token validation error: \(message)"
        case .clientCredentialsError(let message):
            return "Client credentials error: \(message)"
        case .networkError(let message):
            return "Network error: \(message)"
        case .responseError(let message):
            return "Response error: \(message)"
        case .configurationError(let message):
            return "Configuration error: \(message)"
        case .jwksError(let message):
            return "JWKS error: \(message)"
        case .openIDConfigError(let message):
            return "OpenID configuration error: \(message)"
        case .invalidRequest(let message):
            return "Invalid request: \(message)"
        case .invalidResponse(let message):
            return "Invalid response: \(message)"
        case .serverError(let message):
            return "Server error: \(message)"
        }
    }
}
