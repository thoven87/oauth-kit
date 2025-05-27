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
import JWTKit
import NIOFoundationCompat

/// Provider for Google OAuth2/OpenID Connect authentication
public struct GoogleOAuthProvider: Sendable {
    /// Google's OAuth2/OIDC discovery URL
    public static let discoveryURL = "https://accounts.google.com/"

    /// The OAuthKit instance
    private let oauthKit: OAuthKit

    /// The OpenID Connect client configured for Google
    private let client: OpenIDConnectClient

    /// Initialize a new Google OAuth provider
    /// - Parameter oauthKit: The OAuthKit instance
    /// - Parameter openIDConnectClient: An OpenID Connect client configured for Google
    public init(
        oauthKit: OAuthKit,
        openIDConnectClient client: OpenIDConnectClient
    ) {
        self.oauthKit = oauthKit
        self.client = client
    }

    /// Generate an authorization URL for Google Sign-In with recommended parameters
    /// - Parameters:
    ///   - state: An opaque value to maintain state between the request and callback
    ///   - prompt: Controls the Google Sign-In prompt behavior
    ///   - loginHint: Email address or sub identifier to pre-fill the authentication screen
    ///   - usePKCE: Whether to use PKCE (recommended and enabled by default)
    /// - Returns: A tuple containing the authorization URL and code verifier (for PKCE)
    public func signInURL(
        state: String? = nil,
        prompt: GooglePrompt? = nil,
        loginHint: String? = nil,
        usePKCE: Bool = true
    ) throws -> (url: URL, codeVerifier: String?) {
        var additionalParams: [String: String] = [:]
        var codeVerifier: String? = nil
        var codeChallenge: String? = nil

        // Generate PKCE if requested
        if usePKCE {
            let pkce = OAuth2Client.generatePKCE()
            codeVerifier = pkce.codeVerifier
            codeChallenge = pkce.codeChallenge
        }

        // Add Google-specific parameters
        if let prompt = prompt {
            additionalParams["prompt"] = prompt.rawValue
        }

        if let loginHint = loginHint {
            additionalParams["login_hint"] = loginHint
        }

        // Google recommends adding these parameters
        additionalParams["access_type"] = "offline"  // Request refresh token
        additionalParams["include_granted_scopes"] = "true"  // Request incremental authorization

        // Generate nonce for improved security
        let nonce = UUID().uuidString
        additionalParams["nonce"] = nonce

        let url = try client.authorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            additionalParameters: additionalParams
        )

        return (url, codeVerifier)
    }

    /// Exchange an authorization code for tokens with Google
    /// - Parameters:
    ///   - code: The authorization code received from Google
    ///   - codeVerifier: The PKCE code verifier used when generating the authorization URL
    /// - Returns: The token response and ID token claims
    public func exchangeCode(
        code: String,
        codeVerifier: String?
    ) async throws -> (tokenResponse: TokenResponse, claims: IDTokenClaims) {
        try await client.exchangeCode(
            code: code,
            codeVerifier: codeVerifier
        )
    }

    /// Retrieve the user's profile information from Google
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    /// - Returns: The user's Google profile information
    public func getUserProfile(
        accessToken: String
    ) async throws -> GoogleIdentityToken {
        let userInfo: GoogleIdentityToken = try await client.getUserInfo(accessToken: accessToken)
        return userInfo
    }
}

/// Google Sign-In prompt behavior
public enum GooglePrompt: String {
    /// Default behavior - shows the authentication page when necessary
    case none = "none"

    /// Always show the authentication page
    case consent = "consent"

    /// Always show the account selection page
    case selectAccount = "select_account"
}
