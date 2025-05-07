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
import Testing

@testable import OAuthKit

@Suite("Token Response Tests")
struct TokenResponseTests {
    @Test("Token Creation")
    func testTokenCreation() {
        let tokenResponse = TokenResponse(
            accessToken: "test-access-token",
            tokenType: "Bearer",
            expiresIn: 3600,
            refreshToken: "test-refresh-token",
            scope: "test-scope",
            idToken: "test-id-token",
            createdAt: Date()
        )

        #expect(tokenResponse.accessToken == "test-access-token")
        #expect(tokenResponse.tokenType == "Bearer")
        #expect(tokenResponse.expiresIn == 3600)
        #expect(tokenResponse.refreshToken == "test-refresh-token")
        #expect(tokenResponse.scope == "test-scope")
        #expect(tokenResponse.idToken == "test-id-token")
    }

    @Test("Token Expiration")
    func testTokenExpiration() {
        let now = Date()

        // Create an unexpired token (1 hour expiry)
        let validToken = TokenResponse(
            accessToken: "test-access-token",
            tokenType: "Bearer",
            expiresIn: 3600,
            refreshToken: "test-refresh-token",
            scope: "test-scope",
            idToken: nil,
            createdAt: now
        )

        #expect(!validToken.isExpired())
        #expect(!validToken.isExpired(buffer: 0))

        // Create a token that is about to expire (30 seconds left)
        let almostExpiredToken = TokenResponse(
            accessToken: "test-access-token",
            tokenType: "Bearer",
            expiresIn: 30,
            refreshToken: "test-refresh-token",
            scope: "test-scope",
            idToken: nil,
            createdAt: now
        )

        // Should be expired with a 60-second buffer (default)
        #expect(almostExpiredToken.isExpired())
        // But not expired with no buffer
        #expect(!almostExpiredToken.isExpired(buffer: 0))

        // Create a token with no expiration
        let noExpirationToken = TokenResponse(
            accessToken: "test-access-token",
            tokenType: "Bearer",
            expiresIn: nil,
            refreshToken: "test-refresh-token",
            scope: "test-scope",
            idToken: nil,
            createdAt: now
        )

        #expect(!noExpirationToken.isExpired())
    }

    @Test("Token Deserialization")
    func testTokenDeserialization() throws {
        let json = """
            {
                "access_token": "test-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "test-refresh-token",
                "scope": "test-scope",
                "id_token": "test-id-token"
            }
            """

        let jsonData = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let tokenResponse = try decoder.decode(TokenResponse.self, from: jsonData)

        #expect(tokenResponse.accessToken == "test-access-token")
        #expect(tokenResponse.tokenType == "Bearer")
        #expect(tokenResponse.expiresIn == 3600)
        #expect(tokenResponse.refreshToken == "test-refresh-token")
        #expect(tokenResponse.scope == "test-scope")
        #expect(tokenResponse.idToken == "test-id-token")
    }

    @Test("Partial Token Deserialization")
    func testPartialTokenDeserialization() throws {
        let json = """
            {
                "access_token": "test-access-token",
                "token_type": "Bearer"
            }
            """

        let jsonData = json.data(using: .utf8)!
        let decoder = JSONDecoder()
        let tokenResponse = try decoder.decode(TokenResponse.self, from: jsonData)

        #expect(tokenResponse.accessToken == "test-access-token")
        #expect(tokenResponse.tokenType == "Bearer")
        #expect(tokenResponse.expiresIn == nil)
        #expect(tokenResponse.refreshToken == nil)
        #expect(tokenResponse.scope == nil)
        #expect(tokenResponse.idToken == nil)
    }
}
