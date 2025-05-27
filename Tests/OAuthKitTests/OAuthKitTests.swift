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
import Testing

@testable import OAuthKit

@Suite("OAuthKit Core Tests")
struct OAuthKitTests {
    static let logger = Logger(label: "OAuthKitTests")
    let oauthKit = OAuthKit(httpClient: .shared, logger: logger)

    @Test("OAuth2 Client Creation")
    func testOAuth2ClientCreation() {
        let client = oauthKit.oauth2Client(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            tokenEndpoint: "https://example.com/token",
            authorizationEndpoint: "https://example.com/authorize",
            redirectURI: "https://example.com/callback",
            scopes: ["test-scope"]
        )

        #expect(client.clientID == "test-client-id")
        #expect(client.clientSecret == "test-client-secret")
        #expect(client.tokenEndpoint == "https://example.com/token")
        #expect(client.authorizationEndpoint == "https://example.com/authorize")
        #expect(client.redirectURI == "https://example.com/callback")
        #expect(client.scopes.contains("test-scope"))
    }

    @Test("PKCE Generation")
    func testPKCEGeneration() {
        let (verifier, challenge) = OAuth2Client.generatePKCE()

        #expect(verifier.count == 64)
        #expect(!challenge.isEmpty)
        #expect(verifier != challenge)
    }

    @Test("Authorization URL Generation")
    func testAuthorizationURLGeneration() throws {
        let client = oauthKit.oauth2Client(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            tokenEndpoint: "https://example.com/token",
            authorizationEndpoint: "https://example.com/authorize",
            redirectURI: "https://example.com/callback",
            scopes: ["test-scope"]
        )

        let url = try client.authorizationURL(state: "test-state")
        let components = URLComponents(url: url, resolvingAgainstBaseURL: false)!

        #expect(components.scheme == "https")
        #expect(components.host == "example.com")
        #expect(components.path == "/authorize")

        let queryItems = components.queryItems ?? []
        #expect(queryItems.contains(URLQueryItem(name: "client_id", value: "test-client-id")))
        #expect(queryItems.contains(URLQueryItem(name: "redirect_uri", value: "https://example.com/callback")))
        #expect(queryItems.contains(URLQueryItem(name: "response_type", value: "code")))
        #expect(queryItems.contains(URLQueryItem(name: "scope", value: "test-scope")))
        #expect(queryItems.contains(URLQueryItem(name: "state", value: "test-state")))
    }
}
