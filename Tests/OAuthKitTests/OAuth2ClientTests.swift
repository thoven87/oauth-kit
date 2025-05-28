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
import Logging
import Testing

@testable import OAuthKit

@Suite("OAuth2 Client Tests")
struct OAuth2ClientTests {
    let logger = Logger(label: "OAuth2ClientTests")

    @Test("Client Creation")
    func testClientCreation() {
        let client = OAuth2Client(
            httpClient: .shared,
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            tokenEndpoint: "https://example.com/token",
            authorizationEndpoint: "https://example.com/auth",
            redirectURI: "https://example.com/callback",
            logger: logger
        )

        #expect(client.clientID == "test-client-id")
        #expect(client.clientSecret == "test-client-secret")
        #expect(client.tokenEndpoint == "https://example.com/token")
        #expect(client.authorizationEndpoint == "https://example.com/auth")
        #expect(client.redirectURI == "https://example.com/callback")
    }

    @Test("Authorization URL Generation")
    func testAuthorizationURLGeneration() throws {
        let client = OAuth2Client(
            httpClient: .shared,
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            tokenEndpoint: "https://example.com/token",
            authorizationEndpoint: "https://example.com/auth",
            redirectURI: "https://example.com/callback",
            logger: logger
        )

        // Basic URL
        let basicURL = try client.generateAuthorizationURL(
            state: nil,
            codeChallenge: nil,
            additionalParameters: [:],
            scopes: ["test-scope"]
        )
        #expect(basicURL.absoluteString.hasPrefix("https://example.com/auth?"))
        #expect(basicURL.absoluteString.contains("client_id=test-client-id"))
        #expect(basicURL.absoluteString.contains("redirect_uri=https://example.com/callback"))
        #expect(basicURL.absoluteString.contains("response_type=code"))
        #expect(basicURL.absoluteString.contains("scope=test-scope"))

        // URL with state
        let stateURL = try client.generateAuthorizationURL(
            state: "test-state",
            codeChallenge: nil,
            additionalParameters: [:],
            scopes: []
        )
        #expect(stateURL.absoluteString.contains("state=test-state"))

        // URL with PKCE
        let pkceURL = try client.generateAuthorizationURL(
            state: nil,
            codeChallenge: "test-challenge",
            additionalParameters: [:],
            scopes: ["test-scope"]
        )
        #expect(pkceURL.absoluteString.contains("code_challenge=test-challenge"))
        #expect(pkceURL.absoluteString.contains("code_challenge_method=S256"))

        // URL with additional parameters
        let additionalParamsURL = try client.generateAuthorizationURL(
            state: nil,
            codeChallenge: nil,
            additionalParameters: ["foo": "bar"],
            scopes: ["test-scope"]
        )
        #expect(additionalParamsURL.absoluteString.contains("foo=bar"))
    }

    @Test("PKCE Generation")
    func testPKCEGeneration() {
        let (verifier, challenge) = OAuth2Client.generatePKCE()

        #expect(verifier.count == 64)
        #expect(!challenge.isEmpty)
        #expect(verifier != challenge)
    }

    @Test("Invalid Authorization Endpoint")
    func testInvalidAuthorizationEndpoint() {
        let client = OAuth2Client(
            httpClient: .shared,
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            tokenEndpoint: "https://example.com/token",
            authorizationEndpoint: nil,
            redirectURI: "https://example.com/callback",
            logger: logger
        )

        do {
            _ = try client.generateAuthorizationURL(
                state: nil,
                codeChallenge: nil,
                additionalParameters: [:],
                scopes: []
            )
            #expect(Bool(false), "Expected error not thrown")
        } catch let error as OAuth2Error {
            switch error {
            case .configurationError(let message):
                #expect(message.contains("Authorization endpoint is required"))
            default:
                #expect(Bool(false), "Unexpected OAuth2Error type: \(error)")
            }
        } catch {
            #expect(Bool(false), "Unexpected error type: \(error)")
        }
    }
}
