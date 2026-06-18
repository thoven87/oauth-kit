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

@Suite("OpenID Connect Tests")
struct OpenIDConnectTests {
    var logger: Logger = Logger(label: "OpenIDConnectTests")
    var oauthKit: OAuthClientFactory = OAuthClientFactory(httpClient: .shared, logger: Logger(label: "OAuthKitTest"))

    private let keycloakURL = ProcessInfo.processInfo.environment["KEYCLOAK_URL"] ?? "http://localhost:8080"
    private let redirectURI = "http://localhost:8080/callback"

    private let clientID = ProcessInfo.processInfo.environment["KEYCLOAK_CLIENT_ID"] ?? "example-app"
    private let clientSecret = ProcessInfo.processInfo.environment["KEYCLOAK_CLIENT_SECRET"] ?? "ZXhhbXBsZS1hcHAtc2VjcmV0"

    @Test("Address Claim Creation")
    func testAddressClaimCreation() {
        let address = IDTokenClaims.AddressClaim(
            formatted: "123 Main St, Anytown, CA 12345",
            streetAddress: "123 Main St",
            locality: "Anytown",
            region: "CA",
            postalCode: "12345",
            country: "US"
        )

        #expect(address.formatted == "123 Main St, Anytown, CA 12345")
        #expect(address.streetAddress == "123 Main St")
        #expect(address.locality == "Anytown")
        #expect(address.region == "CA")
        #expect(address.postalCode == "12345")
        #expect(address.country == "US")
    }

    @Test("OIDC Configuration Creation")
    func testOIDCConfigurationCreation() {
        let config = OpenIDConfiguration(
            authorizationEndpoint: "https://example.com/auth",
            tokenEndpoint: "https://example.com/token",
            userinfoEndpoint: "https://example.com/userinfo",
            jwksUri: "https://example.com/jwks",
            scopesSupported: ["openid", "profile", "email"],
            responseTypesSupported: ["code"],
            grantTypesSupported: ["authorization_code", "refresh_token"],
            subjectTypesSupported: ["public"],
            idTokenSigningAlgValuesSupported: ["RS256"],
            issuer: "https://example.com",
            endSessionEndpoint: "https://example.com/logout",
            introspectionEndpoint: "https://example.com/introspect",
            revocationEndpoint: "https://example.com/revoke"
        )

        #expect(config.authorizationEndpoint == "https://example.com/auth")
        #expect(config.tokenEndpoint == "https://example.com/token")
        #expect(config.userinfoEndpoint == "https://example.com/userinfo")
        #expect(config.jwksUri == "https://example.com/jwks")
        #expect(config.scopesSupported == Optional(["openid", "profile", "email"]))
        #expect(config.responseTypesSupported == ["code"])
        #expect(config.grantTypesSupported == Optional(["authorization_code", "refresh_token"]))
        #expect(config.subjectTypesSupported == ["public"])
        #expect(config.idTokenSigningAlgValuesSupported == ["RS256"])
        #expect(config.issuer == "https://example.com")
        #expect(config.endSessionEndpoint == "https://example.com/logout")
        #expect(config.introspectionEndpoint == "https://example.com/introspect")
        #expect(config.revocationEndpoint == "https://example.com/revoke")
    }

    @Test("Create OpenID Connect Client")
    func testCreateOpenIDConnectClient() {
        let keyManager = JWKSKeyManager()
        let client = OpenIDConnectClient(
            httpClient: .shared,
            clientID: clientID,
            clientSecret: clientSecret,
            configuration: OpenIDConfiguration(
                authorizationEndpoint: "\(keycloakURL)/realms/test/protocol/openid-connect/auth",
                tokenEndpoint: "\(keycloakURL)/realms/test/protocol/openid-connect/token",
                userinfoEndpoint: "\(keycloakURL)/realms/test/protocol/openid-connect/userinfo",
                jwksUri: "\(keycloakURL)/realms/test/protocol/openid-connect/certs",
                scopesSupported: ["openid", "profile", "email"],
                responseTypesSupported: ["code"],
                grantTypesSupported: ["authorization_code", "refresh_token"],
                subjectTypesSupported: ["public"],
                idTokenSigningAlgValuesSupported: ["RS256"],
                issuer: "\(keycloakURL)/realms/test",
                endSessionEndpoint: nil,
                introspectionEndpoint: nil,
                revocationEndpoint: nil
            ),
            redirectURI: "https://example.com/callback",
            keyManager: keyManager,
            logger: logger
        )

        #expect(client.clientID == clientID)
        #expect(client.clientSecret == clientSecret)
        #expect(client.redirectURI == "https://example.com/callback")
        #expect(client.configuration.authorizationEndpoint == "\(keycloakURL)/realms/test/protocol/openid-connect/auth")
        #expect(client.configuration.tokenEndpoint == "\(keycloakURL)/realms/test/protocol/openid-connect/token")
    }

    @Test("Get user info")
    func testCreateOpenIDConnectClientWithCustomLogger() async throws {
        let client = try await oauthKit.openIDConnectClient(
            discoveryURL: "\(keycloakURL)/realms/test",
            clientID: clientID,
            clientSecret: clientSecret,
            redirectURI: "http://localhost:5555/callback"
        )

        let result = try client.generateAuthorizationURL(
            state: "hbkfjksdfhjksdfhjksdf",
            scopes: ["openid", "profile", "email"]
        )

        #expect(result.absoluteString.contains("state=hbkfjksdfhjksdfhjksdf"))
    }
}
