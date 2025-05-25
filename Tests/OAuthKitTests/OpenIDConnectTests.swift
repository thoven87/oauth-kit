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
    var httpClient = HTTPClient.shared
    var logger: Logger = Logger(label: "OpenIDConnectTests")
    var oauthKit: OAuthKit = OAuthKit(httpClient: HTTPClient.shared, logger: Logger(label: "OAuthKitTest"))

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
        #expect(config.scopesSupported == ["openid", "profile", "email"])
        #expect(config.responseTypesSupported == ["code"])
        #expect(config.grantTypesSupported == ["authorization_code", "refresh_token"])
        #expect(config.subjectTypesSupported == ["public"])
        #expect(config.idTokenSigningAlgValuesSupported == ["RS256"])
        #expect(config.issuer == "https://example.com")
        #expect(config.endSessionEndpoint == "https://example.com/logout")
        #expect(config.introspectionEndpoint == "https://example.com/introspect")
        #expect(config.revocationEndpoint == "https://example.com/revoke")
    }

    @Test("Create OpenID Connect Client")
    func testCreateOpenIDConnectClient() async throws {
        // Wait for Keycloak to be ready before proceeding
        await waitForKeycloakReadiness()

        let client = try await OpenIDConnectClient(
            httpClient: httpClient,
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
            scope: "openid profile email",
            logger: logger
        )

        #expect(client.clientID == clientID)
        #expect(client.clientSecret == clientSecret)
        #expect(client.redirectURI == "https://example.com/callback")
        #expect(client.scope == "openid profile email")
        #expect(client.configuration.authorizationEndpoint == "\(keycloakURL)/realms/test/protocol/openid-connect/auth")
        #expect(client.configuration.tokenEndpoint == "\(keycloakURL)/realms/test/protocol/openid-connect/token")
    }

    @Test("Get user info")
    func testCreateOpenIDConnectClientWithCustomLogger() async throws {
        // Wait for Keycloak to be ready before proceeding
        await waitForKeycloakReadiness()

        let client = try await oauthKit.openIDConnectClient(
            discoveryURL: "\(keycloakURL)/realms/test",
            clientID: clientID,
            clientSecret: clientSecret,
            redirectURI: "http://localhost:5555/callback"
        )

        let result = try client.authorizationURL(state: "hbkfjksdfhjksdfhjksdf")

        #expect(result.absoluteString.contains("state=hbkfjksdfhjksdfhjksdf"))

        //        let validatedToken = try await client.validateIDToken(
        //            "eyJhbGciOiJSUzI1NiIsImtpZCI6ImI3YmNlM2Y5MGY2NzljMzE5NTViN2RlN2EzZmQ5OGUyMmUyODdkZjMifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU1NTYvZGV4Iiwic3ViIjoiQ2cwd0xUTTROUzB5T0RBNE9TMHdFZ1J0YjJOciIsImF1ZCI6ImV4YW1wbGUtYXBwIiwiZXhwIjoxNzQ2NzI0MjgxLCJpYXQiOjE3NDY2Mzc4ODEsImF0X2hhc2giOiI2N1NZMmF5WmNiX0FOVmZJTEJuSUdnIiwiY19oYXNoIjoiV1FvWjBqSEhKOFJnZ1QzLU0wbUlMUSIsImVtYWlsIjoia2lsZ29yZUBraWxnb3JlLnRyb3V0IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJLaWxnb3JlIFRyb3V0In0.gBQpgE3aZwgy6fnk7vkj6MMUbZDo8_L1Kc-_Ga9kWrYPmbf6Y8hmjtf0jNAFrwBpDtKPMCNGU8TznaoUJwC20VPvrf_nXQk2v4L7BEksBgIcL-sAhtvrT_eRuQ_hsW73iweCQezxvCDr41Pcmz_1T14dEjOL7oiWKzXn-gZn0EwNK627tsACwL-vhE0NZ450m_XBdv-Vn7X1iPvJT8d70gUsMEEEt-tUrzaHFG1sp9hqopaBu9oMfF7-M1GSAfFvyNoAxjP4ZYi-HpHs9GtUI6NNMh5yxxflwtQ99c7XCcRGIBuduBffM_zAjQR3jrVWsS5raTbDXX2AE4s72sa1TA"
        //        )
        //
        //        logger.info("Valida: \(validatedToken)")

        //logger.info("result: \(result)")
        //        let pp = try await client.exchangeCode(code: "beqzprpcyus434fxvwoegfm25", additionalParameters: ["state": "son"])

        //let idToken = client.validateIDToken(pp.tokenResponse.accessToken)

        //logger.info("exchange code: \(pp)")

        //        let userInfo: UserInfo = try await client.getUserInfo(
        //            accessToken:
        //                "eyJhbGciOiJSUzI1NiIsImtpZCI6ImI3YmNlM2Y5MGY2NzljMzE5NTViN2RlN2EzZmQ5OGUyMmUyODdkZjMifQ.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjU1NTYvZGV4Iiwic3ViIjoiQ2cwd0xUTTROUzB5T0RBNE9TMHdFZ1J0YjJOciIsImF1ZCI6ImV4YW1wbGUtYXBwIiwiZXhwIjoxNzQ2NzI0MjgxLCJpYXQiOjE3NDY2Mzc4ODEsImF0X2hhc2giOiJZV1pDMU01aFIwZmhtZVprendZZkRnIiwiZW1haWwiOiJraWxnb3JlQGtpbGdvcmUudHJvdXQiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IktpbGdvcmUgVHJvdXQifQ.DxSh9SVuc8rsXS4V7Z1H46ecyq7Ryb7shkZ8LnilDUADjfrykTyIJ80IzlTOBjOEDddwnlDpBZaguFZP5lLpoPMBMF6mbSZR4JKmppM2jVcXGHpKn0ZTWAZ67Yx0VP4Af1nyCfsNi88GgL2n7pNIWvTrUXFAL0Z8dIo0mB-no3GHY9pFMF__EgBcykTRllKbIud15Rk2jd1v6dQS77cTB-78W0nY3JB8gEm2Vhl9F9FxisA_9RDnmoiNQwo2z5u35JUAtxitUzswlyLahQC3zX2i4iqLTN0VthTThL8E-td6eH3hROtSL8zh89r8s3nAwcLqOF58cjUW3Uu0NQhGIA"
        //        )
        //
        //        #expect(userInfo.email == "kilgore@kilgore.trout", "email not match")
        //
        //        logger.info("user info: \(userInfo)")
    }

    /// Helper function to wait for Keycloak to be ready
    private func waitForKeycloakReadiness() async {
        let maxAttempts = 30
        let delayBetweenAttempts: UInt64 = 1_000_000_000  // 1 second

        for attempt in 1...maxAttempts {
            do {
                var request = HTTPClientRequest(url: "\(keycloakURL)/realms/test/.well-known/openid-configuration")
                request.method = .GET
                request.headers.add(name: "Accept", value: "application/json")

                let response = try await httpClient.execute(request, timeout: .seconds(5))

                if response.status == .ok {
                    // Additional check for JWKS endpoint
                    var jwksRequest = HTTPClientRequest(url: "\(keycloakURL)/realms/test/protocol/openid-connect/certs")
                    jwksRequest.method = .GET
                    jwksRequest.headers.add(name: "Accept", value: "application/json")

                    let jwksResponse = try await httpClient.execute(jwksRequest, timeout: .seconds(5))
                    if jwksResponse.status == .ok {
                        logger.info("Keycloak is ready and JWKS endpoint is accessible")
                        return
                    }
                }

                if attempt == maxAttempts {
                    logger.error("Keycloak is not ready after \(maxAttempts) attempts")
                    return
                }

                logger.info("Keycloak not ready yet (attempt \(attempt)/\(maxAttempts)), waiting...")
                do {
                    try await Task.sleep(nanoseconds: delayBetweenAttempts)
                } catch {
                    logger.warning("Sleep interrupted: \(error)")
                }
            } catch {
                if attempt == maxAttempts {
                    logger.error("Failed to connect to Keycloak after \(maxAttempts) attempts: \(error)")
                    return
                }

                logger.info("Attempt \(attempt)/\(maxAttempts) failed: \(error), retrying...")
                do {
                    try await Task.sleep(nanoseconds: delayBetweenAttempts)
                } catch {
                    logger.warning("Sleep interrupted: \(error)")
                }
            }
        }
    }
}
