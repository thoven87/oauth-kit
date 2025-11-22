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
import NIOFoundationCompat
import Testing

@testable import OAuthKit

@Suite("RFC Implementation Tests")
struct RFCImplementationTests {

    // MARK: - Token Exchange (RFC 8693) Tests

    @Suite("Token Exchange (RFC 8693)")
    struct TokenExchangeTests {

        @Test("TokenType enum handles standard types correctly")
        func testTokenTypeEnum() {
            #expect(TokenType.accessToken.rawValue == "urn:ietf:params:oauth:token-type:access_token")
            #expect(TokenType.refreshToken.rawValue == "urn:ietf:params:oauth:token-type:refresh_token")
            #expect(TokenType.idToken.rawValue == "urn:ietf:params:oauth:token-type:id_token")
            #expect(TokenType.jwt.rawValue == "urn:ietf:params:oauth:token-type:jwt")
            #expect(TokenType.saml1.rawValue == "urn:ietf:params:oauth:token-type:saml1")
            #expect(TokenType.saml2.rawValue == "urn:ietf:params:oauth:token-type:saml2")
        }

        @Test("TokenType handles custom types")
        func testTokenTypeCustom() {
            let customType = TokenType.custom("custom:token:type")
            #expect(customType.rawValue == "custom:token:type")
        }

        @Test("TokenType encoding and decoding")
        func testTokenTypeCodable() throws {
            let accessToken = TokenType.accessToken
            let encoded = try JSONEncoder().encode(accessToken)
            let decoded = try JSONDecoder().decode(TokenType.self, from: encoded)
            #expect(decoded == accessToken)

            let customType = TokenType.custom("custom:type")
            let encodedCustom = try JSONEncoder().encode(customType)
            let decodedCustom = try JSONDecoder().decode(TokenType.self, from: encodedCustom)
            #expect(decodedCustom.rawValue == "custom:type")
        }

        @Test("TokenExchangeRequest parameter conversion")
        func testTokenExchangeRequestParameters() {
            let request = TokenExchangeRequest(
                subjectToken: "subject_token_value",
                subjectTokenType: .accessToken,
                requestedTokenType: .refreshToken,
                resource: ["https://api.example.com"],
                audience: ["https://service.example.com"],
                scope: ["read", "write"],
                actorToken: "actor_token_value",
                actorTokenType: .jwt
            )

            let parameters = request.toParameters()

            #expect(parameters["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange")
            #expect(parameters["subject_token"] == "subject_token_value")
            #expect(parameters["subject_token_type"] == "urn:ietf:params:oauth:token-type:access_token")
            #expect(parameters["requested_token_type"] == "urn:ietf:params:oauth:token-type:refresh_token")
            #expect(parameters["resource"] == "https://api.example.com")
            #expect(parameters["audience"] == "https://service.example.com")
            #expect(parameters["scope"] == "read write")
            #expect(parameters["actor_token"] == "actor_token_value")
            #expect(parameters["actor_token_type"] == "urn:ietf:params:oauth:token-type:jwt")
        }

        @Test("TokenExchangeResponse decoding")
        func testTokenExchangeResponseDecoding() throws {
            let json = """
                {
                    "access_token": "new_access_token",
                    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "read write"
                }
                """

            let data = json.data(using: .utf8)!
            let response = try JSONDecoder().decode(TokenResponse.self, from: data)

            #expect(response.accessToken == "new_access_token")
            #expect(response.issuedTokenType == .accessToken)
            #expect(response.tokenType == "Bearer")
            #expect(response.expiresIn == 3600)
            #expect(response.scope == "read write")
        }

        @Test("TokenResponse expiration check with issued token type")
        func testTokenResponseExpirationWithIssuedType() {
            let expiredResponse = TokenResponse(
                accessToken: "token",
                tokenType: "Bearer",
                expiresIn: -1,
                issuedTokenType: .accessToken,
                createdAt: Date().addingTimeInterval(-3600)
            )

            #expect(expiredResponse.isExpired())

            let validResponse = TokenResponse(
                accessToken: "token",
                tokenType: "Bearer",
                expiresIn: 3600,
                issuedTokenType: .accessToken,
                createdAt: Date()
            )

            #expect(!validResponse.isExpired())
        }

        @Test("TokenResponse with issued token type")
        func testTokenResponseWithIssuedTokenType() {
            let tokenResponse = TokenResponse(
                accessToken: "access_token",
                tokenType: "Bearer",
                expiresIn: 3600,
                refreshToken: "refresh_token",
                scope: "read write",
                issuedTokenType: .accessToken
            )

            #expect(tokenResponse.accessToken == "access_token")
            #expect(tokenResponse.tokenType == "Bearer")
            #expect(tokenResponse.expiresIn == 3600)
            #expect(tokenResponse.scope == "read write")
            #expect(tokenResponse.refreshToken == "refresh_token")
            #expect(tokenResponse.issuedTokenType == .accessToken)
        }
    }

    // MARK: - Token Introspection (RFC 7662) Tests

    @Suite("Token Introspection (RFC 7662)")
    struct TokenIntrospectionTests {

        @Test("TokenIntrospectionRequest parameter conversion")
        func testTokenIntrospectionRequestParameters() {
            let request = TokenIntrospectionRequest(
                token: "test_token",
                tokenTypeHint: "access_token"
            )

            let parameters = request.toParameters()

            #expect(parameters["token"] == "test_token")
            #expect(parameters["token_type_hint"] == "access_token")
        }

        @Test("TokenIntrospectionRequest without hint")
        func testTokenIntrospectionRequestWithoutHint() {
            let request = TokenIntrospectionRequest(token: "test_token")
            let parameters = request.toParameters()

            #expect(parameters["token"] == "test_token")
            #expect(parameters["token_type_hint"] == nil)
        }

        @Test("TokenIntrospectionResponse decoding with all fields")
        func testTokenIntrospectionResponseDecoding() throws {
            let json = """
                {
                    "active": true,
                    "scope": "read write",
                    "client_id": "client123",
                    "username": "user@example.com",
                    "token_type": "Bearer",
                    "exp": 1640995200,
                    "iat": 1640991600,
                    "nbf": 1640991600,
                    "sub": "user123",
                    "aud": ["https://api.example.com", "https://service.example.com"],
                    "iss": "https://auth.example.com",
                    "jti": "token123",
                    "custom_claim": "custom_value"
                }
                """

            let data = json.data(using: .utf8)!
            let response = try JSONDecoder().decode(TokenIntrospectionResponse.self, from: data)

            #expect(response.active == true)
            #expect(response.scope == "read write")
            #expect(response.clientID == "client123")
            #expect(response.username == "user@example.com")
            #expect(response.tokenType == "Bearer")
            #expect(response.exp == 1_640_995_200)
            #expect(response.iat == 1_640_991_600)
            #expect(response.nbf == 1_640_991_600)
            #expect(response.sub == "user123")
            #expect(response.aud == ["https://api.example.com", "https://service.example.com"])
            #expect(response.iss == "https://auth.example.com")
            #expect(response.jti == "token123")
            #expect(response.additionalClaims?["custom_claim"] != nil)
        }

        @Test("TokenIntrospectionResponse inactive token")
        func testTokenIntrospectionResponseInactive() throws {
            let json = """
                {
                    "active": false
                }
                """

            let data = json.data(using: .utf8)!
            let response = try JSONDecoder().decode(TokenIntrospectionResponse.self, from: data)

            #expect(response.active == false)
            #expect(response.scope == nil)
            #expect(response.clientID == nil)
        }

        @Test("TokenIntrospectionResponse audience as string")
        func testTokenIntrospectionResponseAudienceString() throws {
            let json = """
                {
                    "active": true,
                    "aud": "https://api.example.com"
                }
                """

            let data = json.data(using: .utf8)!
            let response = try JSONDecoder().decode(TokenIntrospectionResponse.self, from: data)

            #expect(response.active == true)
            #expect(response.aud == ["https://api.example.com"])
        }

        @Test("TokenIntrospectionResponse expiration checks")
        func testTokenIntrospectionResponseExpirationChecks() {
            let currentTime = Date().timeIntervalSince1970

            let expiredResponse = TokenIntrospectionResponse(
                active: true,
                exp: Int(currentTime - 3600)  // Expired 1 hour ago
            )
            #expect(expiredResponse.isExpired())

            let validResponse = TokenIntrospectionResponse(
                active: true,
                exp: Int(currentTime + 3600)  // Expires in 1 hour
            )
            #expect(!validResponse.isExpired())

            let notYetValidResponse = TokenIntrospectionResponse(
                active: true,
                nbf: Int(currentTime + 3600)  // Valid starting in 1 hour
            )
            #expect(notYetValidResponse.isNotYetValid())
        }

        @Test("TokenIntrospectionResponse date properties")
        func testTokenIntrospectionResponseDateProperties() {
            let exp = 1_640_995_200
            let iat = 1_640_991_600
            let nbf = 1_640_991_600

            let response = TokenIntrospectionResponse(
                active: true,
                exp: exp,
                iat: iat,
                nbf: nbf
            )

            #expect(response.expirationDate == Date(timeIntervalSince1970: TimeInterval(exp)))
            #expect(response.issuedAtDate == Date(timeIntervalSince1970: TimeInterval(iat)))
            #expect(response.notBeforeDate == Date(timeIntervalSince1970: TimeInterval(nbf)))
        }
    }

    // MARK: - Token Revocation (RFC 7009) Tests

    @Suite("Token Revocation (RFC 7009)")
    struct TokenRevocationTests {

        @Test("TokenRevocationRequest parameter conversion")
        func testTokenRevocationRequestParameters() {
            let request = TokenRevocationRequest(
                token: "test_token",
                tokenTypeHint: "access_token"
            )

            let parameters = request.toParameters()

            #expect(parameters["token"] == "test_token")
            #expect(parameters["token_type_hint"] == "access_token")
        }

        @Test("TokenRevocationRequest without hint")
        func testTokenRevocationRequestWithoutHint() {
            let request = TokenRevocationRequest(token: "test_token")
            let parameters = request.toParameters()

            #expect(parameters["token"] == "test_token")
            #expect(parameters["token_type_hint"] == nil)
        }

        @Test("TokenRevocationResponse success")
        func testTokenRevocationResponseSuccess() {
            let successResponse = TokenRevocationResponse.success()

            #expect(successResponse.success == true)
            #expect(successResponse.error == nil)
            #expect(successResponse.errorDescription == nil)
            #expect(successResponse.errorURI == nil)
        }

        @Test("TokenRevocationResponse failure")
        func testTokenRevocationResponseFailure() {
            let failureResponse = TokenRevocationResponse.failure(
                error: "invalid_token",
                description: "The token is invalid",
                uri: "https://example.com/error"
            )

            #expect(failureResponse.success == false)
            #expect(failureResponse.error == "invalid_token")
            #expect(failureResponse.errorDescription == "The token is invalid")
            #expect(failureResponse.errorURI == "https://example.com/error")
        }

        @Test("TokenRevocationResponse decoding success (empty)")
        func testTokenRevocationResponseDecodingSuccess() throws {
            let json = "{}"
            let data = json.data(using: .utf8)!
            let response = try JSONDecoder().decode(TokenRevocationResponse.self, from: data)

            #expect(response.success == true)
            #expect(response.error == nil)
        }

        @Test("TokenRevocationResponse decoding error")
        func testTokenRevocationResponseDecodingError() throws {
            let json = """
                {
                    "error": "invalid_token",
                    "error_description": "The token is invalid or expired",
                    "error_uri": "https://example.com/errors#invalid_token"
                }
                """

            let data = json.data(using: .utf8)!
            let response = try JSONDecoder().decode(TokenRevocationResponse.self, from: data)

            #expect(response.success == false)
            #expect(response.error == "invalid_token")
            #expect(response.errorDescription == "The token is invalid or expired")
            #expect(response.errorURI == "https://example.com/errors#invalid_token")
        }

        @Test("TokenRevocationHint constants")
        func testTokenRevocationHintConstants() {
            #expect(TokenRevocationHint.accessToken == "access_token")
            #expect(TokenRevocationHint.refreshToken == "refresh_token")
        }
    }

    // MARK: - Internal Implementation Tests

    @Suite("Internal Implementation")
    struct InternalImplementationTests {

        @Test("Token introspection handles additional claims internally")
        func testTokenIntrospectionAdditionalClaims() throws {
            // Test that additional claims are properly handled even though AnyCodable is internal
            let json = """
                {
                    "active": true,
                    "scope": "read write",
                    "custom_field": "custom_value",
                    "another_field": 123
                }
                """

            let data = json.data(using: .utf8)!
            let response = try JSONDecoder().decode(TokenIntrospectionResponse.self, from: data)

            #expect(response.active == true)
            #expect(response.scope == "read write")
            // Additional claims are handled internally and not exposed in public API
            #expect(response.additionalClaims != nil)
        }

        @Test("Additional claims are properly parsed")
        func testAdditionalClaimsParsing() throws {
            // Test that additional custom claims beyond RFC 7662 standard fields are captured
            let json = """
                {
                    "active": true,
                    "scope": "read write",
                    "client_id": "client123",
                    "username": "user@example.com",
                    "custom_department": "engineering",
                    "permission_level": "admin",
                    "nested_data": {
                        "team": "backend",
                        "role": "lead"
                    }
                }
                """

            let data = json.data(using: .utf8)!
            let response = try JSONDecoder().decode(TokenIntrospectionResponse.self, from: data)

            // Standard fields should be parsed normally
            #expect(response.active == true)
            #expect(response.scope == "read write")
            #expect(response.clientID == "client123")
            #expect(response.username == "user@example.com")

            // Additional claims should be captured
            #expect(response.additionalClaims != nil)
            #expect(response.additionalClaims?.count == 3)  // custom_department, permission_level, nested_data
        }
    }

    // MARK: - OAuth2Error Extended Tests

    @Suite("OAuth2Error Extensions")
    struct OAuth2ErrorTests {

        @Test("Unified token error descriptions")
        func testUnifiedTokenErrorDescriptions() {
            let tokenError = OAuth2Error.tokenError("Token operation failed")
            #expect(tokenError.errorDescription == "Token error: Token operation failed")

            // Test that all token operations use the same error type
            let exchangeError = OAuth2Error.tokenError("Exchange failed")
            #expect(exchangeError.errorDescription == "Token error: Exchange failed")

            let introspectionError = OAuth2Error.tokenError("Introspection failed")
            #expect(introspectionError.errorDescription == "Token error: Introspection failed")

            let revocationError = OAuth2Error.tokenError("Revocation failed")
            #expect(revocationError.errorDescription == "Token error: Revocation failed")
        }
    }
}
