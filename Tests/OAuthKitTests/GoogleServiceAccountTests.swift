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
import Logging
import Testing

@testable import OAuthKit

@Suite("Google Service Account Tests")
struct GoogleServiceAccountTests {

    let oauthKit: OAuthClientFactory
    let logger: Logger

    init() {
        self.logger = Logger(label: "GoogleServiceAccountTests")
        self.oauthKit = OAuthClientFactory(httpClient: .shared, logger: logger)
    }

    @Test("Parse Google Service Account Credentials from JSON")
    func testParseServiceAccountCredentials() throws {
        let serviceAccountJSON = """
            {
                "type": "service_account",
                "project_id": "test-project-123",
                "private_key_id": "key123",
                "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5test\\n-----END PRIVATE KEY-----\\n",
                "client_email": "test-service@test-project-123.iam.gserviceaccount.com",
                "client_id": "123456789",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test-service%40test-project-123.iam.gserviceaccount.com",
                "universe_domain": "googleapis.com"
            }
            """

        let credentials = try GoogleServiceAccountCredentials(from: serviceAccountJSON)

        #expect(credentials.type == "service_account")
        #expect(credentials.projectId == "test-project-123")
        #expect(credentials.privateKeyId == "key123")
        #expect(credentials.clientEmail == "test-service@test-project-123.iam.gserviceaccount.com")
        #expect(credentials.clientId == "123456789")
        #expect(credentials.authUri == "https://accounts.google.com/o/oauth2/auth")
        #expect(credentials.tokenUri == "https://oauth2.googleapis.com/token")
        #expect(credentials.universeDomain == "googleapis.com")
    }

    @Test("Parse Google Service Account Credentials from Data")
    func testParseServiceAccountCredentialsFromData() throws {
        let serviceAccountJSON = """
            {
                "type": "service_account",
                "project_id": "test-project-456",
                "private_key_id": "key456",
                "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5test\\n-----END PRIVATE KEY-----\\n",
                "client_email": "test-service@test-project-456.iam.gserviceaccount.com",
                "client_id": "987654321",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test-service%40test-project-456.iam.gserviceaccount.com"
            }
            """

        guard let jsonData = serviceAccountJSON.data(using: .utf8) else {
            throw OAuth2Error.configurationError("Failed to convert JSON to Data")
        }

        let credentials = try GoogleServiceAccountCredentials(from: jsonData)

        #expect(credentials.type == "service_account")
        #expect(credentials.projectId == "test-project-456")
        #expect(credentials.privateKeyId == "key456")
        #expect(credentials.clientEmail == "test-service@test-project-456.iam.gserviceaccount.com")
        #expect(credentials.clientId == "987654321")
        #expect(credentials.universeDomain == nil)  // Not provided in this JSON
    }

    @Test("Invalid JSON throws error")
    func testInvalidJSONThrowsError() {
        let invalidJSON = """
            {
                "type": "service_account",
                "project_id": "test-project",
                // This is invalid JSON due to the comment
            }
            """

        #expect(throws: Error.self) {
            try GoogleServiceAccountCredentials(from: invalidJSON)
        }
    }

    @Test("Missing required fields throws error")
    func testMissingRequiredFieldsThrowsError() {
        let incompleteJSON = """
            {
                "type": "service_account",
                "project_id": "test-project"
            }
            """

        #expect(throws: Error.self) {
            try GoogleServiceAccountCredentials(from: incompleteJSON)
        }
    }

    @Test("Google Service Account JWT Claims")
    func testServiceAccountJWTClaims() throws {
        let now = Date()
        let expiration = now.addingTimeInterval(3600)

        let claims = GoogleServiceAccountJWT(
            iss: IssuerClaim(value: "test-service@test-project.iam.gserviceaccount.com"),
            scope: "https://www.googleapis.com/auth/cloud-platform",
            aud: AudienceClaim(value: "https://oauth2.googleapis.com/token"),
            exp: ExpirationClaim(value: expiration),
            iat: IssuedAtClaim(value: now),
            sub: nil
        )

        #expect(claims.iss.value == "test-service@test-project.iam.gserviceaccount.com")
        #expect(claims.scope == "https://www.googleapis.com/auth/cloud-platform")
        #expect(claims.aud.value.contains("https://oauth2.googleapis.com/token"))
        #expect(claims.sub == nil)
    }

    @Test("Google Service Account JWT Claims with Subject")
    func testServiceAccountJWTClaimsWithSubject() throws {
        let now = Date()
        let expiration = now.addingTimeInterval(3600)

        let claims = GoogleServiceAccountJWT(
            iss: IssuerClaim(value: "test-service@test-project.iam.gserviceaccount.com"),
            scope: "https://www.googleapis.com/auth/gmail.readonly",
            aud: AudienceClaim(value: "https://oauth2.googleapis.com/token"),
            exp: ExpirationClaim(value: expiration),
            iat: IssuedAtClaim(value: now),
            sub: "user@example.com"
        )

        #expect(claims.iss.value == "test-service@test-project.iam.gserviceaccount.com")
        #expect(claims.scope == "https://www.googleapis.com/auth/gmail.readonly")
        #expect(claims.aud.value.contains("https://oauth2.googleapis.com/token"))
        #expect(claims.sub == "user@example.com")
    }

    @Test("Google Service Account JWT Claims JSON Encoding")
    func testServiceAccountJWTClaimsEncoding() throws {
        let now = Date()
        let expiration = now.addingTimeInterval(3600)

        let claims = GoogleServiceAccountJWT(
            iss: IssuerClaim(value: "test-service@test-project.iam.gserviceaccount.com"),
            scope: "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/bigquery",
            aud: AudienceClaim(value: "https://oauth2.googleapis.com/token"),
            exp: ExpirationClaim(value: expiration),
            iat: IssuedAtClaim(value: now),
            sub: "user@example.com"
        )

        let encoder = JSONEncoder()
        let jsonData = try encoder.encode(claims)
        let jsonString = String(data: jsonData, encoding: .utf8)

        #expect(jsonString != nil)
        #expect(jsonString!.contains("test-service@test-project.iam.gserviceaccount.com"))
        #expect(jsonString!.contains("user@example.com"))
    }

    @Test("Google Provider Creation")
    func testGoogleProviderCreation() async throws {
        let provider = try await oauthKit.googleProvider(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            redirectURI: "http://localhost:3000/callback"
        )

        // Test that the provider was created successfully
        // We can't test much without making actual network calls
        // but we can verify the provider exists
        #expect(type(of: provider) == GoogleOAuthProvider.self)
    }

    @Test("Service Account Authentication with JSON String - Invalid JSON")
    func testServiceAccountAuthenticationWithInvalidJSONString() async throws {
        let provider = try await oauthKit.googleProvider(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            redirectURI: "http://localhost:3000/callback"
        )

        let invalidJSON = """
            {
                "type": "service_account",
                "project_id": "test-project"
                // Invalid JSON due to missing comma and comment
            }
            """

        await #expect(throws: Error.self) {
            try await provider.authenticateWithServiceAccount(
                credentialsJSON: invalidJSON,
                scopes: ["https://www.googleapis.com/auth/cloud-platform"]
            )
        }
    }

    @Test("Service Account Authentication with JSON String - Validation")
    func testServiceAccountAuthenticationWithJSONStringValidation() async throws {
        let provider = try await oauthKit.googleProvider(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            redirectURI: "http://localhost:3000/callback"
        )

        let validJSON = """
            {
                "type": "service_account",
                "project_id": "test-project-123",
                "private_key_id": "key123",
                "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5test\\n-----END PRIVATE KEY-----\\n",
                "client_email": "test-service@test-project-123.iam.gserviceaccount.com",
                "client_id": "123456789",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test-service%40test-project-123.iam.gserviceaccount.com",
                "universe_domain": "googleapis.com"
            }
            """

        // This will fail at the private key parsing stage, but that's expected
        // We're just testing that the JSON parsing works and the method is called
        await #expect(throws: OAuth2Error.self) {
            try await provider.authenticateWithServiceAccount(
                credentialsJSON: validJSON,
                scopes: ["https://www.googleapis.com/auth/cloud-platform"]
            )
        }
    }

    @Test("Service Account Authentication with File Path - Non-existent file")
    func testServiceAccountAuthenticationWithNonExistentFile() async throws {
        let provider = try await oauthKit.googleProvider(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            redirectURI: "http://localhost:3000/callback"
        )

        let nonExistentPath = "/path/that/does/not/exist/service-account.json"

        await #expect(throws: OAuth2Error.self) {
            try await provider.authenticateWithServiceAccount(
                credentialsFilePath: nonExistentPath,
                scopes: ["https://www.googleapis.com/auth/cloud-platform"]
            )
        }
    }

    @Test("Service Account Authentication with File Path - Error handling")
    func testServiceAccountAuthenticationFilePathErrorHandling() async throws {
        let provider = try await oauthKit.googleProvider(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            redirectURI: "http://localhost:3000/callback"
        )

        // Test with an invalid file path
        do {
            _ = try await provider.authenticateWithServiceAccount(
                credentialsFilePath: "/invalid/path/service-account.json",
                scopes: ["https://www.googleapis.com/auth/cloud-platform"]
            )
            #expect(Bool(false), "Expected error to be thrown")
        } catch let error as OAuth2Error {
            switch error {
            case .configurationError(let message):
                #expect(message.contains("Failed to load service account credentials from file"))
                #expect(message.contains("/invalid/path/service-account.json"))
            default:
                #expect(Bool(false), "Expected configurationError")
            }
        } catch {
            #expect(Bool(false), "Expected OAuth2Error")
        }
    }

    @Test("Service Account Convenience Methods - JSON String with Subject")
    func testServiceAccountJSONStringWithSubject() async throws {
        let provider = try await oauthKit.googleProvider(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            redirectURI: "http://localhost:3000/callback"
        )

        let serviceAccountJSON = """
            {
                "type": "service_account",
                "project_id": "test-project-456",
                "private_key_id": "key456",
                "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5test\\n-----END PRIVATE KEY-----\\n",
                "client_email": "test-service@test-project-456.iam.gserviceaccount.com",
                "client_id": "987654321",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test-service%40test-project-456.iam.gserviceaccount.com"
            }
            """

        // This will fail at private key parsing, but we're testing the method signature and JSON parsing
        await #expect(throws: OAuth2Error.self) {
            try await provider.authenticateWithServiceAccount(
                credentialsJSON: serviceAccountJSON,
                scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
                subject: "user@example.com"
            )
        }
    }

    @Test("Service Account Credentials Codable")
    func testServiceAccountCredentialsCodable() throws {
        let originalJSON = """
            {
                "type": "service_account",
                "project_id": "test-project",
                "private_key_id": "key123",
                "private_key": "-----BEGIN PRIVATE KEY-----\\ntest\\n-----END PRIVATE KEY-----\\n",
                "client_email": "test@test-project.iam.gserviceaccount.com",
                "client_id": "123456789",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test%40test-project.iam.gserviceaccount.com",
                "universe_domain": "googleapis.com"
            }
            """

        let original = try GoogleServiceAccountCredentials(from: originalJSON)

        // Encode to JSON
        let encoder = JSONEncoder()
        let jsonData = try encoder.encode(original)

        // Decode from JSON
        let decoder = JSONDecoder()
        let decoded = try decoder.decode(GoogleServiceAccountCredentials.self, from: jsonData)

        // Verify all fields match
        #expect(decoded.type == original.type)
        #expect(decoded.projectId == original.projectId)
        #expect(decoded.privateKeyId == original.privateKeyId)
        #expect(decoded.privateKey == original.privateKey)
        #expect(decoded.clientEmail == original.clientEmail)
        #expect(decoded.clientId == original.clientId)
        #expect(decoded.authUri == original.authUri)
        #expect(decoded.tokenUri == original.tokenUri)
        #expect(decoded.authProviderX509CertUrl == original.authProviderX509CertUrl)
        #expect(decoded.clientX509CertUrl == original.clientX509CertUrl)
        #expect(decoded.universeDomain == original.universeDomain)
    }

    @Test("Direct JWT Token Creation with Credentials Object")
    func testDirectJWTTokenCreation() async throws {
        let provider = try await oauthKit.googleProvider(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            redirectURI: "http://localhost:3000/callback"
        )

        let credentials = GoogleServiceAccountCredentials.testCredentials()

        // This will fail at private key parsing, but we're testing the method signature and flow
        await #expect(throws: OAuth2Error.self) {
            try await provider.createServiceAccountJWTToken(
                credentials: credentials,
                audience: "https://storage.googleapis.com/"
            )
        }
    }

    @Test("Direct JWT Token Creation with JSON String")
    func testDirectJWTTokenCreationWithJSONString() async throws {
        let provider = try await oauthKit.googleProvider(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            redirectURI: "http://localhost:3000/callback"
        )

        let serviceAccountJSON = """
            {
                "type": "service_account",
                "project_id": "test-project-123",
                "private_key_id": "key123",
                "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5test\\n-----END PRIVATE KEY-----\\n",
                "client_email": "test-service@test-project-123.iam.gserviceaccount.com",
                "client_id": "123456789",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test-service%40test-project-123.iam.gserviceaccount.com",
                "universe_domain": "googleapis.com"
            }
            """

        // This will fail at private key parsing, but we're testing the method signature and JSON parsing
        await #expect(throws: OAuth2Error.self) {
            try await provider.createServiceAccountJWTToken(
                credentialsJSON: serviceAccountJSON,
                audience: "https://bigquery.googleapis.com/"
            )
        }
    }

    @Test("Direct JWT Token Creation with File Path")
    func testDirectJWTTokenCreationWithFilePath() async throws {
        let provider = try await oauthKit.googleProvider(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            redirectURI: "http://localhost:3000/callback"
        )

        let nonExistentPath = "/path/that/does/not/exist/service-account.json"

        await #expect(throws: OAuth2Error.self) {
            try await provider.createServiceAccountJWTToken(
                credentialsFilePath: nonExistentPath,
                audience: "https://www.googleapis.com/auth/cloud-platform"
            )
        }
    }

    @Test("Direct JWT Token Creation with Subject")
    func testDirectJWTTokenCreationWithSubject() async throws {
        let provider = try await oauthKit.googleProvider(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            redirectURI: "http://localhost:3000/callback"
        )

        let credentials = GoogleServiceAccountCredentials.testCredentials()

        // This will fail at private key parsing, but we're testing the method signature and subject parameter
        await #expect(throws: OAuth2Error.self) {
            try await provider.createServiceAccountJWTToken(
                credentials: credentials,
                audience: "https://www.googleapis.com/auth/gmail.readonly",
                subject: "user@example.com"
            )
        }
    }

    @Test("Direct JWT Token Creation with Additional Claims")
    func testDirectJWTTokenCreationWithAdditionalClaims() async throws {
        let provider = try await oauthKit.googleProvider(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            redirectURI: "http://localhost:3000/callback"
        )

        let credentials = GoogleServiceAccountCredentials.testCredentials()
        let additionalClaims = [
            "department": "engineering",
            "role": "service",
        ]

        // This will fail at private key parsing, but we're testing the method signature and additional claims
        await #expect(throws: OAuth2Error.self) {
            try await provider.createServiceAccountJWTToken(
                credentials: credentials,
                audience: "https://your-api.googleapis.com/",
                additionalClaims: additionalClaims
            )
        }
    }

    @Test("Direct JWT Claims Structure")
    func testDirectJWTClaimsStructure() throws {
        let now = Date()
        let expiration = now.addingTimeInterval(3600)

        let claims = GoogleServiceAccountDirectJWT(
            iss: IssuerClaim(value: "test-service@test-project.iam.gserviceaccount.com"),
            aud: AudienceClaim(value: "https://storage.googleapis.com/"),
            exp: ExpirationClaim(value: expiration),
            iat: IssuedAtClaim(value: now),
            sub: "user@example.com"
        )

        #expect(claims.iss.value == "test-service@test-project.iam.gserviceaccount.com")
        #expect(claims.aud.value.contains("https://storage.googleapis.com/"))
        #expect(claims.sub == "user@example.com")
        #expect(claims.additionalClaims.isEmpty)
    }

    @Test("Direct JWT Claims with Additional Claims")
    func testDirectJWTClaimsWithAdditionalClaims() throws {
        let now = Date()
        let expiration = now.addingTimeInterval(3600)

        var claims = GoogleServiceAccountDirectJWT(
            iss: IssuerClaim(value: "test-service@test-project.iam.gserviceaccount.com"),
            aud: AudienceClaim(value: "https://bigquery.googleapis.com/"),
            exp: ExpirationClaim(value: expiration),
            iat: IssuedAtClaim(value: now),
            sub: nil
        )

        claims.additionalClaims = [
            "custom_claim": "custom_value",
            "organization": "test-org",
        ]

        #expect(claims.iss.value == "test-service@test-project.iam.gserviceaccount.com")
        #expect(claims.aud.value.contains("https://bigquery.googleapis.com/"))
        #expect(claims.sub == nil)
        #expect(claims.additionalClaims["custom_claim"] == "custom_value")
        #expect(claims.additionalClaims["organization"] == "test-org")
    }

    @Test("Direct JWT Claims JSON Encoding")
    func testDirectJWTClaimsJSONEncoding() throws {
        let now = Date()
        let expiration = now.addingTimeInterval(3600)

        var claims = GoogleServiceAccountDirectJWT(
            iss: IssuerClaim(value: "test-service@test-project.iam.gserviceaccount.com"),
            aud: AudienceClaim(value: "https://www.googleapis.com/auth/cloud-platform"),
            exp: ExpirationClaim(value: expiration),
            iat: IssuedAtClaim(value: now),
            sub: "user@example.com"
        )

        claims.additionalClaims = [
            "department": "engineering",
            "role": "admin",
        ]

        let encoder = JSONEncoder()
        let jsonData = try encoder.encode(claims)
        let jsonString = String(data: jsonData, encoding: .utf8)

        #expect(jsonString != nil)
        #expect(jsonString!.contains("test-service@test-project.iam.gserviceaccount.com"))
        #expect(jsonString!.contains("user@example.com"))
        #expect(jsonString!.contains("engineering"))
        #expect(jsonString!.contains("admin"))
    }

    @Test("Direct JWT File Path Error Handling")
    func testDirectJWTFilePathErrorHandling() async throws {
        let provider = try await oauthKit.googleProvider(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            redirectURI: "http://localhost:3000/callback"
        )

        // Test with an invalid file path
        do {
            _ = try await provider.createServiceAccountJWTToken(
                credentialsFilePath: "/invalid/path/service-account.json",
                audience: "https://storage.googleapis.com/"
            )
            #expect(Bool(false), "Expected error to be thrown")
        } catch let error as OAuth2Error {
            switch error {
            case .configurationError(let message):
                #expect(message.contains("Failed to load service account credentials from file"))
                #expect(message.contains("/invalid/path/service-account.json"))
            default:
                #expect(Bool(false), "Expected configurationError")
            }
        } catch {
            #expect(Bool(false), "Expected OAuth2Error")
        }
    }
}

// Extension to create test credentials for internal use
extension GoogleServiceAccountCredentials {
    static func testCredentials() -> GoogleServiceAccountCredentials {
        let testJSON = """
            {
                "type": "service_account",
                "project_id": "test-project-123",
                "private_key_id": "test-key-id",
                "private_key": "-----BEGIN PRIVATE KEY-----\\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC5test\\n-----END PRIVATE KEY-----\\n",
                "client_email": "test-service@test-project-123.iam.gserviceaccount.com",
                "client_id": "123456789012345678901",
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/test-service%40test-project-123.iam.gserviceaccount.com",
                "universe_domain": "googleapis.com"
            }
            """
        return try! GoogleServiceAccountCredentials(from: testJSON)
    }
}
