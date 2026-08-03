//===----------------------------------------------------------------------===//
//
// This source file is part of the oauth-kit open source project
//
// Copyright (c) 2026 the oauth-kit project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of oauth-kit project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import JWTKit
import Testing

@testable import SharedSignalKit

// MARK: - Helpers

/// Creates a signed SET JWT using an ES256 key for testing purposes.
private func createSignedSET(
    keyCollection: JWTKeyCollection,
    kid: JWKIdentifier,
    issuer: String = "https://accounts.google.com/",
    audience: String = "my-client-id",
    jti: String = "unique-jti-1",
    subject: SubjectIdentifier = .issuerSubject(
        iss: "https://accounts.google.com/",
        sub: "user-123"
    ),
    txn: String? = "txn-1",
    eventTypeURI: String = AccountDisabledEvent.eventTypeURI,
    eventPayload: [String: JSONValue] = ["reason": .string("hijacking")]
) async throws -> String {
    let payload = SecurityEventTokenPayload(
        iss: IssuerClaim(value: issuer),
        jti: jti,
        iat: IssuedAtClaim(value: Date()),
        aud: AudienceClaim(value: [audience]),
        txn: txn,
        subId: subject,
        events: [eventTypeURI: .object(eventPayload)]
    )
    return try await keyCollection.sign(payload, kid: kid)
}

// MARK: - SecurityEventDecoder Tests

@Suite("SecurityEventDecoder Tests")
struct SecurityEventDecoderTests {

    @Test("Full decode and validate with signed JWT")
    func fullDecodeValidate() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let setString = try await createSignedSET(
            keyCollection: keyCollection,
            kid: kid
        )

        let decoder = SecurityEventDecoder(keys: keyCollection)
        let token = try await decoder.decode(setString, audience: ["my-client-id"])

        #expect(token.issuer == "https://accounts.google.com/")
        #expect(token.jti == "unique-jti-1")
        #expect(token.audience == ["my-client-id"])
        #expect(token.transactionId == "txn-1")
        #expect(
            token.subject
                == .issuerSubject(
                    iss: "https://accounts.google.com/",
                    sub: "user-123"
                )
        )
        #expect(token.eventType == AccountDisabledEvent.eventTypeURI)

        let event = try token.decodeEvent(AccountDisabledEvent.self)
        #expect(event.reason == .hijacking)
    }

    @Test("Decode typed event in one step")
    func decodeTypedOneStep() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let setString = try await createSignedSET(
            keyCollection: keyCollection,
            kid: kid,
            eventTypeURI: SessionRevokedEvent.eventTypeURI,
            eventPayload: [
                "event_timestamp": .integer(1_615_304_991),
                "initiating_entity": .string("policy"),
            ]
        )

        let decoder = SecurityEventDecoder(keys: keyCollection)
        let (token, event) = try await decoder.decode(
            setString,
            as: SessionRevokedEvent.self,
            audience: ["my-client-id"]
        )

        #expect(token.eventType == SessionRevokedEvent.eventTypeURI)
        #expect(event.eventTimestamp == 1_615_304_991)
        #expect(event.initiatingEntity == .policy)
    }

    @Test("Audience validation rejects wrong audience")
    func audienceValidationRejects() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let setString = try await createSignedSET(
            keyCollection: keyCollection,
            kid: kid,
            audience: "other-client-id"
        )

        let decoder = SecurityEventDecoder(keys: keyCollection)
        await #expect(throws: SharedSignalError.self) {
            try await decoder.decode(setString, audience: ["my-client-id"])
        }
    }

    @Test("Audience validation accepts when one of multiple matches")
    func audienceValidationAcceptsPartialMatch() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let setString = try await createSignedSET(
            keyCollection: keyCollection,
            kid: kid,
            audience: "second-client-id"
        )

        let decoder = SecurityEventDecoder(keys: keyCollection)
        let token = try await decoder.decode(
            setString,
            audience: ["first-client-id", "second-client-id"]
        )
        #expect(token.audience == ["second-client-id"])
    }

    @Test("Signature verification rejects tampered token")
    func signatureVerificationRejects() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let setString = try await createSignedSET(
            keyCollection: keyCollection,
            kid: kid
        )

        // Use a different key collection for verification — should fail
        let differentKeys = JWTKeyCollection()
        await differentKeys.add(
            ecdsa: ES256PrivateKey(),
            kid: JWKIdentifier(string: "other-key")
        )

        let decoder = SecurityEventDecoder(keys: differentKeys)
        await #expect(throws: SharedSignalError.self) {
            try await decoder.decode(setString, audience: ["my-client-id"])
        }
    }

    @Test("Decode with email subject")
    func decodeEmailSubject() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let setString = try await createSignedSET(
            keyCollection: keyCollection,
            kid: kid,
            subject: .email("foo@example.com"),
            eventTypeURI: AccountEnabledEvent.eventTypeURI,
            eventPayload: [:]
        )

        let decoder = SecurityEventDecoder(keys: keyCollection)
        let token = try await decoder.decode(setString, audience: ["my-client-id"])

        #expect(token.subject == .email("foo@example.com"))
        let _ = try token.decodeEvent(AccountEnabledEvent.self)
    }

    @Test("Decode with complex subject preserves all members")
    func decodeComplexSubject() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let complexSubject = SubjectIdentifier.complex(
            ComplexSubject(
                user: .issuerSubject(iss: "https://idp.example.com/", sub: "jane"),
                device: .opaque(id: "device-42"),
                tenant: .opaque(id: "tenant-1")
            )
        )

        let setString = try await createSignedSET(
            keyCollection: keyCollection,
            kid: kid,
            subject: complexSubject,
            eventTypeURI: DeviceComplianceChangeEvent.eventTypeURI,
            eventPayload: [
                "current_status": .string("not-compliant"),
                "previous_status": .string("compliant"),
            ]
        )

        let decoder = SecurityEventDecoder(keys: keyCollection)
        let (token, event) = try await decoder.decode(
            setString,
            as: DeviceComplianceChangeEvent.self,
            audience: ["my-client-id"]
        )

        #expect(token.subject == complexSubject)
        #expect(event.currentStatus == .notCompliant)
        #expect(event.previousStatus == .compliant)
    }

    @Test("Decode SET with no transactionId")
    func decodeWithoutTransactionId() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let setString = try await createSignedSET(
            keyCollection: keyCollection,
            kid: kid,
            txn: nil,
            eventTypeURI: AccountPurgedEvent.eventTypeURI,
            eventPayload: [:]
        )

        let decoder = SecurityEventDecoder(keys: keyCollection)
        let token = try await decoder.decode(setString, audience: ["my-client-id"])

        #expect(token.transactionId == nil)
        let _ = try token.decodeEvent(AccountPurgedEvent.self)
    }

    @Test("Decode RISC credential compromise event end-to-end")
    func decodeCredentialCompromiseEndToEnd() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let setString = try await createSignedSET(
            keyCollection: keyCollection,
            kid: kid,
            eventTypeURI: CredentialCompromiseEvent.eventTypeURI,
            eventPayload: [
                "credential_type": .string("password"),
                "event_timestamp": .integer(1_508_184_845),
                "reason_admin": .object(["en": .string("Found in breach DB")]),
            ]
        )

        let decoder = SecurityEventDecoder(keys: keyCollection)
        let (_, event) = try await decoder.decode(
            setString,
            as: CredentialCompromiseEvent.self,
            audience: ["my-client-id"]
        )

        #expect(event.credentialType == "password")
        #expect(event.eventTimestamp == 1_508_184_845)
        #expect(event.reasonAdmin?["en"] == "Found in breach DB")
    }

    @Test("Decode CAEP risk level change event end-to-end")
    func decodeRiskLevelChangeEndToEnd() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let setString = try await createSignedSET(
            keyCollection: keyCollection,
            kid: kid,
            eventTypeURI: RiskLevelChangeEvent.eventTypeURI,
            eventPayload: [
                "principal": .string("USER"),
                "current_level": .string("HIGH"),
                "previous_level": .string("LOW"),
                "risk_reason": .string("SUSPICIOUS_ACCESS"),
                "event_timestamp": .integer(1_615_304_991),
            ]
        )

        let decoder = SecurityEventDecoder(keys: keyCollection)
        let (_, event) = try await decoder.decode(
            setString,
            as: RiskLevelChangeEvent.self,
            audience: ["my-client-id"]
        )

        #expect(event.principal == "USER")
        #expect(event.currentLevel == .high)
        #expect(event.previousLevel == .low)
        #expect(event.riskReason == "SUSPICIOUS_ACCESS")
        #expect(event.eventTimestamp == 1_615_304_991)
    }
}

// MARK: - peekEventType Tests

@Suite("peekEventType Tests")
struct PeekEventTypeTests {

    @Test("Extracts event type from valid SET without signature verification")
    func peekValidSET() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let token = try await createSignedSET(
            keyCollection: keyCollection,
            kid: kid,
            eventTypeURI: AccountDisabledEvent.eventTypeURI
        )

        let eventType = try SecurityEventDecoder.peekEventType(token)
        #expect(eventType == AccountDisabledEvent.eventTypeURI)
    }

    @Test("Extracts CAEP event type")
    func peekCAEPEventType() async throws {
        let keyCollection = JWTKeyCollection()
        let kid = JWKIdentifier(string: "test-key")
        await keyCollection.add(ecdsa: ES256PrivateKey(), kid: kid)

        let token = try await createSignedSET(
            keyCollection: keyCollection,
            kid: kid,
            eventTypeURI: SessionRevokedEvent.eventTypeURI,
            eventPayload: [:]
        )

        let eventType = try SecurityEventDecoder.peekEventType(token)
        #expect(eventType == SessionRevokedEvent.eventTypeURI)
    }

    @Test("Throws on malformed token (not a JWT)")
    func peekMalformed() {
        #expect(throws: SharedSignalError.self) {
            try SecurityEventDecoder.peekEventType("not-a-jwt")
        }
    }

    @Test("Throws on token with two segments")
    func peekTwoSegments() {
        #expect(throws: SharedSignalError.self) {
            try SecurityEventDecoder.peekEventType("header.payload")
        }
    }

    @Test("Throws on token with no events claim")
    func peekNoEvents() {
        // Manually craft a JWT-shaped string with no events
        let payloadJSON = """
            {"iss": "test", "jti": "1", "iat": 0, "aud": "x"}
            """
        let payloadBase64 = Data(payloadJSON.utf8)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        let fakeToken = "eyJ0eXAiOiJzZWNldmVudCtqd3QifQ.\(payloadBase64).fake-sig"

        #expect(throws: SharedSignalError.self) {
            try SecurityEventDecoder.peekEventType(fakeToken)
        }
    }
}
