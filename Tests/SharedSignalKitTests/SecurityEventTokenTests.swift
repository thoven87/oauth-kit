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
import Testing

@testable import SharedSignalKit

@Suite("SecurityEventToken Tests")
struct SecurityEventTokenTests {

    // MARK: - Helpers

    private func makeToken(
        eventType: String,
        rawEventPayload: JSONValue,
        subject: SubjectIdentifier = .email("user@example.com"),
        issuer: String = "https://idp.example.com/",
        jti: String = "unique-id",
        audience: [String] = ["client-1"],
        transactionId: String? = nil
    ) -> SecurityEventToken {
        SecurityEventToken(
            issuer: issuer,
            jti: jti,
            issuedAt: Date(),
            audience: audience,
            transactionId: transactionId,
            subject: subject,
            eventType: eventType,
            rawEventPayload: rawEventPayload
        )
    }

    // MARK: - decodeEvent Matching

    @Test("decodeEvent succeeds for matching RISC event type")
    func decodeEventMatching() throws {
        let token = makeToken(
            eventType: AccountDisabledEvent.eventTypeURI,
            rawEventPayload: .object(["reason": .string("hijacking")])
        )

        let event = try token.decodeEvent(AccountDisabledEvent.self)
        #expect(event.reason == .hijacking)
    }

    @Test("decodeEvent succeeds with bulk-account reason")
    func decodeEventBulkAccount() throws {
        let token = makeToken(
            eventType: AccountDisabledEvent.eventTypeURI,
            rawEventPayload: .object(["reason": .string("bulk-account")])
        )

        let event = try token.decodeEvent(AccountDisabledEvent.self)
        #expect(event.reason == .bulkAccount)
    }

    @Test("decodeEvent succeeds with nil reason")
    func decodeEventNoReason() throws {
        let token = makeToken(
            eventType: AccountDisabledEvent.eventTypeURI,
            rawEventPayload: .object([:])
        )

        let event = try token.decodeEvent(AccountDisabledEvent.self)
        #expect(event.reason == nil)
    }

    // MARK: - Event Type Mismatch

    @Test("decodeEvent throws on event type mismatch")
    func decodeEventMismatch() throws {
        let token = makeToken(
            eventType: AccountDisabledEvent.eventTypeURI,
            rawEventPayload: .object([:])
        )

        #expect(throws: SharedSignalError.self) {
            try token.decodeEvent(AccountEnabledEvent.self)
        }
    }

    @Test("decodeEvent mismatch error contains expected and actual URIs")
    func decodeEventMismatchErrorDetails() throws {
        let token = makeToken(
            eventType: AccountDisabledEvent.eventTypeURI,
            rawEventPayload: .object([:])
        )

        do {
            _ = try token.decodeEvent(SessionRevokedEvent.self)
            Issue.record("Expected SharedSignalError.eventTypeMismatch to be thrown")
        } catch let error as SharedSignalError {
            guard case .eventTypeMismatch(let expected, let actual) = error else {
                Issue.record("Expected eventTypeMismatch, got \(error)")
                return
            }
            #expect(expected == SessionRevokedEvent.eventTypeURI)
            #expect(actual == AccountDisabledEvent.eventTypeURI)
        }
    }

    // MARK: - Empty Payload Events

    @Test("decodeEvent works with empty payload RISC events")
    func decodeEventEmptyPayloadRISC() throws {
        let emptyPayloadEvents: [(String, any SharedSignalsEvent.Type)] = [
            (AccountEnabledEvent.eventTypeURI, AccountEnabledEvent.self),
            (AccountPurgedEvent.eventTypeURI, AccountPurgedEvent.self),
            (AccountCredentialChangeRequiredEvent.eventTypeURI, AccountCredentialChangeRequiredEvent.self),
            (IdentifierRecycledEvent.eventTypeURI, IdentifierRecycledEvent.self),
            (SessionsRevokedEvent.eventTypeURI, SessionsRevokedEvent.self),
            (RecoveryActivatedEvent.eventTypeURI, RecoveryActivatedEvent.self),
            (RecoveryInformationChangedEvent.eventTypeURI, RecoveryInformationChangedEvent.self),
            (OptInEvent.eventTypeURI, OptInEvent.self),
            (OptOutInitiatedEvent.eventTypeURI, OptOutInitiatedEvent.self),
            (OptOutCancelledEvent.eventTypeURI, OptOutCancelledEvent.self),
            (OptOutEffectiveEvent.eventTypeURI, OptOutEffectiveEvent.self),
        ]

        for (uri, _) in emptyPayloadEvents {
            let token = makeToken(
                eventType: uri,
                rawEventPayload: .object([:])
            )
            // Verify the raw payload can at least be re-encoded without error
            let data = try JSONEncoder().encode(token.rawEventPayload)
            #expect(data.count > 0)
        }
    }

    @Test("decodeEvent works with SessionsRevokedEvent")
    func decodeEventSessionsRevoked() throws {
        let token = makeToken(
            eventType: SessionsRevokedEvent.eventTypeURI,
            rawEventPayload: .object([:])
        )

        let _ = try token.decodeEvent(SessionsRevokedEvent.self)
    }

    @Test("decodeEvent works with VerificationEvent with state")
    func decodeEventVerification() throws {
        let token = makeToken(
            eventType: VerificationEvent.eventTypeURI,
            rawEventPayload: .object(["state": .string("my-state-123")])
        )

        let event = try token.decodeEvent(VerificationEvent.self)
        #expect(event.state == "my-state-123")
    }

    @Test("decodeEvent works with VerificationEvent without state")
    func decodeEventVerificationNoState() throws {
        let token = makeToken(
            eventType: VerificationEvent.eventTypeURI,
            rawEventPayload: .object([:])
        )

        let event = try token.decodeEvent(VerificationEvent.self)
        #expect(event.state == nil)
    }

    // MARK: - CAEP Events

    @Test("decodeEvent works with SessionRevokedEvent")
    func decodeEventSessionRevoked() throws {
        let token = makeToken(
            eventType: SessionRevokedEvent.eventTypeURI,
            rawEventPayload: .object([
                "event_timestamp": .integer(1_615_304_991),
                "initiating_entity": .string("policy"),
                "reason_admin": .object(["en": .string("Policy Violation: C076E82F")]),
                "reason_user": .object(["en": .string("Access denied.")]),
            ])
        )

        let event = try token.decodeEvent(SessionRevokedEvent.self)
        #expect(event.eventTimestamp == 1_615_304_991)
        #expect(event.initiatingEntity == .policy)
        #expect(event.reasonAdmin?["en"] == "Policy Violation: C076E82F")
        #expect(event.reasonUser?["en"] == "Access denied.")
    }

    @Test("decodeEvent works with RiskLevelChangeEvent")
    func decodeEventRiskLevelChange() throws {
        let token = makeToken(
            eventType: RiskLevelChangeEvent.eventTypeURI,
            rawEventPayload: .object([
                "principal": .string("USER"),
                "current_level": .string("HIGH"),
                "previous_level": .string("LOW"),
                "risk_reason": .string("SUSPICIOUS_ACCESS"),
                "event_timestamp": .integer(1_615_304_991),
            ]),
            subject: .issuerSubject(iss: "https://idp.example.com/", sub: "jane"),
            transactionId: "txn-123"
        )

        let event = try token.decodeEvent(RiskLevelChangeEvent.self)
        #expect(event.principal == "USER")
        #expect(event.currentLevel == .high)
        #expect(event.previousLevel == .low)
        #expect(event.riskReason == "SUSPICIOUS_ACCESS")
        #expect(event.eventTimestamp == 1_615_304_991)
    }

    @Test("decodeEvent works with CredentialChangeEvent")
    func decodeEventCredentialChange() throws {
        let token = makeToken(
            eventType: CredentialChangeEvent.eventTypeURI,
            rawEventPayload: .object([
                "credential_type": .string("fido2-roaming"),
                "change_type": .string("create"),
                "friendly_name": .string("Jane's USB key"),
                "fido2_aaguid": .string("accced6a-63f5-490a-9eea-e59bc1896cfc"),
                "event_timestamp": .integer(1_615_304_991),
                "initiating_entity": .string("user"),
            ])
        )

        let event = try token.decodeEvent(CredentialChangeEvent.self)
        #expect(event.credentialType == "fido2-roaming")
        #expect(event.changeType == .create)
        #expect(event.friendlyName == "Jane's USB key")
        #expect(event.fido2Aaguid == "accced6a-63f5-490a-9eea-e59bc1896cfc")
        #expect(event.initiatingEntity == .user)
    }

    @Test("decodeEvent works with DeviceComplianceChangeEvent")
    func decodeEventDeviceCompliance() throws {
        let token = makeToken(
            eventType: DeviceComplianceChangeEvent.eventTypeURI,
            rawEventPayload: .object([
                "current_status": .string("not-compliant"),
                "previous_status": .string("compliant"),
                "initiating_entity": .string("policy"),
                "reason_admin": .object(["en": .string("Location violation")]),
            ])
        )

        let event = try token.decodeEvent(DeviceComplianceChangeEvent.self)
        #expect(event.currentStatus == .notCompliant)
        #expect(event.previousStatus == .compliant)
        #expect(event.initiatingEntity == .policy)
        #expect(event.reasonAdmin?["en"] == "Location violation")
    }

    @Test("decodeEvent works with TokenClaimsChangeEvent")
    func decodeEventTokenClaimsChange() throws {
        let token = makeToken(
            eventType: TokenClaimsChangeEvent.eventTypeURI,
            rawEventPayload: .object([
                "event_timestamp": .integer(1_615_304_991),
                "claims": .object([
                    "role": .string("ro-admin"),
                    "trusted_network": .bool(false),
                ]),
            ])
        )

        let event = try token.decodeEvent(TokenClaimsChangeEvent.self)
        #expect(event.eventTimestamp == 1_615_304_991)
        #expect(event.claims["role"] == .string("ro-admin"))
        #expect(event.claims["trusted_network"] == .bool(false))
    }

    @Test("decodeEvent works with AssuranceLevelChangeEvent")
    func decodeEventAssuranceLevelChange() throws {
        let token = makeToken(
            eventType: AssuranceLevelChangeEvent.eventTypeURI,
            rawEventPayload: .object([
                "namespace": .string("NIST-AAL"),
                "current_level": .string("nist-aal2"),
                "previous_level": .string("nist-aal1"),
                "change_direction": .string("increase"),
            ])
        )

        let event = try token.decodeEvent(AssuranceLevelChangeEvent.self)
        #expect(event.namespace == "NIST-AAL")
        #expect(event.currentLevel == "nist-aal2")
        #expect(event.previousLevel == "nist-aal1")
        #expect(event.changeDirection == .increase)
    }

    @Test("decodeEvent works with StreamUpdatedEvent")
    func decodeEventStreamUpdated() throws {
        let token = makeToken(
            eventType: StreamUpdatedEvent.eventTypeURI,
            rawEventPayload: .object([
                "status": .string("paused"),
                "reason": .string("Maintenance window"),
            ])
        )

        let event = try token.decodeEvent(StreamUpdatedEvent.self)
        #expect(event.status == .paused)
        #expect(event.reason == "Maintenance window")
    }

    @Test("decodeEvent works with IdentifierChangedEvent")
    func decodeEventIdentifierChanged() throws {
        let token = makeToken(
            eventType: IdentifierChangedEvent.eventTypeURI,
            rawEventPayload: .object([
                "new-value": .string("new@example.com")
            ]),
            subject: .email("old@example.com")
        )

        let event = try token.decodeEvent(IdentifierChangedEvent.self)
        #expect(event.newValue == "new@example.com")
    }

    @Test("decodeEvent works with CredentialCompromiseEvent")
    func decodeEventCredentialCompromise() throws {
        let token = makeToken(
            eventType: CredentialCompromiseEvent.eventTypeURI,
            rawEventPayload: .object([
                "credential_type": .string("password"),
                "event_timestamp": .integer(1_508_184_845),
                "reason_admin": .object(["en": .string("Found in data breach")]),
                "reason_user": .object(["en": .string("Your password may be compromised")]),
            ])
        )

        let event = try token.decodeEvent(CredentialCompromiseEvent.self)
        #expect(event.credentialType == "password")
        #expect(event.eventTimestamp == 1_508_184_845)
        #expect(event.reasonAdmin?["en"] == "Found in data breach")
        #expect(event.reasonUser?["en"] == "Your password may be compromised")
    }

    // MARK: - Token Properties

    @Test("Token preserves all metadata fields")
    func tokenPreservesMetadata() {
        let token = makeToken(
            eventType: AccountDisabledEvent.eventTypeURI,
            rawEventPayload: .object([:]),
            subject: .opaque(id: "subject-99"),
            issuer: "https://custom-issuer.example.com",
            jti: "custom-jti-42",
            audience: ["aud-1", "aud-2"],
            transactionId: "txn-abc"
        )

        #expect(token.issuer == "https://custom-issuer.example.com")
        #expect(token.jti == "custom-jti-42")
        #expect(token.audience == ["aud-1", "aud-2"])
        #expect(token.transactionId == "txn-abc")
        #expect(token.subject == .opaque(id: "subject-99"))
        #expect(token.eventType == AccountDisabledEvent.eventTypeURI)
    }

    @Test("Token with nil transactionId")
    func tokenNilTransactionId() {
        let token = makeToken(
            eventType: AccountEnabledEvent.eventTypeURI,
            rawEventPayload: .object([:]),
            transactionId: nil
        )

        #expect(token.transactionId == nil)
    }
}
