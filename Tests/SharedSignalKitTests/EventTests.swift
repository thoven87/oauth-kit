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

// MARK: - RISC Event Tests

@Suite("RISC Event Tests")
struct RISCEventTests {

    @Test("AccountDisabledEvent decodes with reason")
    func accountDisabledWithReason() throws {
        let json = """
            {"reason": "hijacking"}
            """
        let event = try JSONDecoder().decode(AccountDisabledEvent.self, from: Data(json.utf8))
        #expect(event.reason == .hijacking)
    }

    @Test("AccountDisabledEvent decodes with bulk-account reason")
    func accountDisabledBulkAccount() throws {
        let json = """
            {"reason": "bulk-account"}
            """
        let event = try JSONDecoder().decode(AccountDisabledEvent.self, from: Data(json.utf8))
        #expect(event.reason == .bulkAccount)
    }

    @Test("AccountDisabledEvent decodes without reason")
    func accountDisabledNoReason() throws {
        let json = """
            {}
            """
        let event = try JSONDecoder().decode(AccountDisabledEvent.self, from: Data(json.utf8))
        #expect(event.reason == nil)
    }

    @Test("AccountEnabledEvent decodes from empty object")
    func accountEnabled() throws {
        let json = Data("{}".utf8)
        let _ = try JSONDecoder().decode(AccountEnabledEvent.self, from: json)
    }

    @Test("IdentifierChangedEvent decodes with new value")
    func identifierChanged() throws {
        let json = """
            {"new-value": "john.roe@example.com"}
            """
        let event = try JSONDecoder().decode(IdentifierChangedEvent.self, from: Data(json.utf8))
        #expect(event.newValue == "john.roe@example.com")
    }

    @Test("IdentifierChangedEvent decodes without new value")
    func identifierChangedNoNewValue() throws {
        let json = Data("{}".utf8)
        let event = try JSONDecoder().decode(IdentifierChangedEvent.self, from: json)
        #expect(event.newValue == nil)
    }

    @Test("CredentialCompromiseEvent decodes all fields")
    func credentialCompromise() throws {
        let json = """
            {
                "credential_type": "password",
                "event_timestamp": 1508184845,
                "reason_admin": {"en": "Credential found in breach"},
                "reason_user": {"en": "Your password was compromised"}
            }
            """
        let event = try JSONDecoder().decode(CredentialCompromiseEvent.self, from: Data(json.utf8))
        #expect(event.credentialType == "password")
        #expect(event.eventTimestamp == 1_508_184_845)
        #expect(event.reasonAdmin?["en"] == "Credential found in breach")
        #expect(event.reasonUser?["en"] == "Your password was compromised")
    }

    @Test("CredentialCompromiseEvent decodes with only required fields")
    func credentialCompromiseMinimal() throws {
        let json = """
            {"credential_type": "x509"}
            """
        let event = try JSONDecoder().decode(CredentialCompromiseEvent.self, from: Data(json.utf8))
        #expect(event.credentialType == "x509")
        #expect(event.eventTimestamp == nil)
        #expect(event.reasonAdmin == nil)
        #expect(event.reasonUser == nil)
    }

    @Test("Empty-body RISC events all decode from empty object")
    func emptyBodyEvents() throws {
        let json = Data("{}".utf8)
        let _ = try JSONDecoder().decode(AccountCredentialChangeRequiredEvent.self, from: json)
        let _ = try JSONDecoder().decode(AccountPurgedEvent.self, from: json)
        let _ = try JSONDecoder().decode(AccountEnabledEvent.self, from: json)
        let _ = try JSONDecoder().decode(IdentifierRecycledEvent.self, from: json)
        let _ = try JSONDecoder().decode(SessionsRevokedEvent.self, from: json)
        let _ = try JSONDecoder().decode(RecoveryActivatedEvent.self, from: json)
        let _ = try JSONDecoder().decode(RecoveryInformationChangedEvent.self, from: json)
        let _ = try JSONDecoder().decode(OptInEvent.self, from: json)
        let _ = try JSONDecoder().decode(OptOutInitiatedEvent.self, from: json)
        let _ = try JSONDecoder().decode(OptOutCancelledEvent.self, from: json)
        let _ = try JSONDecoder().decode(OptOutEffectiveEvent.self, from: json)
    }

    @Test("All RISC event types have correct URIs")
    func riscEventTypeURIs() {
        let base = "https://schemas.openid.net/secevent/risc/event-type/"
        #expect(AccountCredentialChangeRequiredEvent.eventTypeURI == base + "account-credential-change-required")
        #expect(AccountPurgedEvent.eventTypeURI == base + "account-purged")
        #expect(AccountDisabledEvent.eventTypeURI == base + "account-disabled")
        #expect(AccountEnabledEvent.eventTypeURI == base + "account-enabled")
        #expect(IdentifierChangedEvent.eventTypeURI == base + "identifier-changed")
        #expect(IdentifierRecycledEvent.eventTypeURI == base + "identifier-recycled")
        #expect(CredentialCompromiseEvent.eventTypeURI == base + "credential-compromise")
        #expect(SessionsRevokedEvent.eventTypeURI == base + "sessions-revoked")
        #expect(RecoveryActivatedEvent.eventTypeURI == base + "recovery-activated")
        #expect(RecoveryInformationChangedEvent.eventTypeURI == base + "recovery-information-changed")
        #expect(OptInEvent.eventTypeURI == base + "opt-in")
        #expect(OptOutInitiatedEvent.eventTypeURI == base + "opt-out-initiated")
        #expect(OptOutCancelledEvent.eventTypeURI == base + "opt-out-cancelled")
        #expect(OptOutEffectiveEvent.eventTypeURI == base + "opt-out-effective")
    }
}

// MARK: - CAEP Event Tests

@Suite("CAEP Event Tests")
struct CAEPEventTests {

    @Test("SessionRevokedEvent decodes with all optional fields")
    func sessionRevoked() throws {
        let json = """
            {
                "event_timestamp": 1615304991,
                "initiating_entity": "policy",
                "reason_admin": {"en": "Policy Violation"},
                "reason_user": {"en": "Access denied."}
            }
            """
        let event = try JSONDecoder().decode(SessionRevokedEvent.self, from: Data(json.utf8))
        #expect(event.eventTimestamp == 1_615_304_991)
        #expect(event.initiatingEntity == .policy)
        #expect(event.reasonAdmin?["en"] == "Policy Violation")
        #expect(event.reasonUser?["en"] == "Access denied.")
    }

    @Test("SessionRevokedEvent decodes from empty object")
    func sessionRevokedEmpty() throws {
        let json = Data("{}".utf8)
        let event = try JSONDecoder().decode(SessionRevokedEvent.self, from: json)
        #expect(event.eventTimestamp == nil)
        #expect(event.initiatingEntity == nil)
    }

    @Test("CredentialChangeEvent decodes required and optional fields")
    func credentialChange() throws {
        let json = """
            {
                "credential_type": "fido2-roaming",
                "change_type": "create",
                "friendly_name": "My Yubikey",
                "fido2_aaguid": "aaguid-value",
                "event_timestamp": 1615304991
            }
            """
        let event = try JSONDecoder().decode(CredentialChangeEvent.self, from: Data(json.utf8))
        #expect(event.credentialType == "fido2-roaming")
        #expect(event.changeType == .create)
        #expect(event.friendlyName == "My Yubikey")
        #expect(event.fido2Aaguid == "aaguid-value")
        #expect(event.eventTimestamp == 1_615_304_991)
    }

    @Test("CredentialChangeEvent change types all decode")
    func credentialChangeTypes() throws {
        for rawValue in ["create", "revoke", "update", "delete"] {
            let json = """
                {"credential_type": "password", "change_type": "\(rawValue)"}
                """
            let event = try JSONDecoder().decode(CredentialChangeEvent.self, from: Data(json.utf8))
            #expect(event.changeType.rawValue == rawValue)
        }
    }

    @Test("DeviceComplianceChangeEvent decodes statuses")
    func deviceComplianceChange() throws {
        let json = """
            {
                "current_status": "not-compliant",
                "previous_status": "compliant"
            }
            """
        let event = try JSONDecoder().decode(DeviceComplianceChangeEvent.self, from: Data(json.utf8))
        #expect(event.currentStatus == .notCompliant)
        #expect(event.previousStatus == .compliant)
    }

    @Test("RiskLevelChangeEvent decodes all fields")
    func riskLevelChange() throws {
        let json = """
            {
                "principal": "USER",
                "current_level": "HIGH",
                "previous_level": "LOW",
                "risk_reason": "PASSWORD_FOUND_IN_DATA_BREACH",
                "event_timestamp": 1615304991
            }
            """
        let event = try JSONDecoder().decode(RiskLevelChangeEvent.self, from: Data(json.utf8))
        #expect(event.principal == "USER")
        #expect(event.currentLevel == .high)
        #expect(event.previousLevel == .low)
        #expect(event.riskReason == "PASSWORD_FOUND_IN_DATA_BREACH")
        #expect(event.eventTimestamp == 1_615_304_991)
    }

    @Test("RiskLevelChangeEvent decodes without optional fields")
    func riskLevelChangeMinimal() throws {
        let json = """
            {
                "principal": "DEVICE",
                "current_level": "MEDIUM"
            }
            """
        let event = try JSONDecoder().decode(RiskLevelChangeEvent.self, from: Data(json.utf8))
        #expect(event.principal == "DEVICE")
        #expect(event.currentLevel == .medium)
        #expect(event.previousLevel == nil)
        #expect(event.riskReason == nil)
    }

    @Test("AssuranceLevelChangeEvent decodes")
    func assuranceLevelChange() throws {
        let json = """
            {
                "namespace": "NIST-AAL",
                "current_level": "nist-aal2",
                "previous_level": "nist-aal1",
                "change_direction": "increase",
                "event_timestamp": 1615304991
            }
            """
        let event = try JSONDecoder().decode(AssuranceLevelChangeEvent.self, from: Data(json.utf8))
        #expect(event.namespace == "NIST-AAL")
        #expect(event.currentLevel == "nist-aal2")
        #expect(event.previousLevel == "nist-aal1")
        #expect(event.changeDirection == .increase)
        #expect(event.eventTimestamp == 1_615_304_991)
    }

    @Test("AssuranceLevelChangeEvent decodes decrease direction")
    func assuranceLevelDecrease() throws {
        let json = """
            {
                "namespace": "RFC8176",
                "current_level": "aal1",
                "change_direction": "decrease"
            }
            """
        let event = try JSONDecoder().decode(AssuranceLevelChangeEvent.self, from: Data(json.utf8))
        #expect(event.changeDirection == .decrease)
        #expect(event.previousLevel == nil)
    }

    @Test("SessionEstablishedEvent decodes all fields")
    func sessionEstablished() throws {
        let json = """
            {
                "fp_ua": "abc123hash",
                "acr": "AAL2",
                "amr": ["otp"],
                "ext_id": "external-1",
                "event_timestamp": 1615304991
            }
            """
        let event = try JSONDecoder().decode(SessionEstablishedEvent.self, from: Data(json.utf8))
        #expect(event.fpUa == "abc123hash")
        #expect(event.acr == "AAL2")
        #expect(event.amr == ["otp"])
        #expect(event.extId == "external-1")
        #expect(event.eventTimestamp == 1_615_304_991)
    }

    @Test("SessionPresentedEvent decodes")
    func sessionPresented() throws {
        let json = """
            {
                "fp_ua": "hashvalue",
                "ext_id": "session-ext-1",
                "event_timestamp": 1615304991
            }
            """
        let event = try JSONDecoder().decode(SessionPresentedEvent.self, from: Data(json.utf8))
        #expect(event.fpUa == "hashvalue")
        #expect(event.extId == "session-ext-1")
        #expect(event.eventTimestamp == 1_615_304_991)
    }

    @Test("TokenClaimsChangeEvent decodes claims as JSONValue")
    func tokenClaimsChange() throws {
        let json = """
            {
                "event_timestamp": 1615304991,
                "claims": {
                    "role": "ro-admin",
                    "trusted_network": false
                }
            }
            """
        let event = try JSONDecoder().decode(TokenClaimsChangeEvent.self, from: Data(json.utf8))
        #expect(event.claims["role"] == .string("ro-admin"))
        #expect(event.claims["trusted_network"] == .bool(false))
        #expect(event.eventTimestamp == 1_615_304_991)
    }

    @Test("InitiatingEntity covers all values")
    func initiatingEntityValues() throws {
        for rawValue in ["admin", "user", "policy", "system"] {
            let json = Data("\"\(rawValue)\"".utf8)
            let entity = try JSONDecoder().decode(InitiatingEntity.self, from: json)
            #expect(entity.rawValue == rawValue)
        }
    }

    @Test("All CAEP event types have correct URIs")
    func caepEventTypeURIs() {
        let base = "https://schemas.openid.net/secevent/caep/event-type/"
        #expect(SessionRevokedEvent.eventTypeURI == base + "session-revoked")
        #expect(TokenClaimsChangeEvent.eventTypeURI == base + "token-claims-change")
        #expect(CredentialChangeEvent.eventTypeURI == base + "credential-change")
        #expect(AssuranceLevelChangeEvent.eventTypeURI == base + "assurance-level-change")
        #expect(DeviceComplianceChangeEvent.eventTypeURI == base + "device-compliance-change")
        #expect(SessionEstablishedEvent.eventTypeURI == base + "session-established")
        #expect(SessionPresentedEvent.eventTypeURI == base + "session-presented")
        #expect(RiskLevelChangeEvent.eventTypeURI == base + "risk-level-change")
    }
}

// MARK: - SSF Framework Event Tests

@Suite("SSF Event Tests")
struct SSFEventTests {

    @Test("VerificationEvent decodes with state")
    func verificationWithState() throws {
        let json = """
            {"state": "test-state-value"}
            """
        let event = try JSONDecoder().decode(VerificationEvent.self, from: Data(json.utf8))
        #expect(event.state == "test-state-value")
    }

    @Test("VerificationEvent decodes without state")
    func verificationWithoutState() throws {
        let json = Data("{}".utf8)
        let event = try JSONDecoder().decode(VerificationEvent.self, from: json)
        #expect(event.state == nil)
    }

    @Test("StreamUpdatedEvent decodes with reason")
    func streamUpdated() throws {
        let json = """
            {"status": "paused", "reason": "Internal error"}
            """
        let event = try JSONDecoder().decode(StreamUpdatedEvent.self, from: Data(json.utf8))
        #expect(event.status == .paused)
        #expect(event.reason == "Internal error")
    }

    @Test("StreamUpdatedEvent decodes without reason")
    func streamUpdatedNoReason() throws {
        let json = """
            {"status": "disabled"}
            """
        let event = try JSONDecoder().decode(StreamUpdatedEvent.self, from: Data(json.utf8))
        #expect(event.status == .disabled)
        #expect(event.reason == nil)
    }

    @Test("StreamStatus covers all values")
    func streamStatusValues() throws {
        for rawValue in ["enabled", "paused", "disabled"] {
            let json = Data("\"\(rawValue)\"".utf8)
            let status = try JSONDecoder().decode(
                StreamUpdatedEvent.StreamStatus.self,
                from: json
            )
            #expect(status.rawValue == rawValue)
        }
    }

    @Test("SSF event type URIs are correct")
    func ssfEventTypeURIs() {
        let base = "https://schemas.openid.net/secevent/ssf/event-type/"
        #expect(VerificationEvent.eventTypeURI == base + "verification")
        #expect(StreamUpdatedEvent.eventTypeURI == base + "stream-updated")
    }
}
