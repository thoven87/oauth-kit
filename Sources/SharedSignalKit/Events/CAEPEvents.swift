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

// MARK: - CAEP Events
// Base URI: https://schemas.openid.net/secevent/caep/event-type/

/// A CAEP event indicating that a session has been revoked.
public struct SessionRevokedEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/caep/event-type/session-revoked"

    public var eventTimestamp: Int?
    public var initiatingEntity: InitiatingEntity?
    public var reasonAdmin: [String: String]?
    public var reasonUser: [String: String]?

    public init(
        eventTimestamp: Int? = nil,
        initiatingEntity: InitiatingEntity? = nil,
        reasonAdmin: [String: String]? = nil,
        reasonUser: [String: String]? = nil
    ) {
        self.eventTimestamp = eventTimestamp
        self.initiatingEntity = initiatingEntity
        self.reasonAdmin = reasonAdmin
        self.reasonUser = reasonUser
    }

    private enum CodingKeys: String, CodingKey {
        case eventTimestamp = "event_timestamp"
        case initiatingEntity = "initiating_entity"
        case reasonAdmin = "reason_admin"
        case reasonUser = "reason_user"
    }
}

/// A CAEP event indicating that token claims have changed.
public struct TokenClaimsChangeEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/caep/event-type/token-claims-change"

    public var claims: [String: JSONValue]
    public var eventTimestamp: Int?
    public var initiatingEntity: InitiatingEntity?
    public var reasonAdmin: [String: String]?
    public var reasonUser: [String: String]?

    public init(
        claims: [String: JSONValue],
        eventTimestamp: Int? = nil,
        initiatingEntity: InitiatingEntity? = nil,
        reasonAdmin: [String: String]? = nil,
        reasonUser: [String: String]? = nil
    ) {
        self.claims = claims
        self.eventTimestamp = eventTimestamp
        self.initiatingEntity = initiatingEntity
        self.reasonAdmin = reasonAdmin
        self.reasonUser = reasonUser
    }

    private enum CodingKeys: String, CodingKey {
        case claims
        case eventTimestamp = "event_timestamp"
        case initiatingEntity = "initiating_entity"
        case reasonAdmin = "reason_admin"
        case reasonUser = "reason_user"
    }
}

/// A CAEP event indicating that a credential has changed.
public struct CredentialChangeEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/caep/event-type/credential-change"

    /// The type of credential change that occurred.
    public enum ChangeType: String, Codable, Sendable {
        case create
        case revoke
        case update
        case delete
    }

    public var credentialType: String
    public var changeType: ChangeType
    public var friendlyName: String?
    public var x509Issuer: String?
    public var x509Serial: String?
    public var fido2Aaguid: String?
    public var eventTimestamp: Int?
    public var initiatingEntity: InitiatingEntity?
    public var reasonAdmin: [String: String]?
    public var reasonUser: [String: String]?

    public init(
        credentialType: String,
        changeType: ChangeType,
        friendlyName: String? = nil,
        x509Issuer: String? = nil,
        x509Serial: String? = nil,
        fido2Aaguid: String? = nil,
        eventTimestamp: Int? = nil,
        initiatingEntity: InitiatingEntity? = nil,
        reasonAdmin: [String: String]? = nil,
        reasonUser: [String: String]? = nil
    ) {
        self.credentialType = credentialType
        self.changeType = changeType
        self.friendlyName = friendlyName
        self.x509Issuer = x509Issuer
        self.x509Serial = x509Serial
        self.fido2Aaguid = fido2Aaguid
        self.eventTimestamp = eventTimestamp
        self.initiatingEntity = initiatingEntity
        self.reasonAdmin = reasonAdmin
        self.reasonUser = reasonUser
    }

    private enum CodingKeys: String, CodingKey {
        case credentialType = "credential_type"
        case changeType = "change_type"
        case friendlyName = "friendly_name"
        case x509Issuer = "x509_issuer"
        case x509Serial = "x509_serial"
        case fido2Aaguid = "fido2_aaguid"
        case eventTimestamp = "event_timestamp"
        case initiatingEntity = "initiating_entity"
        case reasonAdmin = "reason_admin"
        case reasonUser = "reason_user"
    }
}

/// A CAEP event indicating that an assurance level has changed.
public struct AssuranceLevelChangeEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/caep/event-type/assurance-level-change"

    /// The direction in which the assurance level changed.
    public enum ChangeDirection: String, Codable, Sendable {
        case increase
        case decrease
    }

    public var namespace: String
    public var currentLevel: String
    public var previousLevel: String?
    public var changeDirection: ChangeDirection?
    public var eventTimestamp: Int?
    public var initiatingEntity: InitiatingEntity?
    public var reasonAdmin: [String: String]?
    public var reasonUser: [String: String]?

    public init(
        namespace: String,
        currentLevel: String,
        previousLevel: String? = nil,
        changeDirection: ChangeDirection? = nil,
        eventTimestamp: Int? = nil,
        initiatingEntity: InitiatingEntity? = nil,
        reasonAdmin: [String: String]? = nil,
        reasonUser: [String: String]? = nil
    ) {
        self.namespace = namespace
        self.currentLevel = currentLevel
        self.previousLevel = previousLevel
        self.changeDirection = changeDirection
        self.eventTimestamp = eventTimestamp
        self.initiatingEntity = initiatingEntity
        self.reasonAdmin = reasonAdmin
        self.reasonUser = reasonUser
    }

    private enum CodingKeys: String, CodingKey {
        case namespace
        case currentLevel = "current_level"
        case previousLevel = "previous_level"
        case changeDirection = "change_direction"
        case eventTimestamp = "event_timestamp"
        case initiatingEntity = "initiating_entity"
        case reasonAdmin = "reason_admin"
        case reasonUser = "reason_user"
    }
}

/// A CAEP event indicating that a device's compliance status has changed.
public struct DeviceComplianceChangeEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/caep/event-type/device-compliance-change"

    /// The compliance status of a device.
    public enum ComplianceStatus: String, Codable, Sendable {
        case compliant
        case notCompliant = "not-compliant"
    }

    public var currentStatus: ComplianceStatus
    public var previousStatus: ComplianceStatus
    public var eventTimestamp: Int?
    public var initiatingEntity: InitiatingEntity?
    public var reasonAdmin: [String: String]?
    public var reasonUser: [String: String]?

    public init(
        currentStatus: ComplianceStatus,
        previousStatus: ComplianceStatus,
        eventTimestamp: Int? = nil,
        initiatingEntity: InitiatingEntity? = nil,
        reasonAdmin: [String: String]? = nil,
        reasonUser: [String: String]? = nil
    ) {
        self.currentStatus = currentStatus
        self.previousStatus = previousStatus
        self.eventTimestamp = eventTimestamp
        self.initiatingEntity = initiatingEntity
        self.reasonAdmin = reasonAdmin
        self.reasonUser = reasonUser
    }

    private enum CodingKeys: String, CodingKey {
        case currentStatus = "current_status"
        case previousStatus = "previous_status"
        case eventTimestamp = "event_timestamp"
        case initiatingEntity = "initiating_entity"
        case reasonAdmin = "reason_admin"
        case reasonUser = "reason_user"
    }
}

/// A CAEP event indicating that a session has been established.
public struct SessionEstablishedEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/caep/event-type/session-established"

    public var fpUa: String?
    public var acr: String?
    public var amr: [String]?
    public var extId: String?
    public var eventTimestamp: Int?

    public init(
        fpUa: String? = nil,
        acr: String? = nil,
        amr: [String]? = nil,
        extId: String? = nil,
        eventTimestamp: Int? = nil
    ) {
        self.fpUa = fpUa
        self.acr = acr
        self.amr = amr
        self.extId = extId
        self.eventTimestamp = eventTimestamp
    }

    private enum CodingKeys: String, CodingKey {
        case fpUa = "fp_ua"
        case acr
        case amr
        case extId = "ext_id"
        case eventTimestamp = "event_timestamp"
    }
}

/// A CAEP event indicating that a session has been presented.
public struct SessionPresentedEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/caep/event-type/session-presented"

    public var fpUa: String?
    public var extId: String?
    public var eventTimestamp: Int?

    public init(
        fpUa: String? = nil,
        extId: String? = nil,
        eventTimestamp: Int? = nil
    ) {
        self.fpUa = fpUa
        self.extId = extId
        self.eventTimestamp = eventTimestamp
    }

    private enum CodingKeys: String, CodingKey {
        case fpUa = "fp_ua"
        case extId = "ext_id"
        case eventTimestamp = "event_timestamp"
    }
}

/// A CAEP event indicating that a principal's risk level has changed.
public struct RiskLevelChangeEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/caep/event-type/risk-level-change"

    /// The risk level assigned to a principal.
    public enum RiskLevel: String, Codable, Sendable {
        case low = "LOW"
        case medium = "MEDIUM"
        case high = "HIGH"
    }

    public var principal: String
    public var currentLevel: RiskLevel
    public var previousLevel: RiskLevel?
    public var riskReason: String?
    public var eventTimestamp: Int?

    public init(
        principal: String,
        currentLevel: RiskLevel,
        previousLevel: RiskLevel? = nil,
        riskReason: String? = nil,
        eventTimestamp: Int? = nil
    ) {
        self.principal = principal
        self.currentLevel = currentLevel
        self.previousLevel = previousLevel
        self.riskReason = riskReason
        self.eventTimestamp = eventTimestamp
    }

    private enum CodingKeys: String, CodingKey {
        case principal
        case currentLevel = "current_level"
        case previousLevel = "previous_level"
        case riskReason = "risk_reason"
        case eventTimestamp = "event_timestamp"
    }
}
