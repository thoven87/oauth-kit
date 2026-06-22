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

// MARK: - RISC Events
// Base URI: https://schemas.openid.net/secevent/risc/event-type/

/// Signals that the account holder should be prompted to change their credentials.
public struct AccountCredentialChangeRequiredEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/risc/event-type/account-credential-change-required"
}

/// Signals that the account has been permanently purged.
public struct AccountPurgedEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/risc/event-type/account-purged"
}

/// Signals that the account has been disabled.
public struct AccountDisabledEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/risc/event-type/account-disabled"

    public enum Reason: String, Codable, Sendable {
        case hijacking
        case bulkAccount = "bulk-account"
    }

    public var reason: Reason?

    public init(reason: Reason? = nil) {
        self.reason = reason
    }
}

/// Signals that the account has been enabled.
public struct AccountEnabledEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/risc/event-type/account-enabled"
}

/// Signals that the account identifier has changed.
public struct IdentifierChangedEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/risc/event-type/identifier-changed"

    public var newValue: String?

    enum CodingKeys: String, CodingKey {
        case newValue = "new-value"
    }

    public init(newValue: String? = nil) {
        self.newValue = newValue
    }
}

/// Signals that the account identifier has been recycled and may now refer to a different user.
public struct IdentifierRecycledEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/risc/event-type/identifier-recycled"
}

/// Signals that a credential has been compromised.
public struct CredentialCompromiseEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/risc/event-type/credential-compromise"

    public var credentialType: String
    public var eventTimestamp: Int?
    public var reasonAdmin: [String: String]?
    public var reasonUser: [String: String]?

    enum CodingKeys: String, CodingKey {
        case credentialType = "credential_type"
        case eventTimestamp = "event_timestamp"
        case reasonAdmin = "reason_admin"
        case reasonUser = "reason_user"
    }

    public init(
        credentialType: String,
        eventTimestamp: Int? = nil,
        reasonAdmin: [String: String]? = nil,
        reasonUser: [String: String]? = nil
    ) {
        self.credentialType = credentialType
        self.eventTimestamp = eventTimestamp
        self.reasonAdmin = reasonAdmin
        self.reasonUser = reasonUser
    }
}

/// Signals that all sessions for the account have been revoked.
///
/// - Note: This event type is deprecated in favor of the CAEP ``SessionRevokedEvent``.
public struct SessionsRevokedEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/risc/event-type/sessions-revoked"
}

/// Signals that a recovery mechanism has been activated for the account.
public struct RecoveryActivatedEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/risc/event-type/recovery-activated"
}

/// Signals that the recovery information for the account has changed.
public struct RecoveryInformationChangedEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/risc/event-type/recovery-information-changed"
}

/// Signals that the subject has opted in to event sharing.
public struct OptInEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/risc/event-type/opt-in"
}

/// Signals that the subject has initiated an opt-out from event sharing.
public struct OptOutInitiatedEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/risc/event-type/opt-out-initiated"
}

/// Signals that the subject has cancelled an opt-out from event sharing.
public struct OptOutCancelledEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/risc/event-type/opt-out-cancelled"
}

/// Signals that the subject's opt-out from event sharing is now effective.
public struct OptOutEffectiveEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/risc/event-type/opt-out-effective"
}
