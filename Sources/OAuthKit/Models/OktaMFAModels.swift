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

import Foundation

/// Okta MFA challenge response containing available factors
public struct OktaMFAChallenge: Codable, Sendable {
    /// The session token for this MFA session
    public let sessionToken: String?

    /// The state token for this MFA session
    public let stateToken: String

    /// The current status of the authentication
    public let status: OktaMFAStatus

    /// Available MFA factors for the user
    public let factors: [OktaMFAFactor]

    /// Factor result if a factor was just used
    public let factorResult: String?

    /// Links for next actions
    public let links: OktaMFALinks?

    /// Expiration time for this challenge
    public let expiresAt: Date?

    enum CodingKeys: String, CodingKey {
        case sessionToken = "sessionToken"
        case stateToken = "stateToken"
        case status
        case factors = "_embedded"
        case factorResult
        case links = "_links"
        case expiresAt
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        sessionToken = try container.decodeIfPresent(String.self, forKey: .sessionToken)
        stateToken = try container.decode(String.self, forKey: .stateToken)
        status = try container.decode(OktaMFAStatus.self, forKey: .status)
        factorResult = try container.decodeIfPresent(String.self, forKey: .factorResult)
        links = try container.decodeIfPresent(OktaMFALinks.self, forKey: .links)

        // Handle date parsing
        if let expiresAtString = try container.decodeIfPresent(String.self, forKey: .expiresAt) {
            let formatter = ISO8601DateFormatter()
            expiresAt = formatter.date(from: expiresAtString)
        } else {
            expiresAt = nil
        }

        // Parse embedded factors
        if let embedded = try container.decodeIfPresent([String: [OktaMFAFactor]].self, forKey: .factors) {
            factors = embedded["factors"] ?? []
        } else {
            factors = []
        }
    }
}

/// Okta MFA status values
public enum OktaMFAStatus: String, Codable, Sendable {
    case mfaRequired = "MFA_REQUIRED"
    case mfaChallenge = "MFA_CHALLENGE"
    case mfaEnroll = "MFA_ENROLL"
    case success = "SUCCESS"
    case passwordWarn = "PASSWORD_WARN"
    case passwordExpired = "PASSWORD_EXPIRED"
    case recovery = "RECOVERY"
    case recoveryChallenge = "RECOVERY_CHALLENGE"
    case passwordReset = "PASSWORD_RESET"
    case lockedOut = "LOCKED_OUT"
    case tempPasswordChange = "TEMP_PASSWORD_CHANGE"
    case active = "ACTIVE"
    case provisioned = "PROVISIONED"
    case deprovisioned = "DEPROVISIONED"
    case suspended = "SUSPENDED"
    case passwordReset2 = "PASSWORD_RESET2"
    case enrollActivate = "ENROLL_ACTIVATE"
}

/// Okta MFA factor information
public struct OktaMFAFactor: Codable, Sendable {
    /// Unique identifier for this factor
    public let id: String

    /// Type of MFA factor
    public let factorType: OktaMFAFactorType

    /// Provider of the factor (OKTA, GOOGLE, etc.)
    public let provider: String

    /// Vendor name for the factor
    public let vendorName: String?

    /// Status of this factor
    public let status: String

    /// Profile information for this factor
    public let profile: OktaMFAFactorProfile?

    /// Links for factor operations
    public let links: OktaMFAFactorLinks

    /// Factor verification information
    public let verify: OktaMFAFactorVerify?

    enum CodingKeys: String, CodingKey {
        case id
        case factorType
        case provider
        case vendorName
        case status
        case profile
        case links = "_links"
        case verify
    }
}

/// Types of Okta MFA factors
public enum OktaMFAFactorType: String, Codable, Sendable {
    case push = "push"
    case sms = "sms"
    case call = "call"
    case totp = "token:software:totp"
    case hotp = "token:hotp"
    case question = "question"
    case tokenHardware = "token:hardware"
    case email = "email"
    case webauthn = "webauthn"
    case u2f = "u2f"
    case duo = "web"
    case rsaSecurID = "token"
    case symantecVIP = "token:software:totp:symantec"
    case yubikey = "token:hardware:yubikey"

    /// Human-readable name for the factor type
    public var displayName: String {
        switch self {
        case .push:
            return "Okta Verify Push"
        case .sms:
            return "SMS Authentication"
        case .call:
            return "Voice Call Authentication"
        case .totp:
            return "Time-based One-time Password"
        case .hotp:
            return "HMAC-based One-time Password"
        case .question:
            return "Security Question"
        case .tokenHardware:
            return "Hardware Token"
        case .email:
            return "Email Authentication"
        case .webauthn:
            return "WebAuthn"
        case .u2f:
            return "Universal 2nd Factor"
        case .duo:
            return "Duo Security"
        case .rsaSecurID:
            return "RSA SecurID"
        case .symantecVIP:
            return "Symantec VIP"
        case .yubikey:
            return "YubiKey"
        }
    }

    /// Whether this factor requires user interaction
    public var requiresUserInput: Bool {
        switch self {
        case .push:
            return false  // User just approves on device
        case .sms, .call, .totp, .hotp, .question, .tokenHardware, .email, .rsaSecurID, .symantecVIP, .yubikey:
            return true  // User must enter code/answer
        case .webauthn, .u2f:
            return false  // Browser handles interaction
        case .duo:
            return false  // Duo handles interaction
        }
    }
}

/// Profile information for an MFA factor
public struct OktaMFAFactorProfile: Codable, Sendable {
    /// Credential ID for the factor
    public let credentialId: String?

    /// Phone number (for SMS/call factors)
    public let phoneNumber: String?

    /// Email address (for email factors)
    public let email: String?

    /// Question text (for security question factors)
    public let question: String?

    /// Answer to security question
    public let answer: String?

    /// Display name for the factor
    public let name: String?

    /// Version information
    public let version: String?

    enum CodingKeys: String, CodingKey {
        case credentialId
        case phoneNumber
        case email
        case question
        case answer
        case name
        case version
    }
}

/// Links associated with MFA factors
public struct OktaMFAFactorLinks: Codable, Sendable {
    /// Link to verify this factor
    public let verify: OktaMFALink?

    /// Link to activate this factor
    public let activate: OktaMFALink?

    /// Link to poll for factor completion
    public let poll: OktaMFALink?

    /// Link to resend factor challenge
    public let resend: OktaMFALink?

    public struct OktaMFALink: Codable, Sendable {
        public let href: String
        public let method: String?
        public let type: String?

        enum CodingKeys: String, CodingKey {
            case href
            case method
            case type
        }
    }
}

/// Factor verification information
public struct OktaMFAFactorVerify: Codable, Sendable {
    /// Passkey for verification
    public let passKey: String?

    /// Next passkey
    public let nextPassKey: String?

    /// Challenge nonce
    public let challenge: String?

    /// Correct answer (for questions)
    public let correctAnswer: String?

    enum CodingKeys: String, CodingKey {
        case passKey
        case nextPassKey
        case challenge
        case correctAnswer
    }
}

/// Links for MFA challenge operations
public struct OktaMFALinks: Codable, Sendable {
    /// Link to cancel the authentication
    public let cancel: OktaMFAFactorLinks.OktaMFALink?

    /// Link to the next step
    public let next: OktaMFAFactorLinks.OktaMFALink?

    /// Link to previous step
    public let prev: OktaMFAFactorLinks.OktaMFALink?

    /// Link to skip this step
    public let skip: OktaMFAFactorLinks.OktaMFALink?

    /// Link to resend
    public let resend: OktaMFAFactorLinks.OktaMFALink?

    enum CodingKeys: String, CodingKey {
        case cancel
        case next
        case prev
        case skip
        case resend
    }
}

/// Request to verify an MFA factor
public struct OktaMFAVerifyRequest: Codable, Sendable {
    /// The state token from the challenge
    public let stateToken: String

    /// The pass code (for TOTP, SMS, etc.)
    public let passCode: String?

    /// Answer (for security questions)
    public let answer: String?

    /// Auto-push for push notifications
    public let autoPush: Bool?

    /// Remember this device
    public let rememberDevice: Bool?

    public init(
        stateToken: String,
        passCode: String? = nil,
        answer: String? = nil,
        autoPush: Bool? = nil,
        rememberDevice: Bool? = nil
    ) {
        self.stateToken = stateToken
        self.passCode = passCode
        self.answer = answer
        self.autoPush = autoPush
        self.rememberDevice = rememberDevice
    }

    enum CodingKeys: String, CodingKey {
        case stateToken
        case passCode
        case answer
        case autoPush
        case rememberDevice
    }
}

/// Response from MFA factor verification
public struct OktaMFAVerifyResponse: Codable, Sendable {
    /// Session token (if verification successful)
    public let sessionToken: String?

    /// State token for continued flow
    public let stateToken: String?

    /// Current status
    public let status: OktaMFAStatus

    /// Factor result
    public let factorResult: String?

    /// Factor result message
    public let factorResultMessage: String?

    /// Links for next actions
    public let links: OktaMFALinks?

    /// Embedded factors (if status is MFA_CHALLENGE)
    public let factors: [OktaMFAFactor]?

    /// Challenge information for push notifications
    public let challengeContext: OktaMFAChallengeContext?

    enum CodingKeys: String, CodingKey {
        case sessionToken
        case stateToken
        case status
        case factorResult
        case factorResultMessage
        case links = "_links"
        case factors = "_embedded"
        case challengeContext
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        sessionToken = try container.decodeIfPresent(String.self, forKey: .sessionToken)
        stateToken = try container.decodeIfPresent(String.self, forKey: .stateToken)
        status = try container.decode(OktaMFAStatus.self, forKey: .status)
        factorResult = try container.decodeIfPresent(String.self, forKey: .factorResult)
        factorResultMessage = try container.decodeIfPresent(String.self, forKey: .factorResultMessage)
        links = try container.decodeIfPresent(OktaMFALinks.self, forKey: .links)
        challengeContext = try container.decodeIfPresent(OktaMFAChallengeContext.self, forKey: .challengeContext)

        // Parse embedded factors
        if let embedded = try container.decodeIfPresent([String: [OktaMFAFactor]].self, forKey: .factors) {
            factors = embedded["factors"]
        } else {
            factors = nil
        }
    }
}

/// Challenge context for push notifications
public struct OktaMFAChallengeContext: Codable, Sendable {
    /// Challenge number to display to user
    public let challengeNumber: String?

    /// Verification method
    public let verificationMethod: String?

    /// Challenge timeout
    public let timeout: Int?

    enum CodingKeys: String, CodingKey {
        case challengeNumber
        case verificationMethod
        case timeout
    }
}

/// Okta MFA polling result
public struct OktaMFAPollResult: Codable, Sendable {
    /// The current status of the MFA challenge
    public let status: OktaMFAStatus

    /// Factor result
    public let factorResult: String?

    /// Session token if authentication completed
    public let sessionToken: String?

    /// State token for continued flow
    public let stateToken: String?

    /// Links for next actions
    public let links: OktaMFALinks?

    enum CodingKeys: String, CodingKey {
        case status
        case factorResult
        case sessionToken
        case stateToken
        case links = "_links"
    }
}

/// Okta MFA error types
public enum OktaMFAError: Error, CustomStringConvertible {
    /// MFA challenge is required
    case mfaRequired(OktaMFAChallenge)

    /// Factor verification failed
    case factorVerificationFailed(String)

    /// Factor not found or not available
    case factorNotFound

    /// MFA challenge timed out
    case challengeTimeout

    /// User denied/cancelled MFA
    case userDenied

    /// Invalid factor type
    case invalidFactorType(String)

    /// API error
    case apiError(String)

    /// Unknown MFA error
    case unknown(String)

    public var description: String {
        switch self {
        case .mfaRequired:
            return "MFA challenge is required to complete authentication"
        case .factorVerificationFailed(let message):
            return "Factor verification failed: \(message)"
        case .factorNotFound:
            return "Requested MFA factor not found or not available"
        case .challengeTimeout:
            return "MFA challenge timed out"
        case .userDenied:
            return "User denied or cancelled MFA challenge"
        case .invalidFactorType(let type):
            return "Invalid or unsupported factor type: \(type)"
        case .apiError(let message):
            return "Okta API error: \(message)"
        case .unknown(let message):
            return "Unknown MFA error: \(message)"
        }
    }
}
