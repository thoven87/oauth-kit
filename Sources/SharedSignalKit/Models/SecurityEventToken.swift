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

/// Internal JWT payload model used for SET signature verification.
/// The `events` field is decoded as raw JSON for deferred typed decoding.
struct SecurityEventTokenPayload: JWTPayload {
    let iss: IssuerClaim
    let jti: String
    let iat: IssuedAtClaim
    let aud: AudienceClaim
    let txn: String?
    let subId: SubjectIdentifier
    let events: [String: JSONValue]

    enum CodingKeys: String, CodingKey {
        case iss, jti, iat, aud, txn
        case subId = "sub_id"
        case events
    }

    func verify(using algorithm: some JWTAlgorithm) throws {
        guard !jti.isEmpty else {
            throw SharedSignalError.invalidToken("SET is missing a \"jti\" claim")
        }
        guard !events.isEmpty else {
            throw SharedSignalError.invalidToken("SET contains no events")
        }
    }
}

/// A decoded and validated Security Event Token (SET).
///
/// SETs are JWTs defined by RFC 8417 and profiled by the OpenID Shared Signals
/// Framework. They carry security events (RISC, CAEP, etc.) between
/// cooperating transmitters and receivers.
///
/// Use ``SecurityEventDecoder`` to decode and validate raw SET strings into
/// this type.
public struct SecurityEventToken: Sendable {
    /// The issuer of the SET — must match the transmitter configuration.
    public let issuer: String

    /// Unique identifier for this event (for deduplication via `jti` claim).
    public let jti: String

    /// When the SET was issued.
    public let issuedAt: Date

    /// The intended receiver(s) of this SET.
    public let audience: [String]

    /// Optional transaction identifier that correlates related SETs.
    public let transactionId: String?

    /// The primary subject of the event.
    public let subject: SubjectIdentifier

    /// The event type URI (the single key from the `events` claim).
    public let eventType: String

    /// The raw event payload as a JSON value.
    /// Use ``decodeEvent(_:)`` to decode into a specific ``SharedSignalsEvent`` type.
    public let rawEventPayload: JSONValue
}

extension SecurityEventToken {
    /// Decode the raw event payload into a specific ``SharedSignalsEvent`` type.
    ///
    /// - Parameter type: The expected event type (e.g. `AccountDisabledEvent.self`).
    /// - Returns: The decoded event.
    /// - Throws: If the event type URI doesn't match or decoding fails.
    public func decodeEvent<E: SharedSignalsEvent>(_ type: E.Type) throws -> E {
        guard eventType == E.eventTypeURI else {
            throw SharedSignalError.eventTypeMismatch(
                expected: E.eventTypeURI,
                actual: eventType
            )
        }
        let data = try JSONEncoder().encode(rawEventPayload)
        return try JSONDecoder().decode(E.self, from: data)
    }
}

/// Errors from SharedSignalKit operations.
public enum SharedSignalError: Error, LocalizedError, Sendable {
    /// The SET contains an event type URI that doesn't match the expected type.
    case eventTypeMismatch(expected: String, actual: String)

    /// The SET signature verification failed.
    case verificationFailed(String)

    /// The SET has an invalid structure.
    case invalidToken(String)

    /// The audience claim doesn't contain any of the expected values.
    case invalidAudience(expected: [String], actual: [String])

    public var errorDescription: String? {
        switch self {
        case .eventTypeMismatch(let expected, let actual):
            return "Event type mismatch: expected \(expected), got \(actual)"
        case .verificationFailed(let reason):
            return "SET verification failed: \(reason)"
        case .invalidToken(let reason):
            return "Invalid SET: \(reason)"
        case .invalidAudience(let expected, let actual):
            return "Invalid audience: expected one of \(expected), got \(actual)"
        }
    }
}
