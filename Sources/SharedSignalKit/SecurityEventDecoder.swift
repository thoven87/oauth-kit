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

import ExtrasBase64
import Foundation
import JWTKit
import Logging
import NIOCore
import NIOFoundationCompat

/// Decodes and validates Security Event Tokens (SETs) from Shared Signals transmitters.
///
/// `SecurityEventDecoder` verifies the SET's cryptographic signature using the
/// provided `JWTKeyCollection`, validates the audience claim, extracts the
/// subject and event type, and provides methods to decode the event payload
/// into strongly-typed ``SharedSignalsEvent`` structs.
///
/// ## Usage
///
/// ```swift
/// let keys = JWTKeyCollection()
/// try await keys.add(jwks: transmitterJWKS)
/// let decoder = SecurityEventDecoder(keys: keys)
///
/// let token = try await decoder.decode(rawSET, audience: ["my-client-id"])
/// let event = try token.decodeEvent(AccountDisabledEvent.self)
/// ```
public struct SecurityEventDecoder: Sendable {
    private let keys: JWTKeyCollection
    private let logger: Logger

    /// Create a new decoder.
    ///
    /// - Parameters:
    ///   - keys: The `JWTKeyCollection` containing the transmitter's public keys.
    ///           This is typically the same collection managed by a JWKS refresh service.
    ///   - logger: Logger for decoder operations.
    public init(
        keys: JWTKeyCollection,
        logger: Logger = Logger(label: "com.shared-signal-kit.SecurityEventDecoder")
    ) {
        self.keys = keys
        self.logger = logger
    }

    /// Decode and validate a Security Event Token.
    ///
    /// This method:
    /// 1. Verifies the SET's cryptographic signature against the key collection
    /// 2. Decodes the JWT payload (iss, jti, iat, aud, sub_id, events)
    /// 3. Validates that the audience contains at least one of the expected values
    /// 4. Extracts the single event type and its raw payload
    ///
    /// - Parameters:
    ///   - token: The raw SET string (a signed JWT).
    ///   - audience: Your client ID(s). The SET's `aud` claim must contain at least one.
    /// - Returns: A decoded ``SecurityEventToken``.
    /// - Throws: ``SharedSignalError`` if validation fails, or `JWTError` if signature verification fails.
    public func decode(
        _ token: String,
        audience: [String]
    ) async throws -> SecurityEventToken {
        // 1. Verify signature and decode JWT payload
        let payload: SecurityEventTokenPayload
        do {
            payload = try await keys.verify(token, as: SecurityEventTokenPayload.self)
        } catch {
            throw SharedSignalError.verificationFailed(String(describing: error))
        }

        // 2. Validate audience
        let tokenAudience = payload.aud.value
        guard tokenAudience.contains(where: { audience.contains($0) }) else {
            throw SharedSignalError.invalidAudience(
                expected: audience,
                actual: tokenAudience
            )
        }

        // 3. Extract the first event (spec says SHOULD be one, but permits
        //    alternative URIs for the same event type)
        let (eventType, eventPayload) = payload.events.first!

        if payload.events.count > 1 {
            logger.warning(
                "SET contains multiple events; only the first will be used",
                metadata: [
                    "eventTypes": .string(payload.events.keys.joined(separator: ", "))
                ]
            )
        }

        // 4. Build the public SecurityEventToken
        return SecurityEventToken(
            issuer: payload.iss.value,
            jti: payload.jti,
            issuedAt: payload.iat.value,
            audience: tokenAudience,
            transactionId: payload.txn,
            subject: payload.subId,
            eventType: eventType,
            rawEventPayload: eventPayload
        )
    }

    /// Decode a SET and extract a typed event in one step.
    ///
    /// Convenience method that combines ``decode(_:audience:)`` with
    /// ``SecurityEventToken/decodeEvent(_:)``.
    ///
    /// - Parameters:
    ///   - token: The raw SET string.
    ///   - eventType: The expected event type.
    ///   - audience: Your client ID(s).
    /// - Returns: A tuple of the decoded token and the typed event.
    public func decode<E: SharedSignalsEvent>(
        _ token: String,
        as eventType: E.Type,
        audience: [String]
    ) async throws -> (token: SecurityEventToken, event: E) {
        let decoded = try await decode(token, audience: audience)
        let event = try decoded.decodeEvent(E.self)
        return (decoded, event)
    }

    /// Peek at the event type URI without performing signature verification.
    ///
    /// Useful for routing incoming SETs to the correct handler before
    /// spending time on cryptographic verification.
    ///
    /// - Parameter token: The raw SET string.
    /// - Returns: The event type URI string.
    /// - Throws: ``SharedSignalError/invalidToken(_:)`` if the token can't be parsed.
    public static func peekEventType(_ token: String) throws -> String {
        // SETs are JWTs: header.payload.signature
        // We only need the payload (second segment), base64url-decoded
        let segments = token.split(separator: ".")
        guard segments.count == 3 else {
            throw SharedSignalError.invalidToken("Expected 3 JWT segments, got \(segments.count)")
        }

        let bytes: [UInt8]
        do {
            bytes = try Base64.decode(
                string: String(segments[1]),
                options: [.base64UrlAlphabet, .omitPaddingCharacter]
            )
        } catch {
            throw SharedSignalError.invalidToken("Invalid base64url in payload segment")
        }

        let buffer = ByteBuffer(bytes: bytes)

        // Decode just enough to extract the event type URI from the "events" key
        guard let envelope = try? JSONDecoder().decode(EventsEnvelope.self, from: buffer),
            let eventType = envelope.events.keys.first
        else {
            throw SharedSignalError.invalidToken("Cannot extract event type from payload")
        }

        return eventType
    }

    /// Minimal decodable used only by ``peekEventType(_:)`` to extract event
    /// type URIs without decoding the full SET payload.
    private struct EventsEnvelope: Decodable {
        let events: [String: EmptyObject]

        fileprivate struct EmptyObject: Decodable {}
    }
}
