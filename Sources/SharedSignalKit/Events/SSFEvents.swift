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

// MARK: - SSF Framework Events
// Base URI: https://schemas.openid.net/secevent/ssf/event-type/

/// A verification event used to confirm that a stream is active and reachable.
public struct VerificationEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/ssf/event-type/verification"

    public var state: String?

    public init(state: String? = nil) {
        self.state = state
    }
}

/// Indicates that the configuration of a stream has been updated.
public struct StreamUpdatedEvent: SharedSignalsEvent {
    public static let eventTypeURI = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated"

    public var status: StreamStatus
    public var reason: String?

    public init(status: StreamStatus, reason: String? = nil) {
        self.status = status
        self.reason = reason
    }

    /// The status of a shared signals stream.
    public enum StreamStatus: String, Codable, Sendable {
        case enabled
        case paused
        case disabled
    }
}
