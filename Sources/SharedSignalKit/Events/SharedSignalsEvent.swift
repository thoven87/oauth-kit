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

/// Protocol that all RISC, CAEP, and SSF event payload types conform to.
public protocol SharedSignalsEvent: Codable, Sendable {
    /// The canonical event type URI.
    static var eventTypeURI: String { get }
}

/// Shared optional claims used across multiple CAEP event types.
public enum InitiatingEntity: String, Codable, Sendable {
    case admin
    case user
    case policy
    case system
}
