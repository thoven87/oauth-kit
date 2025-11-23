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
import JWTKit

/// A JWT claim that represents a string value
public struct StringClaim: JWTClaim, Equatable, ExpressibleByStringLiteral {
    /// See ``JWTClaim``.
    public var value: String

    /// See ``JWTClaim``.
    public init(value: String) {
        self.value = value
    }

    /// See `ExpressibleByStringLiteral`.
    public init(stringLiteral value: String) {
        self.init(value: value)
    }
}
