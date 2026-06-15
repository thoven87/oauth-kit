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
import NIOCore
import NIOFoundationCompat

/// Namespace for shared JSON decoding helpers.
///
enum JSON {

    // MARK: - Shared instances
    //
    // JSONEncoder / JSONDecoder are classes whose construction allocates and initialises
    // strategy tables. Both are `Sendable` in Swift 6 and stateless after initialisation
    // (we never mutate date or key strategies), so sharing across concurrent tasks is safe.
    // ByteBufferAllocator stores reusable allocator state; NIO recommends reuse.
    private static let encoder = JSONEncoder()
    private static let decoder = JSONDecoder()
    private static let allocator = ByteBufferAllocator()

    // MARK: - Encode

    /// Encode `value` directly into a `ByteBuffer`.
    ///
    /// `NIOFoundationCompat` provides `encodeAsByteBuffer(_:allocator:)`, which avoids
    /// the intermediate `Data` allocation you'd get from `JSONEncoder.encode` + `ByteBuffer(data:)`.
    static func encode<T: Encodable>(_ value: T) throws -> ByteBuffer {
        try encoder.encodeAsByteBuffer(value, allocator: allocator)
    }

    // MARK: - Decode

    /// Decode `type` from a `ByteBuffer`.
    ///
    /// `NIOFoundationCompat` bridges directly from the buffer's backing storage,
    /// avoiding an intermediate `Data` copy.
    static func decode<T: Decodable>(_ type: T.Type, from buffer: ByteBuffer) throws -> T {
        try decoder.decode(type, from: buffer)
    }

}
