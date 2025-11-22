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

/// A type-erasing Codable wrapper for handling arbitrary JSON types
internal struct AnyCodable: Codable, Equatable, @unchecked Sendable {
    private let value: Any
    private let encode: (Encoder) throws -> Void

    internal init<T: Codable>(_ value: T) {
        self.value = value
        self.encode = { encoder in
            try value.encode(to: encoder)
        }
    }

    internal init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        if container.decodeNil() {
            self.value = NullValue()
            self.encode = { encoder in
                var container = encoder.singleValueContainer()
                try container.encodeNil()
            }
        } else if let bool = try? container.decode(Bool.self) {
            self.value = bool
            self.encode = { encoder in
                var container = encoder.singleValueContainer()
                try container.encode(bool)
            }
        } else if let int = try? container.decode(Int.self) {
            self.value = int
            self.encode = { encoder in
                var container = encoder.singleValueContainer()
                try container.encode(int)
            }
        } else if let double = try? container.decode(Double.self) {
            self.value = double
            self.encode = { encoder in
                var container = encoder.singleValueContainer()
                try container.encode(double)
            }
        } else if let string = try? container.decode(String.self) {
            self.value = string
            self.encode = { encoder in
                var container = encoder.singleValueContainer()
                try container.encode(string)
            }
        } else if let array = try? container.decode([AnyCodable].self) {
            self.value = array
            self.encode = { encoder in
                var container = encoder.singleValueContainer()
                try container.encode(array)
            }
        } else if let dictionary = try? container.decode([String: AnyCodable].self) {
            self.value = dictionary
            self.encode = { encoder in
                var container = encoder.singleValueContainer()
                try container.encode(dictionary)
            }
        } else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Unable to decode AnyCodable value"
            )
        }
    }

    internal func encode(to encoder: Encoder) throws {
        try encode(encoder)
    }

    internal static func == (lhs: AnyCodable, rhs: AnyCodable) -> Bool {
        isEqual(lhs.value, rhs.value)
    }

    /// Get the underlying value
    internal var underlying: Any {
        value
    }

    /// Try to cast to a specific type
    internal func cast<T>(to type: T.Type) -> T? {
        value as? T
    }
}

/// Simple null value placeholder
private struct NullValue: Equatable {
    static func == (lhs: NullValue, rhs: NullValue) -> Bool {
        true
    }
}

/// Helper function for comparing Any values
private func isEqual(_ lhs: Any, _ rhs: Any) -> Bool {
    if lhs is NullValue && rhs is NullValue {
        return true
    } else if let lhsString = lhs as? String, let rhsString = rhs as? String {
        return lhsString == rhsString
    } else if let lhsInt = lhs as? Int, let rhsInt = rhs as? Int {
        return lhsInt == rhsInt
    } else if let lhsDouble = lhs as? Double, let rhsDouble = rhs as? Double {
        return lhsDouble == rhsDouble
    } else if let lhsBool = lhs as? Bool, let rhsBool = rhs as? Bool {
        return lhsBool == rhsBool
    } else if let lhsArray = lhs as? [AnyCodable], let rhsArray = rhs as? [AnyCodable] {
        return lhsArray == rhsArray
    } else if let lhsDict = lhs as? [String: AnyCodable], let rhsDict = rhs as? [String: AnyCodable] {
        return lhsDict == rhsDict
    }

    return false
}

/// Helper for decoding dynamic keys
internal struct AnyCodingKey: CodingKey {
    var stringValue: String
    var intValue: Int?

    init?(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init?(intValue: Int) {
        self.stringValue = String(intValue)
        self.intValue = intValue
    }
}
