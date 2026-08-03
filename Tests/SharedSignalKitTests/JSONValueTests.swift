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
import Testing

@testable import SharedSignalKit

@Suite("JSONValue Tests")
struct JSONValueTests {

    @Test("Decode string")
    func decodeString() throws {
        let json = Data("\"hello\"".utf8)
        let value = try JSONDecoder().decode(JSONValue.self, from: json)
        #expect(value == .string("hello"))
    }

    @Test("Decode integer")
    func decodeInteger() throws {
        let json = Data("42".utf8)
        let value = try JSONDecoder().decode(JSONValue.self, from: json)
        #expect(value == .integer(42))
    }

    @Test("Decode double")
    func decodeDouble() throws {
        let json = Data("3.14".utf8)
        let value = try JSONDecoder().decode(JSONValue.self, from: json)
        #expect(value == .number(3.14))
    }

    @Test("Decode bool true")
    func decodeBoolTrue() throws {
        let json = Data("true".utf8)
        let value = try JSONDecoder().decode(JSONValue.self, from: json)
        #expect(value == .bool(true))
    }

    @Test("Decode bool false")
    func decodeBoolFalse() throws {
        let json = Data("false".utf8)
        let value = try JSONDecoder().decode(JSONValue.self, from: json)
        #expect(value == .bool(false))
    }

    @Test("Decode null")
    func decodeNull() throws {
        let json = Data("null".utf8)
        let value = try JSONDecoder().decode(JSONValue.self, from: json)
        #expect(value == .null)
    }

    @Test("Decode array")
    func decodeArray() throws {
        let json = Data("[1, \"two\", true]".utf8)
        let value = try JSONDecoder().decode(JSONValue.self, from: json)
        #expect(value == .array([.integer(1), .string("two"), .bool(true)]))
    }

    @Test("Decode object")
    func decodeObject() throws {
        let json = Data(
            """
            {"key": "value", "num": 99}
            """.utf8
        )
        let value = try JSONDecoder().decode(JSONValue.self, from: json)
        #expect(value == .object(["key": .string("value"), "num": .integer(99)]))
    }

    @Test("Decode empty object")
    func decodeEmptyObject() throws {
        let json = Data("{}".utf8)
        let value = try JSONDecoder().decode(JSONValue.self, from: json)
        #expect(value == .object([:]))
    }

    @Test("Decode empty array")
    func decodeEmptyArray() throws {
        let json = Data("[]".utf8)
        let value = try JSONDecoder().decode(JSONValue.self, from: json)
        #expect(value == .array([]))
    }

    @Test("Decode nested object")
    func decodeNestedObject() throws {
        let json = Data(
            """
            {"outer": {"inner": 42}}
            """.utf8
        )
        let value = try JSONDecoder().decode(JSONValue.self, from: json)
        #expect(value == .object(["outer": .object(["inner": .integer(42)])]))
    }

    @Test("Decode negative integer")
    func decodeNegativeInteger() throws {
        let json = Data("-7".utf8)
        let value = try JSONDecoder().decode(JSONValue.self, from: json)
        #expect(value == .integer(-7))
    }

    @Test("Round-trip nested structure")
    func roundTripNested() throws {
        let original = JSONValue.object([
            "name": .string("test"),
            "count": .integer(5),
            "ratio": .number(0.75),
            "active": .bool(true),
            "tags": .array([.string("a"), .string("b")]),
            "meta": .null,
        ])

        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(JSONValue.self, from: data)
        #expect(decoded == original)
    }

    @Test("Round-trip primitives")
    func roundTripPrimitives() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        let values: [JSONValue] = [
            .string("hello"),
            .integer(42),
            .number(2.718),
            .bool(true),
            .bool(false),
            .null,
            .array([]),
            .object([:]),
        ]

        for original in values {
            let data = try encoder.encode(original)
            let decoded = try decoder.decode(JSONValue.self, from: data)
            #expect(decoded == original)
        }
    }

    @Test("Decode deeply nested structure")
    func decodeDeeplyNested() throws {
        let json = Data(
            """
            {
                "a": {
                    "b": {
                        "c": [1, 2, {"d": true}]
                    }
                }
            }
            """.utf8
        )
        let value = try JSONDecoder().decode(JSONValue.self, from: json)

        let expected = JSONValue.object([
            "a": .object([
                "b": .object([
                    "c": .array([
                        .integer(1),
                        .integer(2),
                        .object(["d": .bool(true)]),
                    ])
                ])
            ])
        ])
        #expect(value == expected)
    }
}
