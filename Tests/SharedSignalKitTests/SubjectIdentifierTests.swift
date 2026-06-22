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

@Suite("SubjectIdentifier Tests")
struct SubjectIdentifierTests {

    // MARK: - Simple Format Decoding

    @Test("Decode email subject identifier")
    func decodeEmail() throws {
        let json = """
            {"format": "email", "email": "foo@example.com"}
            """
        let subject = try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))
        #expect(subject == .email("foo@example.com"))
    }

    @Test("Decode phone subject identifier")
    func decodePhone() throws {
        let json = """
            {"format": "phone_number", "phone_number": "+12065550123"}
            """
        let subject = try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))
        #expect(subject == .phone("+12065550123"))
    }

    @Test("Decode iss_sub subject identifier")
    func decodeIssuerSubject() throws {
        let json = """
            {"format": "iss_sub", "iss": "https://idp.example.com/", "sub": "12345"}
            """
        let subject = try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))
        #expect(subject == .issuerSubject(iss: "https://idp.example.com/", sub: "12345"))
    }

    @Test("Decode opaque subject identifier")
    func decodeOpaque() throws {
        let json = """
            {"format": "opaque", "id": "abc-123"}
            """
        let subject = try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))
        #expect(subject == .opaque(id: "abc-123"))
    }

    @Test("Decode jwt_id subject identifier")
    func decodeJwtId() throws {
        let json = """
            {"format": "jwt_id", "iss": "https://idp.example.com/", "jti": "B70BA622"}
            """
        let subject = try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))
        #expect(subject == .jwtId(iss: "https://idp.example.com/", jti: "B70BA622"))
    }

    @Test("Decode saml_assertion_id subject identifier")
    func decodeSamlAssertionId() throws {
        let json = """
            {"format": "saml_assertion_id", "issuer": "https://idp.example.com/", "assertion_id": "_8e8dc5f69a98cc4c"}
            """
        let subject = try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))
        #expect(
            subject
                == .samlAssertionId(
                    issuer: "https://idp.example.com/",
                    assertionId: "_8e8dc5f69a98cc4c"
                )
        )
    }

    @Test("Decode ip-addresses subject identifier")
    func decodeIpAddresses() throws {
        let json = """
            {"format": "ip-addresses", "ip-addresses": ["10.0.0.1", "2001:db8::1"]}
            """
        let subject = try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))
        #expect(subject == .ipAddresses(["10.0.0.1", "2001:db8::1"]))
    }

    // MARK: - Complex Subject Decoding

    @Test("Decode complex subject with user and tenant")
    func decodeComplexUserTenant() throws {
        let json = """
            {
                "format": "complex",
                "user": {"format": "email", "email": "jane@example.com"},
                "tenant": {"format": "opaque", "id": "tenant-123"}
            }
            """
        let subject = try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))
        let expected = SubjectIdentifier.complex(
            ComplexSubject(
                user: .email("jane@example.com"),
                tenant: .opaque(id: "tenant-123")
            )
        )
        #expect(subject == expected)
    }

    @Test("Decode complex subject with user, device, and tenant")
    func decodeComplexUserDeviceTenant() throws {
        let json = """
            {
                "format": "complex",
                "user": {
                    "format": "iss_sub",
                    "iss": "https://idp.example.com/123/",
                    "sub": "jane.smith@example.com"
                },
                "device": {
                    "format": "iss_sub",
                    "iss": "https://idp.example.com/123/",
                    "sub": "e9297990-14d2-42ec-a4a9-4036db86509a"
                },
                "tenant": {
                    "format": "opaque",
                    "id": "123456789"
                }
            }
            """
        let subject = try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))

        guard case .complex(let complex) = subject else {
            Issue.record("Expected complex subject")
            return
        }

        #expect(
            complex.user
                == .issuerSubject(
                    iss: "https://idp.example.com/123/",
                    sub: "jane.smith@example.com"
                )
        )
        #expect(
            complex.device
                == .issuerSubject(
                    iss: "https://idp.example.com/123/",
                    sub: "e9297990-14d2-42ec-a4a9-4036db86509a"
                )
        )
        #expect(complex.tenant == .opaque(id: "123456789"))
        #expect(complex.session == nil)
        #expect(complex.application == nil)
        #expect(complex.orgUnit == nil)
        #expect(complex.group == nil)
    }

    @Test("Decode complex subject with org_unit")
    func decodeComplexOrgUnit() throws {
        let json = """
            {
                "format": "complex",
                "org_unit": {"format": "opaque", "id": "ou-finance"}
            }
            """
        let subject = try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))

        guard case .complex(let complex) = subject else {
            Issue.record("Expected complex subject")
            return
        }

        #expect(complex.orgUnit == .opaque(id: "ou-finance"))
    }

    @Test("Decode complex subject with only session")
    func decodeComplexSessionOnly() throws {
        let json = """
            {
                "format": "complex",
                "session": {"format": "opaque", "id": "session-abc"}
            }
            """
        let subject = try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))
        let expected = SubjectIdentifier.complex(
            ComplexSubject(session: .opaque(id: "session-abc"))
        )
        #expect(subject == expected)
    }

    // MARK: - Round-Trip Encoding / Decoding

    @Test("Round-trip encode/decode preserves all simple formats")
    func roundTripSimple() throws {
        let subjects: [SubjectIdentifier] = [
            .email("test@example.com"),
            .phone("+15551234567"),
            .issuerSubject(iss: "https://issuer.example.com", sub: "user-42"),
            .opaque(id: "opaque-id"),
            .jwtId(iss: "https://issuer.example.com", jti: "jwt-id-1"),
            .samlAssertionId(issuer: "https://idp.example.com", assertionId: "assert-1"),
            .ipAddresses(["192.168.1.1", "10.0.0.1"]),
        ]

        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        for original in subjects {
            let data = try encoder.encode(original)
            let decoded = try decoder.decode(SubjectIdentifier.self, from: data)
            #expect(decoded == original)
        }
    }

    @Test("Round-trip encode/decode preserves complex subject")
    func roundTripComplex() throws {
        let original = SubjectIdentifier.complex(
            ComplexSubject(
                user: .email("u@example.com"),
                device: .opaque(id: "device-1"),
                tenant: .issuerSubject(iss: "https://issuer.example.com", sub: "t-1"),
                group: .opaque(id: "group-a")
            )
        )

        let data = try JSONEncoder().encode(original)
        let decoded = try JSONDecoder().decode(SubjectIdentifier.self, from: data)
        #expect(decoded == original)
    }

    @Test("Encoded email subject contains correct format field")
    func encodedEmailHasFormatField() throws {
        let subject = SubjectIdentifier.email("test@example.com")
        let data = try JSONEncoder().encode(subject)
        let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any]

        #expect(dict?["format"] as? String == "email")
        #expect(dict?["email"] as? String == "test@example.com")
    }

    @Test("Encoded complex subject inlines fields at top level")
    func encodedComplexInlinesFields() throws {
        let subject = SubjectIdentifier.complex(
            ComplexSubject(user: .email("u@example.com"))
        )
        let data = try JSONEncoder().encode(subject)
        let dict = try JSONSerialization.jsonObject(with: data) as? [String: Any]

        #expect(dict?["format"] as? String == "complex")
        // user should be inlined, not nested under a "complex" wrapper
        #expect(dict?["user"] is [String: Any])
    }

    // MARK: - Error Handling

    @Test("Unknown format throws DecodingError")
    func unknownFormat() throws {
        let json = """
            {"format": "unknown_format", "value": "something"}
            """
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))
        }
    }

    @Test("Missing format field throws DecodingError")
    func missingFormat() throws {
        let json = """
            {"email": "foo@example.com"}
            """
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))
        }
    }

    @Test("Email format missing email field throws DecodingError")
    func emailMissingField() throws {
        let json = """
            {"format": "email"}
            """
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))
        }
    }

    @Test("iss_sub format missing sub field throws DecodingError")
    func issSubMissingSub() throws {
        let json = """
            {"format": "iss_sub", "iss": "https://example.com"}
            """
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))
        }
    }

    // MARK: - ComplexSubject Direct Tests

    @Test("ComplexSubject with all nil fields decodes from empty complex")
    func complexSubjectAllNil() throws {
        let json = """
            {"format": "complex"}
            """
        let subject = try JSONDecoder().decode(SubjectIdentifier.self, from: Data(json.utf8))

        guard case .complex(let complex) = subject else {
            Issue.record("Expected complex subject")
            return
        }

        #expect(complex.user == nil)
        #expect(complex.device == nil)
        #expect(complex.session == nil)
        #expect(complex.application == nil)
        #expect(complex.tenant == nil)
        #expect(complex.orgUnit == nil)
        #expect(complex.group == nil)
    }

    // MARK: - Equatable

    @Test("Different subject formats are not equal")
    func differentFormatsNotEqual() {
        let email = SubjectIdentifier.email("test@example.com")
        let opaque = SubjectIdentifier.opaque(id: "test@example.com")
        #expect(email != opaque)
    }

    @Test("Same format different values are not equal")
    func sameFormatDifferentValues() {
        let a = SubjectIdentifier.email("a@example.com")
        let b = SubjectIdentifier.email("b@example.com")
        #expect(a != b)
    }

    @Test("Same format same values are equal")
    func sameFormatSameValues() {
        let a = SubjectIdentifier.issuerSubject(iss: "https://example.com", sub: "user-1")
        let b = SubjectIdentifier.issuerSubject(iss: "https://example.com", sub: "user-1")
        #expect(a == b)
    }
}
