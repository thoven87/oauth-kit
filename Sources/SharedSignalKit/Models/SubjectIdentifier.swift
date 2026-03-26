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

// MARK: - ComplexSubject

/// A complex subject identifier that combines multiple subject identifiers
/// to represent a multi-dimensional identity context, as defined by the
/// Shared Signals Framework.
public struct ComplexSubject: Codable, Sendable, Equatable {
    public var user: SubjectIdentifier?
    public var device: SubjectIdentifier?
    public var session: SubjectIdentifier?
    public var application: SubjectIdentifier?
    public var tenant: SubjectIdentifier?
    public var orgUnit: SubjectIdentifier?
    public var group: SubjectIdentifier?

    private enum CodingKeys: String, CodingKey {
        case user
        case device
        case session
        case application
        case tenant
        case orgUnit = "org_unit"
        case group
    }

    public init(
        user: SubjectIdentifier? = nil,
        device: SubjectIdentifier? = nil,
        session: SubjectIdentifier? = nil,
        application: SubjectIdentifier? = nil,
        tenant: SubjectIdentifier? = nil,
        orgUnit: SubjectIdentifier? = nil,
        group: SubjectIdentifier? = nil
    ) {
        self.user = user
        self.device = device
        self.session = session
        self.application = application
        self.tenant = tenant
        self.orgUnit = orgUnit
        self.group = group
    }
}

// MARK: - SubjectIdentifier

/// A subject identifier as defined in RFC 9493 (Subject Identifiers for
/// Security Event Tokens), with additional formats from the Shared Signals
/// Framework.
///
/// Each case corresponds to a distinct identifier format, discriminated by the
/// `"format"` field in the JSON representation.
public indirect enum SubjectIdentifier: Codable, Sendable, Equatable {
    /// An email-based subject identifier (`"format": "email"`).
    case email(String)

    /// A phone-number-based subject identifier (`"format": "phone_number"`).
    case phone(String)

    /// An issuer-and-subject pair (`"format": "iss_sub"`).
    case issuerSubject(iss: String, sub: String)

    /// An opaque identifier (`"format": "opaque"`).
    case opaque(id: String)

    /// A JWT ID subject identifier (`"format": "jwt_id"`).
    case jwtId(iss: String, jti: String)

    /// A SAML assertion ID subject identifier (`"format": "saml_assertion_id"`).
    case samlAssertionId(issuer: String, assertionId: String)

    /// An IP-addresses subject identifier (`"format": "ip-addresses"`).
    case ipAddresses([String])

    /// A complex subject combining multiple identifiers (`"format": "complex"`).
    case complex(ComplexSubject)

    // MARK: CodingKeys

    private enum CodingKeys: String, CodingKey {
        case format
        case email
        case phoneNumber = "phone_number"
        case iss
        case sub
        case id
        case jti
        case issuer
        case assertionId = "assertion_id"
        case ipAddresses = "ip-addresses"
        case user
        case device
        case session
        case application
        case tenant
        case orgUnit = "org_unit"
        case group
    }

    // MARK: Decodable

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let format = try container.decode(String.self, forKey: .format)

        switch format {
        case "email":
            let value = try container.decode(String.self, forKey: .email)
            self = .email(value)

        case "phone_number":
            let value = try container.decode(String.self, forKey: .phoneNumber)
            self = .phone(value)

        case "iss_sub":
            let iss = try container.decode(String.self, forKey: .iss)
            let sub = try container.decode(String.self, forKey: .sub)
            self = .issuerSubject(iss: iss, sub: sub)

        case "opaque":
            let id = try container.decode(String.self, forKey: .id)
            self = .opaque(id: id)

        case "jwt_id":
            let iss = try container.decode(String.self, forKey: .iss)
            let jti = try container.decode(String.self, forKey: .jti)
            self = .jwtId(iss: iss, jti: jti)

        case "saml_assertion_id":
            let issuer = try container.decode(String.self, forKey: .issuer)
            let assertionId = try container.decode(String.self, forKey: .assertionId)
            self = .samlAssertionId(issuer: issuer, assertionId: assertionId)

        case "ip-addresses":
            let addresses = try container.decode([String].self, forKey: .ipAddresses)
            self = .ipAddresses(addresses)

        case "complex":
            let complexSubject = ComplexSubject(
                user: try container.decodeIfPresent(SubjectIdentifier.self, forKey: .user),
                device: try container.decodeIfPresent(SubjectIdentifier.self, forKey: .device),
                session: try container.decodeIfPresent(SubjectIdentifier.self, forKey: .session),
                application: try container.decodeIfPresent(SubjectIdentifier.self, forKey: .application),
                tenant: try container.decodeIfPresent(SubjectIdentifier.self, forKey: .tenant),
                orgUnit: try container.decodeIfPresent(SubjectIdentifier.self, forKey: .orgUnit),
                group: try container.decodeIfPresent(SubjectIdentifier.self, forKey: .group)
            )
            self = .complex(complexSubject)

        default:
            throw DecodingError.dataCorruptedError(
                forKey: .format,
                in: container,
                debugDescription: "Unknown subject identifier format: \(format)"
            )
        }
    }

    // MARK: Encodable

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)

        switch self {
        case .email(let value):
            try container.encode("email", forKey: .format)
            try container.encode(value, forKey: .email)

        case .phone(let value):
            try container.encode("phone_number", forKey: .format)
            try container.encode(value, forKey: .phoneNumber)

        case .issuerSubject(let iss, let sub):
            try container.encode("iss_sub", forKey: .format)
            try container.encode(iss, forKey: .iss)
            try container.encode(sub, forKey: .sub)

        case .opaque(let id):
            try container.encode("opaque", forKey: .format)
            try container.encode(id, forKey: .id)

        case .jwtId(let iss, let jti):
            try container.encode("jwt_id", forKey: .format)
            try container.encode(iss, forKey: .iss)
            try container.encode(jti, forKey: .jti)

        case .samlAssertionId(let issuer, let assertionId):
            try container.encode("saml_assertion_id", forKey: .format)
            try container.encode(issuer, forKey: .issuer)
            try container.encode(assertionId, forKey: .assertionId)

        case .ipAddresses(let addresses):
            try container.encode("ip-addresses", forKey: .format)
            try container.encode(addresses, forKey: .ipAddresses)

        case .complex(let complexSubject):
            try container.encode("complex", forKey: .format)
            try container.encodeIfPresent(complexSubject.user, forKey: .user)
            try container.encodeIfPresent(complexSubject.device, forKey: .device)
            try container.encodeIfPresent(complexSubject.session, forKey: .session)
            try container.encodeIfPresent(complexSubject.application, forKey: .application)
            try container.encodeIfPresent(complexSubject.tenant, forKey: .tenant)
            try container.encodeIfPresent(complexSubject.orgUnit, forKey: .orgUnit)
            try container.encodeIfPresent(complexSubject.group, forKey: .group)
        }
    }
}
