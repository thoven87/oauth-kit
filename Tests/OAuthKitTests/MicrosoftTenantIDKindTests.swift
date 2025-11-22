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
import Testing

@testable import OAuthKit

@Suite("MicrosoftTenantIDKind Tests")
struct MicrosoftTenantIDKindTests {

    // MARK: - Basic enum value tests

    @Test("Common tenant kind properties")
    func commonTenantKind() {
        let tenantKind = MicrosoftTenantIDKind.common
        #expect(tenantKind.value == "common")
        #expect(tenantKind.discoveryURL == "https://login.microsoftonline.com/common/v2.0/")
        #expect(tenantKind.description == "common (multi-tenant)")
    }

    @Test("Consumers tenant kind properties")
    func consumersTenantKind() {
        let tenantKind = MicrosoftTenantIDKind.consumers
        #expect(tenantKind.value == "consumers")
        #expect(tenantKind.discoveryURL == "https://login.microsoftonline.com/consumers/v2.0/")
        #expect(tenantKind.description == "consumers (personal accounts only)")
    }

    @Test("Organizations tenant kind properties")
    func organizationsTenantKind() {
        let tenantKind = MicrosoftTenantIDKind.organizations
        #expect(tenantKind.value == "organizations")
        #expect(tenantKind.discoveryURL == "https://login.microsoftonline.com/organizations/v2.0/")
        #expect(tenantKind.description == "organizations (work/school accounts only)")
    }

    @Test("Custom tenant kind with GUID")
    func customTenantKindWithGUID() {
        let tenantId = "8eaef023-2b34-4da1-9baa-8bc8c9d6a490"
        let tenantKind = MicrosoftTenantIDKind.custom(tenantId)
        #expect(tenantKind.value == tenantId)
        #expect(tenantKind.discoveryURL == "https://login.microsoftonline.com/\(tenantId)/v2.0/")
        #expect(tenantKind.description == "custom tenant (\(tenantId))")
    }

    @Test("Custom tenant kind with domain")
    func customTenantKindWithDomain() {
        let domain = "contoso.com"
        let tenantKind = MicrosoftTenantIDKind.custom(domain)
        #expect(tenantKind.value == domain)
        #expect(tenantKind.discoveryURL == "https://login.microsoftonline.com/\(domain)/v2.0/")
        #expect(tenantKind.description == "custom tenant (\(domain))")
    }

    // MARK: - From value factory method tests

    @Test("From value factory method - common")
    func fromValueCommon() {
        let tenantKind = MicrosoftTenantIDKind.from(value: "common")
        #expect(tenantKind == .common)
    }

    @Test("From value factory method - common case insensitive")
    func fromValueCommonCaseInsensitive() {
        let tenantKind = MicrosoftTenantIDKind.from(value: "COMMON")
        #expect(tenantKind == .common)
    }

    @Test("From value factory method - consumers")
    func fromValueConsumers() {
        let tenantKind = MicrosoftTenantIDKind.from(value: "consumers")
        #expect(tenantKind == .consumers)
    }

    @Test("From value factory method - consumers case insensitive")
    func fromValueConsumersCaseInsensitive() {
        let tenantKind = MicrosoftTenantIDKind.from(value: "CONSUMERS")
        #expect(tenantKind == .consumers)
    }

    @Test("From value factory method - organizations")
    func fromValueOrganizations() {
        let tenantKind = MicrosoftTenantIDKind.from(value: "organizations")
        #expect(tenantKind == .organizations)
    }

    @Test("From value factory method - organizations case insensitive")
    func fromValueOrganizationsCaseInsensitive() {
        let tenantKind = MicrosoftTenantIDKind.from(value: "ORGANIZATIONS")
        #expect(tenantKind == .organizations)
    }

    @Test("From value factory method - custom GUID")
    func fromValueCustomGUID() {
        let tenantId = "8eaef023-2b34-4da1-9baa-8bc8c9d6a490"
        let tenantKind = MicrosoftTenantIDKind.from(value: tenantId)
        #expect(tenantKind == .custom(tenantId))
    }

    @Test("From value factory method - custom domain")
    func fromValueCustomDomain() {
        let domain = "contoso.com"
        let tenantKind = MicrosoftTenantIDKind.from(value: domain)
        #expect(tenantKind == .custom(domain))
    }

    @Test("From value factory method - empty string defaults to common")
    func fromValueEmptyString() {
        let tenantKind = MicrosoftTenantIDKind.from(value: "")
        #expect(tenantKind == .common)
    }

    @Test("From value factory method - whitespace only defaults to common")
    func fromValueWhitespaceOnly() {
        let tenantKind = MicrosoftTenantIDKind.from(value: "   ")
        #expect(tenantKind == .common)
    }

    // MARK: - RawRepresentable tests

    @Test("RawRepresentable conformance - common")
    func rawRepresentableCommon() {
        let tenantKind = MicrosoftTenantIDKind.common
        #expect(tenantKind.rawValue == "common")

        let fromRaw = MicrosoftTenantIDKind(rawValue: "common")
        #expect(fromRaw == .common)
    }

    @Test("RawRepresentable conformance - consumers")
    func rawRepresentableConsumers() {
        let tenantKind = MicrosoftTenantIDKind.consumers
        #expect(tenantKind.rawValue == "consumers")

        let fromRaw = MicrosoftTenantIDKind(rawValue: "consumers")
        #expect(fromRaw == .consumers)
    }

    @Test("RawRepresentable conformance - organizations")
    func rawRepresentableOrganizations() {
        let tenantKind = MicrosoftTenantIDKind.organizations
        #expect(tenantKind.rawValue == "organizations")

        let fromRaw = MicrosoftTenantIDKind(rawValue: "organizations")
        #expect(fromRaw == .organizations)
    }

    @Test("RawRepresentable conformance - custom")
    func rawRepresentableCustom() {
        let tenantId = "8eaef023-2b34-4da1-9baa-8bc8c9d6a490"
        let tenantKind = MicrosoftTenantIDKind.custom(tenantId)
        #expect(tenantKind.rawValue == tenantId)

        let fromRaw = MicrosoftTenantIDKind(rawValue: tenantId)
        #expect(fromRaw == .custom(tenantId))
    }

    @Test("RawRepresentable conformance - empty string defaults to common")
    func rawRepresentableEmptyString() {
        let fromRaw = MicrosoftTenantIDKind(rawValue: "")
        #expect(fromRaw == .common)
        #expect(fromRaw?.rawValue == "common")
    }

    @Test("RawRepresentable conformance - whitespace defaults to common")
    func rawRepresentableWhitespace() {
        let fromRaw = MicrosoftTenantIDKind(rawValue: "   ")
        #expect(fromRaw == .common)
        #expect(fromRaw?.rawValue == "common")
    }

    // MARK: - ExpressibleByStringLiteral tests

    @Test("String literal support - common")
    func stringLiteralCommon() {
        let tenantKind: MicrosoftTenantIDKind = "common"
        #expect(tenantKind == .common)
    }

    @Test("String literal support - consumers")
    func stringLiteralConsumers() {
        let tenantKind: MicrosoftTenantIDKind = "consumers"
        #expect(tenantKind == .consumers)
    }

    @Test("String literal support - organizations")
    func stringLiteralOrganizations() {
        let tenantKind: MicrosoftTenantIDKind = "organizations"
        #expect(tenantKind == .organizations)
    }

    @Test("String literal support - custom GUID")
    func stringLiteralCustomGUID() {
        let tenantId = "8eaef023-2b34-4da1-9baa-8bc8c9d6a490"
        let tenantKind: MicrosoftTenantIDKind = "8eaef023-2b34-4da1-9baa-8bc8c9d6a490"
        #expect(tenantKind == .custom(tenantId))
    }

    @Test("String literal support - custom domain")
    func stringLiteralCustomDomain() {
        let domain = "contoso.com"
        let tenantKind: MicrosoftTenantIDKind = "contoso.com"
        #expect(tenantKind == .custom(domain))
    }

    @Test("String literal support - empty string defaults to common")
    func stringLiteralEmptyString() {
        let tenantKind: MicrosoftTenantIDKind = ""
        #expect(tenantKind == .common)
    }

    @Test("String literal support - whitespace only defaults to common")
    func stringLiteralWhitespaceOnly() {
        let tenantKind: MicrosoftTenantIDKind = "   "
        #expect(tenantKind == .common)
    }

    // MARK: - Equatable tests

    @Test("Equality - same cases")
    func equalitySameCases() {
        #expect(MicrosoftTenantIDKind.common == MicrosoftTenantIDKind.common)
        #expect(MicrosoftTenantIDKind.consumers == MicrosoftTenantIDKind.consumers)
        #expect(MicrosoftTenantIDKind.organizations == MicrosoftTenantIDKind.organizations)

        let tenantId = "8eaef023-2b34-4da1-9baa-8bc8c9d6a490"
        #expect(MicrosoftTenantIDKind.custom(tenantId) == MicrosoftTenantIDKind.custom(tenantId))
    }

    @Test("Inequality - different custom values")
    func inequalityCustomDifferent() {
        #expect(MicrosoftTenantIDKind.custom("tenant1") != MicrosoftTenantIDKind.custom("tenant2"))
    }

    @Test("Inequality - different cases")
    func inequalityDifferentCases() {
        #expect(MicrosoftTenantIDKind.common != MicrosoftTenantIDKind.consumers)
        #expect(MicrosoftTenantIDKind.consumers != MicrosoftTenantIDKind.organizations)
        #expect(MicrosoftTenantIDKind.common != MicrosoftTenantIDKind.custom("test"))
    }

    // MARK: - Discovery URL format tests

    @Test("Discovery URL formats correctly for all cases")
    func discoveryURLFormats() {
        let testCases: [(MicrosoftTenantIDKind, String)] = [
            (.common, "https://login.microsoftonline.com/common/v2.0/"),
            (.consumers, "https://login.microsoftonline.com/consumers/v2.0/"),
            (.organizations, "https://login.microsoftonline.com/organizations/v2.0/"),
            (.custom("contoso.com"), "https://login.microsoftonline.com/contoso.com/v2.0/"),
            (.custom("8eaef023-2b34-4da1-9baa-8bc8c9d6a490"), "https://login.microsoftonline.com/8eaef023-2b34-4da1-9baa-8bc8c9d6a490/v2.0/"),
        ]

        for (tenantKind, expectedURL) in testCases {
            #expect(tenantKind.discoveryURL == expectedURL)
        }
    }

    // MARK: - Edge cases

    @Test("Custom tenant can accept any non-empty string")
    func customTenantAcceptsAnyValue() {
        let customValue = "any-custom-value"
        let tenantKind = MicrosoftTenantIDKind.custom(customValue)
        #expect(tenantKind.value == customValue)
        #expect(tenantKind.discoveryURL == "https://login.microsoftonline.com/\(customValue)/v2.0/")
    }

    // MARK: - Static factory method on MicrosoftOAuthProvider

    @Test("MicrosoftOAuthProvider discoveryURL factory method")
    func microsoftOAuthProviderDiscoveryURL() {
        let commonURL = MicrosoftOAuthProvider.discoveryURL(for: .common)
        #expect(commonURL == "https://login.microsoftonline.com/common/v2.0/")

        let customURL = MicrosoftOAuthProvider.discoveryURL(for: .custom("contoso.com"))
        #expect(customURL == "https://login.microsoftonline.com/contoso.com/v2.0/")
    }
}
