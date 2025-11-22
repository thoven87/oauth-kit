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

/// Defines the different types of Microsoft tenant IDs for Azure AD authentication
public enum MicrosoftTenantIDKind: Sendable, Equatable {
    /// Users with both a personal Microsoft account and a work or school account from Microsoft Entra ID can sign in to the application.
    /// This enables multi-tenant scenarios where the application accepts both consumer and organizational accounts.
    case common

    /// Only users with a personal Microsoft account can sign in to the application.
    /// This restricts authentication to consumer accounts only (e.g., @outlook.com, @hotmail.com, @live.com).
    case consumers

    /// Only users with work or school accounts from Microsoft Entra ID can sign in to the application.
    /// This restricts authentication to organizational accounts only.
    case organizations

    /// Only users from a specific Microsoft Entra tenant (directory members with a work or school account
    /// or directory guests with a personal Microsoft account) can sign in to the application.
    /// The value can be the domain name of the Microsoft Entra tenant or the tenant ID in GUID format.
    /// - Parameter tenantIdentifier: The tenant ID (GUID format) or domain name (e.g., "contoso.com" or "8eaef023-2b34-4da1-9baa-8bc8c9d6a490")
    case custom(String)
}

extension MicrosoftTenantIDKind {
    /// Returns the string value to be used in Microsoft OAuth URLs
    public var value: String {
        switch self {
        case .common:
            return "common"
        case .consumers:
            return "consumers"
        case .organizations:
            return "organizations"
        case .custom(let tenantIdentifier):
            return tenantIdentifier
        }
    }

    /// Generates the Microsoft OAuth2/OIDC discovery URL for this tenant kind
    public var discoveryURL: String {
        "https://login.microsoftonline.com/\(value)/v2.0/"
    }

    /// Creates a MicrosoftTenantIDKind from a string value
    /// - Parameter value: The tenant identifier string
    /// - Returns: The corresponding MicrosoftTenantIDKind case
    public static func from(value: String) -> MicrosoftTenantIDKind {
        let trimmedValue = value.trimmingCharacters(in: .whitespacesAndNewlines)

        switch trimmedValue.lowercased() {
        case "", "common":
            return .common
        case "consumers":
            return .consumers
        case "organizations":
            return .organizations
        default:
            return .custom(trimmedValue)
        }
    }
}

extension MicrosoftTenantIDKind: CustomStringConvertible {
    public var description: String {
        switch self {
        case .common:
            return "common (multi-tenant)"
        case .consumers:
            return "consumers (personal accounts only)"
        case .organizations:
            return "organizations (work/school accounts only)"
        case .custom(let tenantIdentifier):
            return "custom tenant (\(tenantIdentifier))"
        }
    }
}

extension MicrosoftTenantIDKind: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        self = .from(value: value)
    }
}

extension MicrosoftTenantIDKind: RawRepresentable {
    public var rawValue: String {
        value
    }

    public init?(rawValue: String) {
        self = .from(value: rawValue)
    }
}
