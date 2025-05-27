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

/// OpenID Connect provider configuration
public struct OpenIDConfiguration: Codable, Sendable {
    /// Authorization endpoint URL
    public let authorizationEndpoint: String

    /// Token endpoint URL
    public let tokenEndpoint: String

    /// UserInfo endpoint URL
    public let userinfoEndpoint: String?

    /// JSON Web Key Set endpoint URL
    public let jwksUri: String

    /// Supported scopes
    public let scopesSupported: [String]?

    /// Supported response types
    public let responseTypesSupported: [String]

    /// Supported grant types
    public let grantTypesSupported: [String]?

    /// Supported subject types
    public let subjectTypesSupported: [String]

    /// Supported ID token signing algorithms
    public let idTokenSigningAlgValuesSupported: [String]

    /// Issuer identifier URL
    public let issuer: String

    /// End-session (logout) endpoint URL
    public let endSessionEndpoint: String?

    /// Introspection endpoint URL
    public let introspectionEndpoint: String?

    /// Revocation endpoint URL
    public let revocationEndpoint: String?

    public init(
        authorizationEndpoint: String,
        tokenEndpoint: String,
        userinfoEndpoint: String?,
        jwksUri: String,
        scopesSupported: [String]?,
        responseTypesSupported: [String],
        grantTypesSupported: [String]?,
        subjectTypesSupported: [String],
        idTokenSigningAlgValuesSupported: [String],
        issuer: String,
        endSessionEndpoint: String?,
        introspectionEndpoint: String?,
        revocationEndpoint: String?
    ) {
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.userinfoEndpoint = userinfoEndpoint
        self.jwksUri = jwksUri
        self.scopesSupported = scopesSupported
        self.responseTypesSupported = responseTypesSupported
        self.grantTypesSupported = grantTypesSupported
        self.subjectTypesSupported = subjectTypesSupported
        self.idTokenSigningAlgValuesSupported = idTokenSigningAlgValuesSupported
        self.issuer = issuer
        self.endSessionEndpoint = endSessionEndpoint
        self.introspectionEndpoint = introspectionEndpoint
        self.revocationEndpoint = revocationEndpoint
    }

    /// Coding keys for mapping JSON fields to properties
    enum CodingKeys: String, CodingKey {
        case authorizationEndpoint = "authorization_endpoint"
        case tokenEndpoint = "token_endpoint"
        case userinfoEndpoint = "userinfo_endpoint"
        case jwksUri = "jwks_uri"
        case scopesSupported = "scopes_supported"
        case responseTypesSupported = "response_types_supported"
        case grantTypesSupported = "grant_types_supported"
        case subjectTypesSupported = "subject_types_supported"
        case idTokenSigningAlgValuesSupported = "id_token_signing_alg_values_supported"
        case issuer
        case endSessionEndpoint = "end_session_endpoint"
        case introspectionEndpoint = "introspection_endpoint"
        case revocationEndpoint = "revocation_endpoint"
    }
}
