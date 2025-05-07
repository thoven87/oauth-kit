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

import JWTKit

struct UserInfo: JWTPayload {
    let iss: IssuerClaim
    let sub: SubjectClaim
    let aud: AudienceClaim
    let exp: ExpirationClaim
    let iat: IssuedAtClaim
    let atHash: String?
    let name: String?
    let familyName: String?
    let givenName: String?
    let email: String
    let emailVerified: Bool?
    let picture: String?

    enum CodingKeys: String, CodingKey {
        case iss
        case sub
        case aud
        case exp
        case iat
        case atHash = "at_hash"
        case name
        case familyName = "family_name"
        case givenName = "given_name"
        case emailVerified = "email_verified"
        case email
        case picture
    }

    func verify(using algorithm: some JWTKit.JWTAlgorithm) async throws {
        try exp.verifyNotExpired()
    }
}
