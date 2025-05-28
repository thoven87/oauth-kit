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

import AsyncHTTPClient
import Foundation
import JWTKit
import Logging
import NIOFoundationCompat

/// Provider for Apple OAuth authentication (Sign in with Apple)
public struct AppleOAuthProvider {
    /// Apple's Auth endpoints
    public struct Endpoints {
        /// The authorization endpoint URL
        public static let authorization = "https://appleid.apple.com/auth/authorize"

        /// The token endpoint URL
        public static let token = "https://appleid.apple.com/auth/token"

        /// The revocation endpoint URL
        public static let revocation = "https://appleid.apple.com/auth/revoke"

        /// The JSON Web Key Set endpoint URL
        public static let jwks = "https://appleid.apple.com/auth/keys"

        /// The Issuer URL
        public static let issuer = "https://appleid.apple.com"
    }

    /// The OAuthKit instance
    private let oauthKit: OAuthKit

    /// An OAuth2 client configured for Apple
    private var client: AppleOAuth2Client

    /// Initialize a new Apple OAuth provider
    /// - Parameter oauthKit: The OAuthKit instance
    /// - Parameter client: An OAuth2 client configured for Apple
    public init(
        oauthKit: OAuthKit,
        client: AppleOAuth2Client
    ) {
        self.oauthKit = oauthKit
        self.client = client
    }

    /// Generate an authorization URL for Apple Sign In
    /// - Parameters:
    ///   - client: The OAuth2 client configured for Apple
    ///   - state: An opaque value to maintain state between the request and callback
    ///   - usePKCE: Whether to use PKCE (recommended and enabled by default)
    ///   - additionalParameters: Additional parameters to include in the authorization URL
    /// - Returns: A tuple containing the authorization URL and code verifier (for PKCE)
    public func signInURL(
        state: String? = nil,
        usePKCE: Bool = true,
        additionalParameters: [String: String] = [:],
        scopes: [String] = []
    ) throws -> (url: URL, codeVerifier: String?) {

        var codeVerifier: String? = nil
        var codeChallenge: String? = nil

        // Generate PKCE if requested
        if usePKCE {
            let pkce = AppleOAuth2Client.generatePKCE()
            codeVerifier = pkce.codeVerifier
            codeChallenge = pkce.codeChallenge
        }

        var params = additionalParameters

        // Add Apple-specific parameters
        params["response_mode"] = "form_post"

        let url = try client.generateAuthorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            additionalParameters: params,
            scopes: scopes
        )

        return (url, codeVerifier)
    }

    /// Exchange an authorization code for tokens with Apple
    /// - Parameters:
    ///   - code: The authorization code received from Apple
    ///   - codeVerifier: The PKCE code verifier used when generating the authorization URL
    /// - Returns: The token response
    public func exchangeCode(
        code: String,
        codeVerifier: String? = nil
    ) async throws -> TokenResponse {

        let parameters = [
            "client_secret": "YOUR_CLIENT_SECRET"
        ]

        return try await client.getToken(
            code: code,
            codeVerifier: codeVerifier,
            additionalParameters: parameters
        )
    }

    /// Process and validate the identity token from Apple
    /// - Parameters:
    ///   - idToken: The ID token from the token response
    ///   - nonce: The nonce used during authorization, if any
    /// - Returns: The decoded Apple identity claims
    //    public func validateIdentityToken(
    //        idToken: String,
    //        nonce: String? = nil
    //    ) async throws -> AppleIdentityClaims {
    //        // Create a JWTSigners instance
    //        let signers = JWTKeyCollection()
    //
    //        // Fetch Apple's JWKS and configure the signers
    //        //try await fetchAndConfigureAppleJWKS(signers: signers)
    //
    //        // Verify and decode the token
    //        let claims = try await signers.verify(idToken, as: AppleIdentityClaims.self)
    //
    //        // Validate the issuer
    //        guard claims.iss == "https://appleid.apple.com" else {
    //            throw OAuth2Error.tokenValidationError("Invalid issuer: \(claims.iss ?? "nil")")
    //        }
    //
    //        // If a nonce was provided, validate it
    //        if let nonce = nonce, claims.nonce != nonce {
    //            throw OAuth2Error.tokenValidationError("Nonce mismatch")
    //        }
    //
    //        return claims
    //    }

    /// Create a user profile from Apple's identity token and user info
    /// - Parameters:
    ///   - identityClaims: The validated identity claims from Apple's ID token
    ///   - userInfo: Additional user info from Apple's authorization response (optional)
    /// - Returns: An Apple user profile
    //    public func getUserProfile(
    //        identityClaims: AppleIdentityClaims,
    //        userInfo: AppleUserInfo? = nil
    //    ) -> AppleUserProfile {
    //        return AppleUserProfile(
    //            id: identityClaims.sub ?? "",
    //            email: identityClaims.email,
    //            emailVerified: identityClaims.emailVerified,
    //            isPrivateEmail: identityClaims.isPrivateEmail,
    //            firstName: userInfo?.name?.firstName,
    //            lastName: userInfo?.name?.lastName,
    //            fullName: {
    //                if let firstName = userInfo?.name?.firstName, let lastName = userInfo?.name?.lastName {
    //                    return "\(firstName) \(lastName)".trimmingCharacters(in: .whitespacesAndNewlines)
    //                }
    //                return nil
    //            }()
    //        )
    //    }
}

/// Apple-specific OAuth2 client that generates a JWT client secret automatically
public struct AppleOAuth2Client: OAuth2ClientProtocol {
    /// HTTP client for making requests
    public var httpClient: AsyncHTTPClient.HTTPClient

    /// Apple client ID
    public var clientID: String

    /// Apple client secret
    public var clientSecret: String

    /// Apple token enpoint
    public var tokenEndpoint: String

    /// Apple Autherization Endpoint
    public var authorizationEndpoint: String?

    /// Redirect URI registered with Apple
    public var redirectURI: String?

    /// Logger used for AppleOAuth2Client operations
    public var logger: Logging.Logger

    /// The Team ID from Apple Developer portal
    private let teamID: String

    /// The Key ID for the private key from Apple Developer portal
    private let keyID: String

    /// The private key content in PEM format
    private let privateKey: String

    /// Identifier of key
    let jwkIdentifier: JWKIdentifier

    /// JWT Key collection
    let jwtKeys: JWTKeyCollection

    /// Initialize a new Apple OAuth2 client
    ///
    public init(
        httpClient: HTTPClient = HTTPClient.shared,
        clientID: String,
        clientSecret: String,
        teamID: String,
        keyID: String,
        privateKey: String,
        redirectURI: String? = nil,
        jwksURL: String,
        logger: Logger = Logger(label: "com.oauthkit.AppleOAuth2Client")
    ) async throws {

        self.httpClient = httpClient
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.tokenEndpoint = AppleOAuthProvider.Endpoints.token
        self.authorizationEndpoint = AppleOAuthProvider.Endpoints.authorization
        self.redirectURI = redirectURI
        self.logger = logger

        self.teamID = teamID
        self.keyID = keyID
        self.privateKey = privateKey
        self.jwkIdentifier = JWKIdentifier(string: keyID)
        self.jwtKeys = try await JWTKeyCollection()
            .add(ecdsa: ES256PrivateKey(pem: privateKey), kid: self.jwkIdentifier)
            .add(jwks: try await Self.getJWKS(httpClient: httpClient, jwksURL: jwksURL))
    }

    /// Override to generate a JWT client secret for every token request
    func requestAcessToken(code: String, parameters: [String: String]) async throws -> TokenResponse {
        let secret = AppleAuthToken(
            clientID: clientID,
            teamID: teamID
        )

        return try await getToken(
            code: code,
            codeVerifier: nil,
            additionalParameters: [
                "client_secret": try await jwtKeys.sign(secret, kid: jwkIdentifier)
            ]
        )
    }

    func verifyToken(_ idToken: String, nonce: String?) async throws -> AppleIdentityToken {
        let tokenBytes = [UInt8](idToken.utf8)
        let claims = try await jwtKeys.verify(tokenBytes, as: AppleIdentityToken.self)
        try claims.audience.verifyIntendedAudience(includes: clientID)
        // If a nonce was provided, validate it
        if let nonce = nonce, claims.nonce != nonce {
            throw OAuth2Error.tokenValidationError("Nonce mismatch")
        }
        return claims
    }

    struct AppleAuthToken: JWTPayload {
        let iss: IssuerClaim
        let iat: IssuedAtClaim
        let exp: ExpirationClaim
        let aud: AudienceClaim
        let sub: SubjectClaim

        init(clientID: String, teamID: String, expirationSeconds: Int = 86400 * 180) {
            sub = .init(value: clientID)
            iss = .init(value: teamID)
            let now = Date.now
            iat = .init(value: now)
            exp = .init(value: now + TimeInterval(expirationSeconds))
            aud = .init(value: ["https://appleid.apple.com"])
        }

        func verify(using algorithm: some JWTAlgorithm) async throws {
            if iat.value > exp.value {
                throw OAuth2Error.tokenValidationError("Token expired")
            }
            if iat.value > Date.now {
                throw OAuth2Error.tokenValidationError("Token issued in future")
            }
            if iss.value != AppleOAuthProvider.Endpoints.issuer {
                throw OAuth2Error.tokenValidationError("Unexpected issuer")
            }
            try exp.verifyNotExpired()
        }
    }
}

/// Claims from Apple's identity token
public struct AppleIdentityClaims: JWTPayload {

    /// The issuer identifier (should be https://appleid.apple.com)
    public let iss: IssuerClaim

    /// The subject identifier (user's unique ID with Apple)
    public let sub: SubjectClaim

    /// The audience (client ID)
    public let aud: AudienceClaim

    /// The expiration time
    public let exp: ExpirationClaim

    /// The time at which the JWT was issued
    public let iat: IssuedAtClaim

    /// The user's email address
    public let email: String?

    /// Whether the email is verified
    public let emailVerified: Bool

    /// Whether the email is private/hidden
    public let isPrivateEmail: Bool

    /// The nonce used during authorization
    public let nonce: String?
    /// Indicates wether the transaction is on a nonce-supported platfform
    public let nonceSupported: Bool?

    /// Available after iOS 14. macOS 11, watchOS 7 and later
    /// tvOS 14 and later
    /// This claim isn't supported for web-based apps
    public let realUserStatus: RealUserStatus?

    /// The time when the user was authenticated
    public let authTime: TimeInterval?

    /// A vakue indicates whether the user appers to be a real person
    public enum RealUserStatus: Int16, Codable, Sendable {
        case unsuponported = 0
        case unknown = 1
        case likelyReal = 2
    }

    /// Coding keys for mapping JSON fields to properties
    enum CodingKeys: String, CodingKey {
        case iss, sub, aud, exp, iat, email, nonce
        case emailVerified = "email_verified"
        case isPrivateEmail = "is_private_email"
        case authTime = "auth_time"
        case nonceSupported = "nonce_supported"
        case realUserStatus = "real_user_status"
    }

    public func verify(using algorithm: some JWTKit.JWTAlgorithm) async throws {
        guard iss.value.count == 10 else {
            throw JWTError.claimVerificationFailure(
                failedClaim: iss,
                reason: "TeamId must be your 10-character Team ID from the developer portal"
            )
        }

        let lifetime = Int(exp.value.timeIntervalSinceReferenceDate - iat.value.timeIntervalSinceReferenceDate)
        guard 0...15_777_000 ~= lifetime else {
            throw JWTError.claimVerificationFailure(failedClaim: exp, reason: "Expiration must be between 0 and 15777000")
        }
    }
}

/// User information from Apple's authorization response
public struct AppleUserInfo: Codable {
    /// The user's name
    public let name: AppleName?

    /// The user's email
    public let email: String?
}

/// Name component from Apple's user information
public struct AppleName: Codable {
    /// The user's first name
    public let firstName: String?

    /// The user's last name
    public let lastName: String?
}

/// Apple user profile information
public struct AppleUserProfile: Codable {
    /// The user's unique Apple ID
    public let id: String

    /// The user's email address
    public let email: String?

    /// Whether the user's email is verified
    public let emailVerified: Bool?

    /// Whether the email is a private relay email
    public let isPrivateEmail: Bool?

    /// The user's first name
    public let firstName: String?

    /// The user's last name
    public let lastName: String?

    /// The user's full name
    public let fullName: String?
}
