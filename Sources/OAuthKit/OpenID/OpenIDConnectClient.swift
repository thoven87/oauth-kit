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

/// Client for interacting with OpenID Connect providers
public struct OpenIDConnectClient {
    /// The underlying OAuth2 client
    private let oauth2Client: OAuth2Client

    /// The OpenID Connect provider configuration
    public let configuration: OpenIDConfiguration

    /// HTTP client for making requests
    private let httpClient: HTTPClient

    /// Logger for OpenID Connect operations
    private let logger: Logger

    /// JWT signers for validating ID tokens
    private var jwtSigners: JWTKeyCollection?

    /// Client ID provided by the OIDC provider
    public let clientID: String

    /// The client secret provided by the OIDC provider
    internal let clientSecret: String

    /// The redirect URI registered with the OIDC provider
    internal let redirectURI: String?

    /// The requested scopes (space-separated)
    internal let scope: String

    /// Initialize a new OpenID Connect client
    /// - Parameters:
    ///   - httpClient: The HTTP client used for making requests
    ///   - clientID: The client ID provided by the OIDC provider
    ///   - clientSecret: The client secret provided by the OIDC provider
    ///   - configuration: The OpenID Connect provider configuration
    ///   - redirectURI: The redirect URI registered with the OIDC provider
    ///   - scope: The requested scopes (space-separated)
    ///   - logger: Logger used for OpenID Connect operations
    public init(
        httpClient: HTTPClient = HTTPClient.shared,
        clientID: String,
        clientSecret: String,
        configuration: OpenIDConfiguration,
        redirectURI: String? = nil,
        scope: String = "openid profile email offline_access",
        logger: Logger = Logger(label: "com.oauthkit.OpenIDConnectClient")
    ) async throws {
        self.httpClient = httpClient
        self.configuration = configuration
        self.clientID = clientID
        self.logger = logger
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI
        self.scope = scope
        self.oauth2Client = OAuth2Client(
            httpClient: httpClient,
            clientID: clientID,
            clientSecret: clientSecret,
            tokenEndpoint: configuration.tokenEndpoint,
            authorizationEndpoint: configuration.authorizationEndpoint,
            redirectURI: redirectURI,
            scope: scope,
            logger: logger
        )
        let jwks = try await Self.loadJWKS(jwksURI: configuration.jwksUri)
        self.jwtSigners = try await JWTKeyCollection().add(jwks: jwks)
    }

    /// Generate an authorization URL for the OpenID Connect authentication flow
    /// - Parameters:
    ///   - state: An opaque value used to maintain state between the request and callback
    ///   - codeChallenge: PKCE code challenge (if using PKCE)
    ///   - codeChallengeMethod: PKCE code challenge method (e.g., "S256")
    ///   - additionalParameters: Additional query parameters to include in the URL
    /// - Returns: The authorization URL
    /// - Throws: OAuth2Error if the authorization endpoint is not configured
    public func authorizationURL(
        state: String? = nil,
        codeChallenge: String? = nil,
        codeChallengeMethod: String? = nil,
        additionalParameters: [String: String] = [:]
    ) throws -> URL {
        try oauth2Client.authorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod,
            additionalParameters: additionalParameters
        )
    }

    /// Exchange an authorization code for tokens
    /// - Parameters:
    ///   - code: The authorization code received from the authorization server
    ///   - codeVerifier: PKCE code verifier (if using PKCE)
    ///   - additionalParameters: Additional parameters to include in the token request
    /// - Returns: The token response with validated ID token claims
    /// - Throws: OAuth2Error if the token exchange fails or ID token validation fails
    public func exchangeCode(
        code: String,
        codeVerifier: String? = nil,
        additionalParameters: [String: String] = [:]
    ) async throws -> (tokenResponse: TokenResponse, claims: IDTokenClaims) {
        let tokenResponse = try await oauth2Client.getToken(
            code: code,
            codeVerifier: codeVerifier,
            additionalParameters: additionalParameters
        )

        // Verify and decode the ID token
        guard let idToken = tokenResponse.idToken else {
            throw OAuth2Error.tokenValidationError("No ID token in response")
        }

        let claims = try await validateIDToken(idToken)
        return (tokenResponse, claims)
    }

    /// Get user information from the UserInfo endpoint
    /// - Parameter accessToken: The access token to use for the request
    /// - Returns: The user information as a dictionary
    /// - Throws: OAuth2Error if the UserInfo request fails
    public func getUserInfo<T: Codable>(accessToken: String) async throws -> T {
        guard let userinfoEndpoint = configuration.userinfoEndpoint else {
            throw OAuth2Error.configurationError("UserInfo endpoint not configured")
        }

        var request = HTTPClientRequest(url: userinfoEndpoint)
        request.method = .GET
        request.headers.add(name: "Authorization", value: "Bearer \(accessToken)")
        request.headers.add(name: "User-Agent", value: USER_AGENT)
        request.headers.add(name: "Accept", value: "application/json")

        do {
            let response = try await httpClient.execute(request, timeout: .seconds(60))

            guard response.status == .ok else {
                logger.error("UserInfo request failed with status: \(response.status)")
                throw OAuth2Error.responseError("UserInfo request failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
            return try JSONDecoder().decode(T.self, from: responseBody)
        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("UserInfo request failed with error: \(error)")
            throw OAuth2Error.networkError("UserInfo request failed: \(error)")
        }
    }

    /// End the user's session (logout)
    /// - Parameters:
    ///   - idToken: The ID token from the authentication session
    ///   - postLogoutRedirectURI: Optional URI to redirect to after logout
    ///   - state: Optional state parameter for the logout request
    /// - Returns: The end session (logout) URL
    /// - Throws: OAuth2Error if the end session endpoint is not configured
    public func endSessionURL(
        idToken: String,
        postLogoutRedirectURI: String? = nil,
        state: String? = nil
    ) throws -> URL {
        guard let endSessionEndpoint = configuration.endSessionEndpoint else {
            throw OAuth2Error.configurationError("End session endpoint not configured")
        }

        guard var components = URLComponents(string: endSessionEndpoint) else {
            throw OAuth2Error.configurationError("Invalid end session endpoint URL: \(endSessionEndpoint)")
        }

        var queryItems = [
            URLQueryItem(name: "id_token_hint", value: idToken)
        ]

        if let postLogoutRedirectURI = postLogoutRedirectURI {
            queryItems.append(URLQueryItem(name: "post_logout_redirect_uri", value: postLogoutRedirectURI))
        }

        if let state = state {
            queryItems.append(URLQueryItem(name: "state", value: state))
        }

        components.queryItems = queryItems

        guard let url = components.url else {
            throw OAuth2Error.configurationError("Failed to create end session URL from components")
        }

        return url
    }

    /// Refresh an access token using a refresh token
    /// - Parameters:
    ///   - refreshToken: The refresh token
    ///   - additionalParameters: Additional parameters to include in the token request
    /// - Returns: The token response with validated ID token claims (if an ID token is returned)
    /// - Throws: OAuth2Error if the token refresh fails
    public func refreshToken(
        _ refreshToken: String,
        additionalParameters: [String: String] = [:]
    ) async throws -> (tokenResponse: TokenResponse, claims: IDTokenClaims?) {
        let tokenResponse = try await oauth2Client.refreshToken(
            refreshToken,
            additionalParameters: additionalParameters
        )

        // Validate ID token if present
        if let idToken = tokenResponse.idToken {
            let claims = try await validateIDToken(idToken)
            return (tokenResponse, claims)
        }

        return (tokenResponse, nil)
    }

    /// Validate an ID token and extract its claims
    /// - Parameter idToken: The ID token to validate
    /// - Returns: The validated ID token claims
    /// - Throws: OAuth2Error if validation fails
    public func validateIDToken(_ idToken: String) async throws -> IDTokenClaims {

        guard let signers = jwtSigners else {
            throw OAuth2Error.jwksError("Failed to load JWT signers")
        }

        do {
            // Verify the JWT signature and decode the claims
            let jwt = try await signers.verify(idToken, as: IDTokenClaims.self)

            // Validate issuer
            guard jwt.iss == configuration.issuer else {
                throw OAuth2Error.tokenValidationError("Invalid issuer: \(jwt.iss ?? "nil") != \(configuration.issuer)")
            }

            // Validate audience
            guard jwt.aud?.contains(clientID) == true else {
                throw OAuth2Error.tokenValidationError("Invalid audience: \(jwt.aud?.description ?? "nil") does not contain \(clientID)")
            }

            // Validate expiration time
            let currentTime = Date().timeIntervalSince1970
            guard let expirationTime = jwt.exp, expirationTime > currentTime else {
                throw OAuth2Error.tokenValidationError("Token has expired")
            }

            // Validate issued at time
            if let issuedAt = jwt.iat, issuedAt > currentTime {
                throw OAuth2Error.tokenValidationError("Token issued in the future")
            }

            return jwt
        } catch let error as JWTError {
            logger.error("ID token validation failed: \(error)")
            throw OAuth2Error.tokenValidationError("ID token validation failed: \(error)")
        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("ID token validation failed with error: \(error)")
            throw OAuth2Error.tokenValidationError("ID token validation failed: \(error)")
        }
    }

    /// Load JSON Web Key Set from the provider
    /// - Throws: OAuth2Error if the JWKS can't be loaded
    private static func loadJWKS(httpClient: HTTPClient = .shared, jwksURI: String) async throws -> JWKS {
        let logger = Logger(label: "org.openid.connect.client")

        var request = HTTPClientRequest(url: jwksURI)
        request.method = .GET
        request.headers.add(name: "Accept", value: "application/json")
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        do {
            let response = try await httpClient.execute(request, timeout: .seconds(60))

            guard response.status == .ok else {
                logger.error("JWKS request failed with status: \(response.status)")
                throw OAuth2Error.jwksError("JWKS request failed with status: \(response.status)")
            }

            let jwks = try await response.body.collect(upTo: 1024 * 1024)  // 1MB
            return try JSONDecoder().decode(JWKS.self, from: jwks)
        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("JWKS request failed with error: \(error)")
            throw OAuth2Error.jwksError("JWKS request failed: \(error)")
        }
    }
}

/// Standard claims in an OpenID Connect ID token
public struct IDTokenClaims: JWTPayload, Equatable {
    /// Issuer identifier
    public let iss: String?

    /// Subject identifier
    public let sub: String?

    /// Audience(s) that the JWT is intended for
    public let aud: [String]?

    /// Expiration time
    public let exp: TimeInterval?

    /// Time at which the JWT was issued
    public let iat: TimeInterval?

    /// Time when the authentication occurred
    public let authTime: TimeInterval?

    /// Nonce to associate client session with ID token
    public let nonce: String?

    /// Authentication context class reference
    public let acr: String?

    /// Authentication methods references
    public let amr: [String]?

    /// Authorized party
    public let azp: String?

    /// Access token hash
    public let atHash: String?

    /// Code hash
    public let cHash: String?

    /// Additional custom claims
    //public let additionalClaims: [String: AnyCodable]?

    /// Standard claims for name and email
    public let name: String?
    public let givenName: String?
    public let familyName: String?
    public let middleName: String?
    public let nickname: String?
    public let preferredUsername: String?
    public let profile: String?
    public let picture: String?
    public let website: String?
    public let email: String?
    public let emailVerified: Bool?
    public let gender: String?
    public let birthdate: String?
    public let zoneinfo: String?
    public let locale: String?
    public let phoneNumber: String?
    public let phoneNumberVerified: Bool?
    public let address: AddressClaim?
    public let updatedAt: TimeInterval?

    enum CodingKeys: String, CodingKey {
        case iss, sub, aud, exp, iat
        case authTime = "auth_time"
        case nonce, acr, amr, azp
        case atHash = "at_hash"
        case cHash = "c_hash"
        case name
        case givenName = "given_name"
        case familyName = "family_name"
        case middleName = "middle_name"
        case nickname
        case preferredUsername = "preferred_username"
        case profile, picture, website, email
        case emailVerified = "email_verified"
        case gender, birthdate, zoneinfo, locale
        case phoneNumber = "phone_number"
        case phoneNumberVerified = "phone_number_verified"
        case address
        case updatedAt = "updated_at"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        iss = try container.decodeIfPresent(String.self, forKey: .iss)
        sub = try container.decodeIfPresent(String.self, forKey: .sub)

        // Handle aud as either a single string or an array of strings
        if let audString = try? container.decode(String.self, forKey: .aud) {
            aud = [audString]
        } else {
            aud = try container.decodeIfPresent([String].self, forKey: .aud)
        }

        exp = try container.decodeIfPresent(TimeInterval.self, forKey: .exp)
        iat = try container.decodeIfPresent(TimeInterval.self, forKey: .iat)
        authTime = try container.decodeIfPresent(TimeInterval.self, forKey: .authTime)
        nonce = try container.decodeIfPresent(String.self, forKey: .nonce)
        acr = try container.decodeIfPresent(String.self, forKey: .acr)
        amr = try container.decodeIfPresent([String].self, forKey: .amr)
        azp = try container.decodeIfPresent(String.self, forKey: .azp)
        atHash = try container.decodeIfPresent(String.self, forKey: .atHash)
        cHash = try container.decodeIfPresent(String.self, forKey: .cHash)

        // Standard claims
        name = try container.decodeIfPresent(String.self, forKey: .name)
        givenName = try container.decodeIfPresent(String.self, forKey: .givenName)
        familyName = try container.decodeIfPresent(String.self, forKey: .familyName)
        middleName = try container.decodeIfPresent(String.self, forKey: .middleName)
        nickname = try container.decodeIfPresent(String.self, forKey: .nickname)
        preferredUsername = try container.decodeIfPresent(String.self, forKey: .preferredUsername)
        profile = try container.decodeIfPresent(String.self, forKey: .profile)
        picture = try container.decodeIfPresent(String.self, forKey: .picture)
        website = try container.decodeIfPresent(String.self, forKey: .website)
        email = try container.decodeIfPresent(String.self, forKey: .email)
        emailVerified = try container.decodeIfPresent(Bool.self, forKey: .emailVerified)
        gender = try container.decodeIfPresent(String.self, forKey: .gender)
        birthdate = try container.decodeIfPresent(String.self, forKey: .birthdate)
        zoneinfo = try container.decodeIfPresent(String.self, forKey: .zoneinfo)
        locale = try container.decodeIfPresent(String.self, forKey: .locale)
        phoneNumber = try container.decodeIfPresent(String.self, forKey: .phoneNumber)
        phoneNumberVerified = try container.decodeIfPresent(Bool.self, forKey: .phoneNumberVerified)
        address = try container.decodeIfPresent(AddressClaim.self, forKey: .address)
        updatedAt = try container.decodeIfPresent(TimeInterval.self, forKey: .updatedAt)

        // Capture additional claims
        let customContainer = try decoder.container(keyedBy: DynamicCodingKeys.self)
        var extras = [String: AnyCodable]()

        for key in customContainer.allKeys {
            if CodingKeys(stringValue: key.stringValue) == nil {
                if let value = try? customContainer.decode(AnyCodable.self, forKey: key) {
                    extras[key.stringValue] = value
                }
            }
        }

        //self.additionalClaims = extras.isEmpty ? nil : extras
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(iss, forKey: .iss)
        try container.encodeIfPresent(sub, forKey: .sub)
        try container.encodeIfPresent(aud, forKey: .aud)
        try container.encodeIfPresent(exp, forKey: .exp)
        try container.encodeIfPresent(iat, forKey: .iat)
        try container.encodeIfPresent(authTime, forKey: .authTime)
        try container.encodeIfPresent(nonce, forKey: .nonce)
        try container.encodeIfPresent(acr, forKey: .acr)
        try container.encodeIfPresent(amr, forKey: .amr)
        try container.encodeIfPresent(azp, forKey: .azp)
        try container.encodeIfPresent(atHash, forKey: .atHash)
        try container.encodeIfPresent(cHash, forKey: .cHash)

        // Standard claims
        try container.encodeIfPresent(name, forKey: .name)
        try container.encodeIfPresent(givenName, forKey: .givenName)
        try container.encodeIfPresent(familyName, forKey: .familyName)
        try container.encodeIfPresent(middleName, forKey: .middleName)
        try container.encodeIfPresent(nickname, forKey: .nickname)
        try container.encodeIfPresent(preferredUsername, forKey: .preferredUsername)
        try container.encodeIfPresent(profile, forKey: .profile)
        try container.encodeIfPresent(picture, forKey: .picture)
        try container.encodeIfPresent(website, forKey: .website)
        try container.encodeIfPresent(email, forKey: .email)
        try container.encodeIfPresent(emailVerified, forKey: .emailVerified)
        try container.encodeIfPresent(gender, forKey: .gender)
        try container.encodeIfPresent(birthdate, forKey: .birthdate)
        try container.encodeIfPresent(zoneinfo, forKey: .zoneinfo)
        try container.encodeIfPresent(locale, forKey: .locale)
        try container.encodeIfPresent(phoneNumber, forKey: .phoneNumber)
        try container.encodeIfPresent(phoneNumberVerified, forKey: .phoneNumberVerified)
        try container.encodeIfPresent(address, forKey: .address)
        try container.encodeIfPresent(updatedAt, forKey: .updatedAt)

        // Encode additional claims
        //        if let additionalClaims = additionalClaims {
        //            var customContainer = encoder.container(keyedBy: DynamicCodingKeys.self)
        //            for (key, value) in additionalClaims {
        //                let dynamicKey = DynamicCodingKeys(stringValue: key)
        //                try customContainer.encode(value, forKey: dynamicKey)
        //            }
        //        }
    }

    /// Address claim in OpenID Connect ID tokens
    public struct AddressClaim: Codable, Equatable, Sendable {
        public let formatted: String?
        public let streetAddress: String?
        public let locality: String?
        public let region: String?
        public let postalCode: String?
        public let country: String?

        enum CodingKeys: String, CodingKey {
            case formatted
            case streetAddress = "street_address"
            case locality
            case region
            case postalCode = "postal_code"
            case country
        }
    }

    //public func verify(using signer: JWTSigner) throws {
    public func verify(using algorithm: some JWTAlgorithm) throws {
        // JWT-Kit will verify expiration and issuance times

    }
}

/// Dynamic coding keys for handling custom claims
private struct DynamicCodingKeys: CodingKey {
    var stringValue: String
    var intValue: Int?

    init(stringValue: String) {
        self.stringValue = stringValue
        self.intValue = nil
    }

    init?(intValue: Int) {
        self.stringValue = "\(intValue)"
        self.intValue = intValue
    }
}

/// A type-erasing Codable wrapper for handling arbitrary JSON types
public struct AnyCodable: Codable, Equatable {
    private let value: Any
    private let encode: (Encoder) throws -> Void

    public init<T: Codable>(_ value: T) {
        self.value = value
        self.encode = { encoder in
            try value.encode(to: encoder)
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        if container.decodeNil() {
            self.value = NSNull()
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
            self.value = array.map { $0.value }
            self.encode = { encoder in
                var container = encoder.singleValueContainer()
                try container.encode(array)
            }
        } else if let dictionary = try? container.decode([String: AnyCodable].self) {
            self.value = dictionary.mapValues { $0.value }
            self.encode = { encoder in
                var container = encoder.singleValueContainer()
                try container.encode(dictionary)
            }
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Cannot decode AnyCodable")
        }
    }

    public func encode(to encoder: Encoder) throws {
        try encode(encoder)
    }

    public static func == (lhs: AnyCodable, rhs: AnyCodable) -> Bool {
        isEqual(lhs.value, rhs.value)
    }

    private static func isEqual(_ lhs: Any, _ rhs: Any) -> Bool {
        if let lhs = lhs as? NSNumber, let rhs = rhs as? NSNumber {
            return lhs.isEqual(rhs)
        } else if let lhs = lhs as? String, let rhs = rhs as? String {
            return lhs == rhs
        } else if let lhs = lhs as? Bool, let rhs = rhs as? Bool {
            return lhs == rhs
        } else if let lhs = lhs as? [Any], let rhs = rhs as? [Any] {
            return lhs.count == rhs.count && zip(lhs, rhs).allSatisfy(isEqual)
        } else if let lhs = lhs as? [String: Any], let rhs = rhs as? [String: Any] {
            return lhs.count == rhs.count
                && lhs.keys.allSatisfy { key in
                    rhs[key].map { isEqual(lhs[key]!, $0) } ?? false
                }
        } else if lhs is NSNull && rhs is NSNull {
            return true
        }
        return false
    }
}
