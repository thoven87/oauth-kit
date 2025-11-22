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

/// Client for interacting with OpenID Connect providers
public struct OpenIDConnectClient: Sendable {
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

    /// Initialize a new OpenID Connect client
    /// - Parameters:
    ///   - httpClient: The HTTP client used for making requests
    ///   - clientID: The client ID provided by the OIDC provider
    ///   - clientSecret: The client secret provided by the OIDC provider
    ///   - configuration: The OpenID Connect provider configuration
    ///   - redirectURI: The redirect URI registered with the OIDC provider
    ///   - logger: Logger used for OpenID Connect operations
    public init(
        httpClient: HTTPClient = HTTPClient.shared,
        clientID: String,
        clientSecret: String,
        configuration: OpenIDConfiguration,
        redirectURI: String? = nil,
        logger: Logger = Logger(label: "com.oauthkit.OpenIDConnectClient")
    ) async throws {
        self.httpClient = httpClient
        self.configuration = configuration
        self.clientID = clientID
        self.logger = logger
        self.clientSecret = clientSecret
        self.redirectURI = redirectURI

        self.oauth2Client = OAuth2Client(
            httpClient: httpClient,
            clientID: clientID,
            clientSecret: clientSecret,
            tokenEndpoint: configuration.tokenEndpoint,
            authorizationEndpoint: configuration.authorizationEndpoint,
            redirectURI: redirectURI,
            logger: logger
        )
        let jwks = try await Self.loadJWKS(httpClient: httpClient, jwksURI: configuration.jwksUri)
        self.jwtSigners = try await JWTKeyCollection().add(jwks: jwks)
    }

    /// Generate an authorization URL for the OpenID Connect authentication flow
    /// - Parameters:
    ///   - state: An opaque value used to maintain state between the request and callback
    ///   - codeChallenge: PKCE code challenge (if using PKCE)
    ///   - codeChallengeMethod: PKCE code challenge method (e.g., "S256")
    ///   - additionalParameters: Additional query parameters to include in the URL
    ///   - scope: The requested scopes
    /// - Returns: The authorization URL
    /// - Throws: OAuth2Error if the authorization endpoint is not configured
    public func generateAuthorizationURL(
        state: String? = nil,
        codeChallenge: String? = nil,
        codeChallengeMethod: OAuthCodeChallengeMethod? = nil,
        additionalParameters: [String: String] = [:],
        scopes: [String] = ["openid", "profile", "email", "offline_access"]
    ) throws -> URL {
        try oauth2Client.generateAuthorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod,
            additionalParameters: additionalParameters,
            scopes: scopes
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
            throw OAuth2Error.tokenError("No ID token in response")
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

    /// Request device authorization for device flow (RFC 8628)
    /// - Parameters:
    ///   - scopes: The requested scopes
    ///   - additionalParameters: Additional parameters to include in the device authorization request
    /// - Returns: Device authorization response containing device code, user code, and verification URI
    /// - Throws: OAuth2Error if the device authorization request fails
    public func requestDeviceAuthorization(
        scopes: [String] = ["openid", "profile", "email"],
        additionalParameters: [String: String] = [:]
    ) async throws -> DeviceAuthorizationResponse {
        try await oauth2Client.requestDeviceAuthorization(
            scopes: scopes,
            additionalParameters: additionalParameters
        )
    }

    /// Exchange device code for tokens and validate ID token (device flow)
    /// - Parameters:
    ///   - deviceCode: The device code from device authorization response
    ///   - additionalParameters: Additional parameters to include in the token request
    /// - Returns: The token response with validated ID token claims
    /// - Throws: OAuth2Error or DeviceFlowError if the token exchange fails
    public func exchangeDeviceCode(
        _ deviceCode: String,
        additionalParameters: [String: String] = [:]
    ) async throws -> (tokenResponse: TokenResponse, claims: IDTokenClaims) {
        let tokenResponse = try await oauth2Client.exchangeDeviceCode(
            deviceCode,
            additionalParameters: additionalParameters
        )

        // Validate ID token if present
        guard let idToken = tokenResponse.idToken else {
            throw OAuth2Error.invalidResponse("No ID token in device flow token response")
        }

        let claims = try await validateIDToken(idToken)
        return (tokenResponse, claims)
    }

    /// Poll for device authorization completion with automatic retry logic
    /// - Parameters:
    ///   - deviceCode: The device code from device authorization response
    ///   - interval: Polling interval in seconds (default from device auth response)
    ///   - timeout: Maximum time to wait in seconds (default 300)
    ///   - additionalParameters: Additional parameters to include in token requests
    /// - Returns: The token response with validated ID token claims when authorization is complete
    /// - Throws: DeviceFlowError or OAuth2Error if polling fails or times out
    public func pollForDeviceAuthorization(
        deviceCode: String,
        interval: Int = 5,
        timeout: TimeInterval = 300,
        additionalParameters: [String: String] = [:]
    ) async throws -> (tokenResponse: TokenResponse, claims: IDTokenClaims) {
        let tokenResponse = try await oauth2Client.pollForDeviceAuthorization(
            deviceCode: deviceCode,
            interval: interval,
            timeout: timeout,
            additionalParameters: additionalParameters
        )

        // Validate ID token if present
        guard let idToken = tokenResponse.idToken else {
            throw OAuth2Error.invalidResponse("No ID token in device flow token response")
        }

        let claims = try await validateIDToken(idToken)
        return (tokenResponse, claims)
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
            guard jwt.iss?.value == configuration.issuer else {
                throw OAuth2Error.tokenError("Invalid issuer: \(jwt.iss ?? "nil") != \(configuration.issuer)")
            }

            // Validate audience
            guard jwt.aud?.contains(clientID) == true else {
                throw OAuth2Error.tokenError("Invalid audience: \(jwt.aud?.description ?? "nil") does not contain \(clientID)")
            }

            // Validate expiration time
            let currentTime = Date()
            guard let expirationTime = jwt.exp?.value, expirationTime > currentTime else {
                throw OAuth2Error.tokenError("Token has expired")
            }

            // Validate issued at time
            if let issuedAt = jwt.iat?.value, issuedAt > currentTime {
                throw OAuth2Error.tokenError("Token issued in the future")
            }

            return jwt
        } catch let error as JWTError {
            logger.error("ID token validation failed: \(error)")
            throw OAuth2Error.tokenError("ID token validation failed: \(error)")
        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("ID token validation failed with error: \(error)")
            throw OAuth2Error.tokenError("ID token validation failed: \(error)")
        }
    }

    /// Load JSON Web Key Set from the provider with retry mechanism
    /// - Parameters:
    ///   - httpClient: The HTTP client to use for requests
    ///   - jwksURI: The JWKS endpoint URI
    ///   - maxRetries: Maximum number of retry attempts (default: 5)
    ///   - retryDelay: Base delay between retries in nanoseconds (default: 1 second)
    /// - Throws: OAuth2Error if the JWKS can't be loaded after all retries
    private static func loadJWKS(
        httpClient: HTTPClient = .shared,
        jwksURI: String,
        maxRetries: Int = 5,
        retryDelay: UInt64 = 1_000_000_000
    ) async throws -> JWKS {
        let logger = Logger(label: "com.oauthkit.OpenIDConnectClient")

        var lastError: Error?

        for attempt in 1...(maxRetries + 1) {
            do {
                var request = HTTPClientRequest(url: jwksURI)
                request.method = .GET
                request.headers.add(name: "Accept", value: "application/json")
                request.headers.add(name: "User-Agent", value: USER_AGENT)

                let response = try await httpClient.execute(request, timeout: .seconds(60))

                guard response.status == .ok else {
                    let statusError = OAuth2Error.jwksError("JWKS request failed with status: \(response.status)")
                    if attempt <= maxRetries {
                        logger.warning("JWKS request attempt \(attempt)/\(maxRetries) failed with status: \(response.status), retrying...")
                        lastError = statusError
                        try await Task.sleep(nanoseconds: retryDelay * UInt64(attempt))
                        continue
                    } else {
                        logger.error("JWKS request failed with status: \(response.status) after \(maxRetries) attempts")
                        throw statusError
                    }
                }

                let jwks = try await response.body.collect(upTo: 1024 * 1024)  // 1MB
                return try JSONDecoder().decode(JWKS.self, from: jwks)
            } catch let error as OAuth2Error {
                if attempt <= maxRetries {
                    logger.warning("JWKS request attempt \(attempt)/\(maxRetries) failed with OAuth2Error: \(error), retrying...")
                    lastError = error
                    try await Task.sleep(nanoseconds: retryDelay * UInt64(attempt))
                    continue
                } else {
                    throw error
                }
            } catch {
                if attempt <= maxRetries {
                    logger.warning("JWKS request attempt \(attempt)/\(maxRetries) failed with error: \(error), retrying...")
                    lastError = error
                    try await Task.sleep(nanoseconds: retryDelay * UInt64(attempt))
                    continue
                } else {
                    logger.error("JWKS request failed with error: \(error) after \(maxRetries) attempts")
                    throw OAuth2Error.jwksError("JWKS request failed: \(error)")
                }
            }
        }

        // This should never be reached due to the logic above, but Swift requires it
        if let lastError = lastError {
            if let oauth2Error = lastError as? OAuth2Error {
                throw oauth2Error
            } else {
                throw OAuth2Error.jwksError("JWKS request failed after all retry attempts: \(lastError)")
            }
        } else {
            throw OAuth2Error.jwksError("JWKS request failed after all retry attempts")
        }
    }
}

/// Standard claims in an OpenID Connect ID token
public struct IDTokenClaims: JWTPayload, Equatable {
    /// Issuer identifier
    public let iss: IssuerClaim?

    /// Subject identifier
    public let sub: SubjectClaim?

    /// Audience(s) that the JWT is intended for
    public let aud: [String]?

    /// Expiration time
    public let exp: ExpirationClaim?

    /// External user id
    public let userId: String?

    /// Time at which the JWT was issued
    public let iat: IssuedAtClaim?

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
        case userId = "user_id"
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        iss = try container.decodeIfPresent(IssuerClaim.self, forKey: .iss)
        sub = try container.decodeIfPresent(SubjectClaim.self, forKey: .sub)

        // Handle aud as either a single string or an array of strings
        if let audString = try? container.decode(String.self, forKey: .aud) {
            aud = [audString]
        } else {
            aud = try container.decodeIfPresent([String].self, forKey: .aud)
        }

        exp = try container.decodeIfPresent(ExpirationClaim.self, forKey: .exp)
        iat = try container.decodeIfPresent(IssuedAtClaim.self, forKey: .iat)
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
        userId = try container.decodeIfPresent(String.self, forKey: .userId)

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
        try container.encodeIfPresent(userId, forKey: .userId)

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

    public func verify(using algorithm: some JWTAlgorithm) throws {
        try exp?.verifyNotExpired()
    }
}

/// Dynamic coding keys for handling custom claims
internal struct DynamicCodingKeys: CodingKey {
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
