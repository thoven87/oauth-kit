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
import NIOFoundationCompat

/// Google user identity token containing profile information
public typealias GoogleIdentityToken = IDTokenClaims

/// Provider for Google OAuth2/OpenID Connect authentication
public struct GoogleOAuthProvider: Sendable {
    /// Google's OAuth2/OIDC discovery URL
    public static let discoveryURL = "https://accounts.google.com/"

    /// The OAuthKit instance
    private let oauthKit: OAuthKit

    /// The OpenID Connect client configured for Google
    private let client: OpenIDConnectClient

    public enum TokenAccessType: String {
        case offline
        case online
    }

    /// Initialize a new Google OAuth provider
    /// - Parameter oauthKit: The OAuthKit instance
    /// - Parameter openIDConnectClient: An OpenID Connect client configured for Google
    public init(
        oauthKit: OAuthKit,
        openIDConnectClient client: OpenIDConnectClient
    ) {
        self.oauthKit = oauthKit
        self.client = client
    }

    /// Generate an authorization URL for Google Sign-In with recommended parameters
    /// - Parameters:
    ///   - state: An opaque value to maintain state between the request and callback
    ///   - prompt: Controls the Google Sign-In prompt behavior
    ///   - loginHint: Email address or sub identifier to pre-fill the authentication screen
    ///   - usePKCE: Whether to use PKCE (recommended and enabled by default)
    ///   - accessType: offline | online refresh acess token
    ///   - includeGrantedScopes: Request incremental authorization
    ///   - additionalParameters: Additional parameters to include in the authorization URL
    ///   - scopes: The requested scopes
    /// - Returns: A tuple containing the authorization URL and code verifier (for PKCE)
    public func generateAuthURL(
        state: String? = nil,
        prompt: GooglePrompt? = nil,
        loginHint: String? = nil,
        usePKCE: Bool = true,
        accessType: TokenAccessType = .offline,
        includeGrantedScopes: Bool = true,
        additionalParameters: [String: String] = [:],
        scopes: [String]
    ) throws -> (url: URL, codeVerifier: String?) {
        var additionalParams = additionalParameters
        var codeVerifier: String? = nil
        var codeChallenge: String? = nil

        // Generate PKCE if requested
        if usePKCE {
            let pkce = OAuth2Client.generatePKCE()
            codeVerifier = pkce.codeVerifier
            codeChallenge = pkce.codeChallenge
        }

        // Add Google-specific parameters
        if let prompt = prompt {
            additionalParams["prompt"] = prompt.rawValue
        }

        if let loginHint = loginHint {
            additionalParams["login_hint"] = loginHint
        }

        // Google recommends adding these parameters
        additionalParams["access_type"] = accessType.rawValue
        additionalParams["include_granted_scopes"] = String(includeGrantedScopes)

        if additionalParameters["nonce"] == nil {
            // Generate nonce for improved security
            let nonce = UUID().uuidString
            additionalParams["nonce"] = nonce
        }

        let url = try client.generateAuthorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            additionalParameters: additionalParams,
            scopes: scopes
        )

        return (url, codeVerifier)
    }

    /// Retrieves an access token using a refresh token
    /// - Parameters:
    ///  - refreshToken: a valid refresh token
    ///  - additionalParameters: additional parameters
    public func refreshAccessToken(
        refreshToken: String,
        additionalParameters: [String: String] = [:]
    ) async throws -> (tokenResponse: TokenResponse, claims: IDTokenClaims?) {
        try await client.refreshToken(
            refreshToken,
            additionalParameters: additionalParameters
        )
    }

    /// End the user's session (logout)
    /// - Parameters:
    ///   - idToken: The ID token from the authentication session
    ///   - postLogoutRedirectURI: Optional URI to redirect to after logout
    ///   - state: Optional state parameter for the logout request
    /// - Returns: The end session (logout) URL
    public func revokeToken(
        idToken: String,
        postLogoutRedirectURI: String?,
        state: String?
    ) throws -> URL {
        try client.endSessionURL(
            idToken: idToken,
            postLogoutRedirectURI: postLogoutRedirectURI,
            state: state
        )
    }

    /// Exchange an authorization code for tokens with Google
    /// - Parameters:
    ///   - code: The authorization code received from Google
    ///   - codeVerifier: The PKCE code verifier used when generating the authorization URL
    /// - Returns: The token response and ID token claims
    public func exchangeCode(
        code: String,
        codeVerifier: String?
    ) async throws -> (tokenResponse: TokenResponse, claims: IDTokenClaims) {
        try await client.exchangeCode(
            code: code,
            codeVerifier: codeVerifier
        )
    }

    /// Retrieve the user's profile information from Google
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    /// - Returns: The user's Google profile information
    public func getUserProfile(
        accessToken: String
    ) async throws -> GoogleIdentityToken {
        let userInfo: GoogleIdentityToken = try await client.getUserInfo(accessToken: accessToken)
        return userInfo
    }

    /// Authenticate using Google service account credentials
    /// - Parameters:
    ///   - credentials: The Google service account credentials
    ///   - scopes: The requested scopes for the access token
    ///   - subject: Optional subject (user email) for domain-wide delegation
    /// - Returns: The token response containing the access token
    /// - Throws: OAuth2Error if authentication fails
    public func authenticateWithServiceAccount(
        credentials: GoogleServiceAccountCredentials,
        scopes: [String],
        subject: String? = nil
    ) async throws -> TokenResponse {
        // Create JWT assertion
        let jwt = try await createServiceAccountJWT(
            credentials: credentials,
            scopes: scopes,
            subject: subject
        )

        // Exchange JWT for access token
        return try await exchangeJWTForToken(jwt: jwt, credentials: credentials)
    }

    /// Authenticate using Google service account credentials from a JSON string
    /// - Parameters:
    ///   - credentialsJSON: The Google service account credentials as a JSON string
    ///   - scopes: The requested scopes for the access token
    ///   - subject: Optional subject (user email) for domain-wide delegation
    /// - Returns: The token response containing the access token
    /// - Throws: OAuth2Error if authentication fails or JSON parsing fails
    public func authenticateWithServiceAccount(
        credentialsJSON: String,
        scopes: [String],
        subject: String? = nil
    ) async throws -> TokenResponse {
        let credentials = try GoogleServiceAccountCredentials(from: credentialsJSON)
        return try await authenticateWithServiceAccount(
            credentials: credentials,
            scopes: scopes,
            subject: subject
        )
    }

    /// Authenticate using Google service account credentials from a file path
    /// - Parameters:
    ///   - credentialsFilePath: The path to the Google service account JSON file
    ///   - scopes: The requested scopes for the access token
    ///   - subject: Optional subject (user email) for domain-wide delegation
    /// - Returns: The token response containing the access token
    /// - Throws: OAuth2Error if authentication fails, file reading fails, or JSON parsing fails
    public func authenticateWithServiceAccount(
        credentialsFilePath: String,
        scopes: [String],
        subject: String? = nil
    ) async throws -> TokenResponse {
        do {
            let fileURL = URL(fileURLWithPath: credentialsFilePath)
            let jsonData = try Data(contentsOf: fileURL)
            let credentials = try GoogleServiceAccountCredentials(from: jsonData)
            return try await authenticateWithServiceAccount(
                credentials: credentials,
                scopes: scopes,
                subject: subject
            )
        } catch let error as OAuth2Error {
            throw error
        } catch {
            throw OAuth2Error.configurationError("Failed to load service account credentials from file '\(credentialsFilePath)': \(error)")
        }
    }

    /// Create a signed JWT for direct use as a bearer token (without token exchange)
    /// - Parameters:
    ///   - credentials: The Google service account credentials
    ///   - audience: The audience for the JWT (typically the API endpoint URL)
    ///   - subject: Optional subject (user email) for domain-wide delegation
    ///   - additionalClaims: Optional additional claims to include in the JWT
    /// - Returns: The signed JWT string that can be used directly as a bearer token
    /// - Throws: OAuth2Error if JWT creation fails
    public func createServiceAccountJWTToken(
        credentials: GoogleServiceAccountCredentials,
        audience: String,
        subject: String? = nil,
        additionalClaims: [String: String] = [:]
    ) async throws -> String {
        let now = Date()
        let expiration = now.addingTimeInterval(3600)  // 1 hour

        var claims = GoogleServiceAccountDirectJWT(
            iss: IssuerClaim(value: credentials.clientEmail),
            aud: AudienceClaim(value: audience),
            exp: ExpirationClaim(value: expiration),
            iat: IssuedAtClaim(value: now),
            sub: subject
        )

        // Add any additional claims
        claims.additionalClaims = additionalClaims

        // Create the signer with RSA key
        let signer = JWTKeyCollection()
        let jwkIdentifier = JWKIdentifier(string: credentials.privateKeyId)

        // Create RSA key from PEM string
        let rsaKey: JWTKit.Insecure.RSA.PrivateKey
        do {
            rsaKey = try JWTKit.Insecure.RSA.PrivateKey(pem: credentials.privateKey)
        } catch {
            throw OAuth2Error.configurationError("Failed to parse RSA private key from service account credentials: \(error)")
        }

        await signer.add(rsa: rsaKey, digestAlgorithm: .sha256, kid: jwkIdentifier)

        // Sign the JWT
        return try await signer.sign(claims, kid: jwkIdentifier)
    }

    /// Create a signed JWT for direct use as a bearer token using JSON string
    /// - Parameters:
    ///   - credentialsJSON: The Google service account credentials as a JSON string
    ///   - audience: The audience for the JWT (typically the API endpoint URL)
    ///   - subject: Optional subject (user email) for domain-wide delegation
    ///   - additionalClaims: Optional additional claims to include in the JWT
    /// - Returns: The signed JWT string that can be used directly as a bearer token
    /// - Throws: OAuth2Error if JWT creation fails or JSON parsing fails
    public func createServiceAccountJWTToken(
        credentialsJSON: String,
        audience: String,
        subject: String? = nil,
        additionalClaims: [String: String] = [:]
    ) async throws -> String {
        let credentials = try GoogleServiceAccountCredentials(from: credentialsJSON)
        return try await createServiceAccountJWTToken(
            credentials: credentials,
            audience: audience,
            subject: subject,
            additionalClaims: additionalClaims
        )
    }

    /// Create a signed JWT for direct use as a bearer token using file path
    /// - Parameters:
    ///   - credentialsFilePath: The path to the Google service account JSON file
    ///   - audience: The audience for the JWT (typically the API endpoint URL)
    ///   - subject: Optional subject (user email) for domain-wide delegation
    ///   - additionalClaims: Optional additional claims to include in the JWT
    /// - Returns: The signed JWT string that can be used directly as a bearer token
    /// - Throws: OAuth2Error if JWT creation fails, file reading fails, or JSON parsing fails
    public func createServiceAccountJWTToken(
        credentialsFilePath: String,
        audience: String,
        subject: String? = nil,
        additionalClaims: [String: String] = [:]
    ) async throws -> String {
        do {
            let fileURL = URL(fileURLWithPath: credentialsFilePath)
            let jsonData = try Data(contentsOf: fileURL)
            let credentials = try GoogleServiceAccountCredentials(from: jsonData)
            return try await createServiceAccountJWTToken(
                credentials: credentials,
                audience: audience,
                subject: subject,
                additionalClaims: additionalClaims
            )
        } catch let error as OAuth2Error {
            throw error
        } catch {
            throw OAuth2Error.configurationError("Failed to load service account credentials from file '\(credentialsFilePath)': \(error)")
        }
    }

    /// Create a JWT assertion for service account authentication
    /// - Parameters:
    ///   - credentials: The Google service account credentials
    ///   - scopes: The requested scopes
    ///   - subject: Optional subject for domain-wide delegation
    /// - Returns: The signed JWT assertion
    /// - Throws: OAuth2Error if JWT creation fails
    private func createServiceAccountJWT(
        credentials: GoogleServiceAccountCredentials,
        scopes: [String],
        subject: String? = nil
    ) async throws -> String {
        let now = Date()
        let expiration = now.addingTimeInterval(3600)  // 1 hour

        let payload = GoogleServiceAccountJWT(
            iss: IssuerClaim(value: credentials.clientEmail),
            scope: scopes.isEmpty ? nil : scopes.joined(separator: " "),
            aud: AudienceClaim(value: credentials.tokenUri),
            exp: ExpirationClaim(value: expiration),
            iat: IssuedAtClaim(value: now),
            sub: subject
        )

        // Create the signer with RSA key
        let signer = JWTKeyCollection()
        let jwkIdentifier = JWKIdentifier(string: credentials.privateKeyId)

        // Create RSA key from PEM string
        let rsaKey: JWTKit.Insecure.RSA.PrivateKey
        do {
            rsaKey = try JWTKit.Insecure.RSA.PrivateKey(pem: credentials.privateKey)
        } catch {
            throw OAuth2Error.configurationError("Failed to parse RSA private key from service account credentials: \(error)")
        }

        await signer.add(rsa: rsaKey, digestAlgorithm: .sha256, kid: jwkIdentifier)

        // Sign the JWT
        return try await signer.sign(payload, kid: jwkIdentifier)
    }

    /// Exchange JWT assertion for access token
    /// - Parameters:
    ///   - jwt: The signed JWT assertion
    ///   - credentials: The service account credentials
    /// - Returns: The token response
    /// - Throws: OAuth2Error if the token exchange fails
    private func exchangeJWTForToken(
        jwt: String,
        credentials: GoogleServiceAccountCredentials
    ) async throws -> TokenResponse {
        guard let url = URL(string: credentials.tokenUri) else {
            throw OAuth2Error.configurationError("Invalid token URI: \(credentials.tokenUri)")
        }

        let parameters = [
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt,
        ]

        // Convert parameters to form-urlencoded body
        let formBody =
            parameters
            .map { key, value in
                "\(key.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? key)=\(value.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? value)"
            }
            .joined(separator: "&")

        guard let bodyData = formBody.data(using: .utf8) else {
            throw OAuth2Error.configurationError("Failed to encode request parameters")
        }

        var request = HTTPClientRequest(url: url.absoluteString)
        request.method = .POST
        request.headers.add(name: "Content-Type", value: "application/x-www-form-urlencoded")
        request.headers.add(name: "Accept", value: "application/json")
        request.headers.add(name: "User-Agent", value: USER_AGENT)
        request.body = .bytes(bodyData)

        do {
            let response = try await oauthKit.httpClient.execute(request, timeout: .seconds(60))

            guard response.status == .ok else {
                let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
                let responseString = String(buffer: responseBody)
                throw OAuth2Error.tokenExchangeError("Service account token request failed with status: \(response.status), body: \(responseString)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit
            let decoder = JSONDecoder()
            return try decoder.decode(TokenResponse.self, from: responseBody)
        } catch let error as OAuth2Error {
            throw error
        } catch {
            throw OAuth2Error.networkError("Service account token request failed: \(error)")
        }
    }
}

/// Google Service Account Credentials
public struct GoogleServiceAccountCredentials: Codable, Sendable {
    /// The type of credentials (should be "service_account")
    public let type: String

    /// The project ID
    public let projectId: String

    /// The private key ID
    public let privateKeyId: String

    /// The private key in PEM format
    public let privateKey: String

    /// The client email (service account email)
    public let clientEmail: String

    /// The client ID
    public let clientId: String

    /// The auth URI
    public let authUri: String

    /// The token URI
    public let tokenUri: String

    /// The auth provider X509 cert URL
    public let authProviderX509CertUrl: String

    /// The client X509 cert URL
    public let clientX509CertUrl: String

    /// Universe domain (optional, defaults to googleapis.com)
    public let universeDomain: String?

    enum CodingKeys: String, CodingKey {
        case type
        case projectId = "project_id"
        case privateKeyId = "private_key_id"
        case privateKey = "private_key"
        case clientEmail = "client_email"
        case clientId = "client_id"
        case authUri = "auth_uri"
        case tokenUri = "token_uri"
        case authProviderX509CertUrl = "auth_provider_x509_cert_url"
        case clientX509CertUrl = "client_x509_cert_url"
        case universeDomain = "universe_domain"
    }

    /// Initialize service account credentials from JSON data
    /// - Parameter jsonData: The JSON data from the service account key file
    /// - Throws: DecodingError if the JSON is invalid
    public init(from jsonData: Data) throws {
        let decoder = JSONDecoder()
        self = try decoder.decode(GoogleServiceAccountCredentials.self, from: jsonData)
    }

    /// Initialize service account credentials from a JSON string
    /// - Parameter jsonString: The JSON string from the service account key file
    /// - Throws: DecodingError if the JSON is invalid, or if the string cannot be converted to Data
    public init(from jsonString: String) throws {
        guard let jsonData = jsonString.data(using: .utf8) else {
            throw OAuth2Error.configurationError("Invalid JSON string - cannot convert to Data")
        }
        try self.init(from: jsonData)
    }
}

/// JWT claims for Google service account authentication (for token exchange)
struct GoogleServiceAccountJWT: JWTPayload {
    let iss: IssuerClaim
    let scope: String?
    let aud: AudienceClaim
    let exp: ExpirationClaim
    let iat: IssuedAtClaim
    let sub: String?

    enum CodingKeys: String, CodingKey {
        case iss, scope, aud, exp, iat, sub
    }

    func verify(using algorithm: some JWTAlgorithm) async throws {
        try exp.verifyNotExpired()
    }
}

/// JWT claims for direct Google service account authentication (without token exchange)
struct GoogleServiceAccountDirectJWT: JWTPayload {
    let iss: IssuerClaim
    let aud: AudienceClaim
    let exp: ExpirationClaim
    let iat: IssuedAtClaim
    let sub: String?
    var additionalClaims: [String: String] = [:]

    enum CodingKeys: String, CodingKey {
        case iss, aud, exp, iat, sub
    }

    init(iss: IssuerClaim, aud: AudienceClaim, exp: ExpirationClaim, iat: IssuedAtClaim, sub: String?) {
        self.iss = iss
        self.aud = aud
        self.exp = exp
        self.iat = iat
        self.sub = sub
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(iss, forKey: .iss)
        try container.encode(aud, forKey: .aud)
        try container.encode(exp, forKey: .exp)
        try container.encode(iat, forKey: .iat)
        try container.encodeIfPresent(sub, forKey: .sub)

        // Encode additional claims
        for (key, value) in additionalClaims {
            let dynamicKey = DynamicCodingKeys(stringValue: key)
            var dynamicContainer = encoder.container(keyedBy: DynamicCodingKeys.self)
            try dynamicContainer.encode(value, forKey: dynamicKey)
        }
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        iss = try container.decode(IssuerClaim.self, forKey: .iss)
        aud = try container.decode(AudienceClaim.self, forKey: .aud)
        exp = try container.decode(ExpirationClaim.self, forKey: .exp)
        iat = try container.decode(IssuedAtClaim.self, forKey: .iat)
        sub = try container.decodeIfPresent(String.self, forKey: .sub)

        // Decode additional claims
        let dynamicContainer = try decoder.container(keyedBy: DynamicCodingKeys.self)
        var claims: [String: String] = [:]
        let knownKeys = Set(CodingKeys.allCases.map(\.stringValue))
        for key in dynamicContainer.allKeys {
            if !knownKeys.contains(key.stringValue) {
                if let value = try? dynamicContainer.decode(String.self, forKey: key) {
                    claims[key.stringValue] = value
                }
            }
        }
        additionalClaims = claims
    }

    func verify(using algorithm: some JWTAlgorithm) async throws {
        try exp.verifyNotExpired()
    }
}

extension GoogleServiceAccountDirectJWT.CodingKeys: CaseIterable {}

/// Google Sign-In prompt behavior
public enum GooglePrompt: String {
    /// Default behavior - shows the authentication page when necessary
    case none = "none"

    /// Always show the authentication page
    case consent = "consent"

    /// Always show the account selection page
    case selectAccount = "select_account"
}
