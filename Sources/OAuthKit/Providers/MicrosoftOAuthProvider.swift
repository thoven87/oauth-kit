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
import Logging
import NIOFoundationCompat

/// Provider for Microsoft OAuth2/OpenID Connect authentication
public struct MicrosoftOAuthProvider: Sendable {
    /// Microsoft's common (multi-tenant) OAuth2/OIDC discovery URL
    public static let commonDiscoveryURL = "https://login.microsoftonline.com/common/v2.0/"

    /// Generate Microsoft's tenant-specific discovery URL
    /// - Parameter tenantID: The Azure AD tenant ID
    /// - Returns: The discovery URL for the specified tenant
    public static func tenantDiscoveryURL(tenantID: String) -> String {
        "https://login.microsoftonline.com/\(tenantID)/v2.0/"
    }

    /// The OAuthKit instance
    private let oauthKit: OAuthKit

    /// The OpenID Connect client configured for Microsoft
    private let client: OpenIDConnectClient

    /// Initialize a new Microsoft OAuth provider
    /// - Parameter oauthKit: The OAuthKit instance
    /// - Parameter openIDConnectClient: The OpenID Connect client configured for Microsoft
    internal init(oauthKit: OAuthKit, openIDConnectClient client: OpenIDConnectClient) {
        self.oauthKit = oauthKit
        self.client = client
    }

    /// Generate an authorization URL for Microsoft Sign-In with recommended parameters
    /// - Parameters:
    ///   - state: An opaque value to maintain state between the request and callback
    ///   - prompt: Controls the Microsoft Sign-In prompt behavior
    ///   - loginHint: Email address to pre-fill the authentication screen
    ///   - domainHint: Hint about the domain/tenant the user should use to sign in
    ///   - usePKCE: Whether to use PKCE (recommended and enabled by default)
    /// - Returns: A tuple containing the authorization URL and code verifier (for PKCE)
    public func signInURL(
        state: String? = nil,
        prompt: MicrosoftPrompt? = nil,
        loginHint: String? = nil,
        domainHint: MicrosoftDomainHint? = nil,
        usePKCE: Bool = true
    ) throws -> (url: URL, codeVerifier: String?) {
        var additionalParams: [String: String] = [:]
        var codeVerifier: String? = nil
        var codeChallenge: String? = nil

        // Generate PKCE if requested
        if usePKCE {
            let pkce = OAuth2Client.generatePKCE()
            codeVerifier = pkce.codeVerifier
            codeChallenge = pkce.codeChallenge
        }

        // Add Microsoft-specific parameters
        if let prompt = prompt {
            additionalParams["prompt"] = prompt.rawValue
        }

        if let loginHint = loginHint {
            additionalParams["login_hint"] = loginHint
        }

        if let domainHint = domainHint {
            additionalParams["domain_hint"] = domainHint.rawValue
        }

        // Microsoft recommends adding response_mode for security
        additionalParams["response_mode"] = "query"

        // Generate nonce for improved security
        let nonce = UUID().uuidString
        additionalParams["nonce"] = nonce

        let url = try client.authorizationURL(
            state: state,
            codeChallenge: codeChallenge,
            additionalParameters: additionalParams
        )

        return (url, codeVerifier)
    }

    /// Exchange an authorization code for tokens with Microsoft
    /// - Parameters:
    ///   - code: The authorization code received from Microsoft
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

    /// Retrieve the user's profile information from Microsoft
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    /// - Returns: The user's Microsoft profile information
    public func getUserProfile(
        accessToken: String
    ) async throws -> MicrosoftUserProfile {
        let userInfo: MicrosoftUserProfile = try await client.getUserInfo(accessToken: accessToken)
        return userInfo
    }

    /// Call the Microsoft Graph API
    /// - Parameters:
    ///   - accessToken: The access token from the token response
    ///   - endpoint: The Graph API endpoint to call (e.g., "/me")
    ///   - httpClient: The HTTP client to use for the request
    ///   - logger: Logger for the Graph API operation
    /// - Returns: The response data as a dictionary
    public func callGraphAPI(
        accessToken: String,
        endpoint: String,
        httpClient: HTTPClient = HTTPClient.shared,
        logger: Logger = Logger(label: "com.oauthkit.MicrosoftOAuthProvider")
    ) async throws -> [String: Any] {
        let apiEndpoint =
            endpoint.hasPrefix("/")
            ? "https://graph.microsoft.com/v1.0\(endpoint)"
            : "https://graph.microsoft.com/v1.0/\(endpoint)"

        var request = HTTPClientRequest(url: apiEndpoint)
        request.method = .GET
        request.headers.add(name: "Authorization", value: "Bearer \(accessToken)")
        request.headers.add(name: "Accept", value: "application/json")
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        do {
            let response = try await httpClient.execute(request, timeout: .seconds(60))

            guard response.status == .ok else {
                logger.error("Graph API request failed with status: \(response.status)")
                throw OAuth2Error.responseError("Graph API request failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit

            guard let jsonObject = try JSONSerialization.jsonObject(with: responseBody) as? [String: Any] else {
                throw OAuth2Error.responseError("Invalid Graph API response format")
            }

            return jsonObject
        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("Graph API request failed with error: \(error)")
            throw OAuth2Error.networkError("Graph API request failed: \(error)")
        }
    }
}

/// Microsoft Sign-In prompt behavior
public enum MicrosoftPrompt: String {
    /// Default behavior
    case none = "none"

    /// Force the user to enter their credentials on this request
    case login = "login"

    /// Prompt the user to select from multiple accounts they might have cached
    case selectAccount = "select_account"

    /// Force consent dialogue showing permissions requested by the app
    case consent = "consent"
}

/// Microsoft domain hint - helps direct users to the correct identity provider
public enum MicrosoftDomainHint: String {
    /// Hint the user should sign in with their consumer account
    case consumers = "consumers"

    /// Hint the user should sign in with their organizational account
    case organizations = "organizations"
}

/// Microsoft user profile information
public struct MicrosoftUserProfile: Codable {
    /// The user's unique Microsoft ID
    public let id: String

    /// The user's email address (may be absent for consumer accounts)
    public let email: String?

    /// The user's full name
    public let name: String?

    /// The user's given name
    public let givenName: String?

    /// The user's family name
    public let familyName: String?

    /// The user's display name
    //public let displayName: String?

    /// The user's job title
    public let jobTitle: String?

    /// The user's office location
    public let officeLocation: String?

    /// The user's preferred language
    public let preferredLanguage: String?

    /// The user's tenant ID (for organizational accounts)
    public let tenantId: String?

    enum CodingKeys: String, CodingKey {
        case id = "sub"
        case email
        case name
        case givenName = "given_name"
        case familyName = "family_name"
        //case displayName = "name"
        case jobTitle
        case officeLocation
        case preferredLanguage
        case tenantId = "tid"
    }
}
