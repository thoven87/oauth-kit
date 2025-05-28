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
import Logging

public struct OAuth2Client: OAuth2ClientProtocol {
    /// HTTP client for making requests
    public var httpClient: AsyncHTTPClient.HTTPClient

    /// Client ID provided by the OAuth2 provider
    public var clientID: String

    /// Client secret provided by the OAuth2 provider
    public var clientSecret: String

    /// Token endpoint URL
    public var tokenEndpoint: String

    /// Authorization endpoint URL (optional)
    public var authorizationEndpoint: String?

    /// Redirect URI registered with the OAuth2 provider
    public var redirectURI: String?

    /// Logger used for OAuth operations
    public var logger: Logging.Logger

    /// Initialize a new OAuth2Client client
    /// - Parameters:
    ///   - httpClient: The HTTP client used for making requests
    ///   - clientID: The client ID provided by the OAuth2 provider
    ///   - clientSecret: The client secret provided by the OAuth2 provider
    ///   - tokenEndpoint: The OAuth2 token endpoint
    ///   - authorizationEndpoint:The OAuth2 authorization endpoint
    ///   - redirectURI: The redirect URI registered with the OAuth2 provider
    ///   - logger: Logger used for OAuth2Client operations
    public init(
        httpClient: AsyncHTTPClient.HTTPClient = .shared,
        clientID: String,
        clientSecret: String,
        tokenEndpoint: String,
        authorizationEndpoint: String?,
        redirectURI: String?,
        logger: Logging.Logger = Logger(label: "com.oauthkit.OAuth2Client")
    ) {
        self.httpClient = httpClient
        self.clientID = clientID
        self.clientSecret = clientSecret
        self.tokenEndpoint = tokenEndpoint
        self.authorizationEndpoint = authorizationEndpoint
        self.redirectURI = redirectURI
        self.logger = logger
    }
}
