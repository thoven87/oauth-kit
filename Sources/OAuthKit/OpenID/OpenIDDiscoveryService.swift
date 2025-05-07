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

/// Service for discovering OpenID Connect provider configuration
public struct OpenIDDiscoveryService {
    /// HTTP client for making requests
    private let httpClient: HTTPClient

    /// Logger for discovery operations
    private let logger: Logger

    /// Initialize a new OpenID discovery service
    /// - Parameters:
    ///   - httpClient: The HTTP client used for making requests
    ///   - logger: Logger used for discovery operations
    public init(
        httpClient: HTTPClient,
        logger: Logger = Logger(label: "com.oauthkit.OpenIDDiscoveryService")
    ) {
        self.httpClient = httpClient
        self.logger = logger
    }

    /// Discover OpenID Connect provider configuration
    /// - Parameter url: The URL to the OpenID Connect discovery document or base issuer URL
    /// - Returns: The OpenID Connect provider configuration
    /// - Throws: OAuth2Error if discovery fails
    public func discover(url: String) async throws -> OpenIDConfiguration {
        let discoveryURL: String

        // If the URL doesn't end with .well-known/openid-configuration, append it
        if url.hasSuffix("/.well-known/openid-configuration") || url.hasSuffix(".well-known/openid-configuration") {
            discoveryURL = url
        } else {
            // Normalize the URL to ensure it has a trailing slash before appending
            let baseURL = url.hasSuffix("/") ? url : "\(url)/"
            discoveryURL = "\(baseURL).well-known/openid-configuration"
        }

        logger.debug("Discovering OpenID configuration at: \(discoveryURL)")

        var request = HTTPClientRequest(url: discoveryURL)
        request.method = .GET
        request.headers.add(name: "Accept", value: "application/json")
        request.headers.add(name: "User-Agent", value: USER_AGENT)

        do {
            let response = try await httpClient.execute(request, timeout: .seconds(60))

            guard response.status == .ok else {
                logger.error("OpenID discovery failed with status: \(response.status)")
                throw OAuth2Error.openIDConfigError("Discovery request failed with status: \(response.status)")
            }

            let responseBody = try await response.body.collect(upTo: 1024 * 1024)  // 1MB limit

            let decoder = JSONDecoder()
            return try decoder.decode(OpenIDConfiguration.self, from: responseBody)
        } catch let error as OAuth2Error {
            throw error
        } catch {
            logger.error("OpenID discovery failed with error: \(error)")
            throw OAuth2Error.openIDConfigError("Discovery request failed: \(error)")
        }
    }
}
