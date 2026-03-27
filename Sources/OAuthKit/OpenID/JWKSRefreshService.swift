//===----------------------------------------------------------------------===//
//
// This source file is part of the oauth-kit open source project
//
// Copyright (c) 2026 the oauth-kit project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of oauth-kit project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import AsyncAlgorithms
import AsyncHTTPClient
import Foundation
import JWTKit
import Logging
import NIOHTTP1
import ServiceLifecycle
import Synchronization

/// Background service that periodically refreshes JWKS (JSON Web Key Sets)
/// from registered OpenID Connect provider endpoints.
///
/// The service fetches fresh key sets on a configurable interval and feeds them
/// into a shared ``JWKSKeyManager``, which performs in-place key rotation using
/// jwt-kit's `removeAll(except:)` / `add(jwks:)` primitives.  This means every
/// ``OpenIDConnectClient`` that shares the same key manager will immediately
/// see rotated keys without any manual cache invalidation.
///
/// ## Lifecycle
///
/// `JWKSRefreshService` conforms to `ServiceLifecycle.Service`.  Add it (or the
/// ``OAuthClientFactory`` that owns it) to a `ServiceGroup` so that it runs
/// until a graceful-shutdown signal is received:
///
/// ```swift
/// let serviceGroup = ServiceGroup(
///     configuration: .init(
///         services: [oauthClientFactory],
///         gracefulShutdownSignals: [.sigterm, .sigint],
///         logger: logger
///     )
/// )
/// try await serviceGroup.run()
/// ```
public final class JWKSRefreshService: Service {

    // MARK: - Configuration

    /// Tuning knobs for the refresh loop.
    public struct Configuration: Sendable {
        /// How often to re-fetch every registered JWKS endpoint.
        public let refreshInterval: Duration

        /// Per-request HTTP timeout.
        public let requestTimeout: Duration

        /// Maximum number of retry attempts for a single fetch.
        public let maxRetries: Int

        /// Base delay between retries (multiplied by the attempt number).
        public let retryDelay: Duration

        public init(
            refreshInterval: Duration = .seconds(1800),
            requestTimeout: Duration = .seconds(30),
            maxRetries: Int = 3,
            retryDelay: Duration = .seconds(1)
        ) {
            self.refreshInterval = refreshInterval
            self.requestTimeout = requestTimeout
            self.maxRetries = maxRetries
            self.retryDelay = retryDelay
        }
    }

    // MARK: - Endpoint registry

    /// Lightweight value that identifies a JWKS endpoint to poll.
    private struct JWKSEndpoint: Sendable, Hashable {
        let jwksUri: String
        let issuer: String

        func hash(into hasher: inout Hasher) {
            hasher.combine(jwksUri)
        }

        static func == (lhs: JWKSEndpoint, rhs: JWKSEndpoint) -> Bool {
            lhs.jwksUri == rhs.jwksUri
        }
    }

    // MARK: - Stored properties

    private let httpClient: HTTPClient
    private let keyManager: JWKSKeyManager
    private let configuration: Configuration
    private let logger: Logger

    /// Thread-safe set of endpoints to refresh on each cycle.
    private let registeredEndpoints: Mutex<Set<JWKSEndpoint>> = Mutex([])

    // MARK: - Init

    /// Create a new refresh service.
    ///
    /// - Parameters:
    ///   - httpClient: The HTTP client used to fetch JWKS documents.
    ///   - keyManager: The shared key manager that will receive updated keys.
    ///   - configuration: Tuning knobs for the refresh loop.
    ///   - logger: Logger for service-level messages.
    internal init(
        httpClient: HTTPClient,
        keyManager: JWKSKeyManager,
        configuration: Configuration = Configuration(),
        logger: Logger = Logger(label: "com.oauthkit.JWKSRefreshService")
    ) {
        self.httpClient = httpClient
        self.keyManager = keyManager
        self.configuration = configuration
        self.logger = logger
    }

    // MARK: - Endpoint registration

    /// Register a JWKS endpoint for periodic refresh.
    ///
    /// - Parameters:
    ///   - jwksUri: The JWKS document URL.
    ///   - issuer: The issuer identifier (used only for logging).
    public func registerEndpoint(jwksUri: String, issuer: String) {
        registeredEndpoints.withLock { endpoints in
            _ = endpoints.insert(JWKSEndpoint(jwksUri: jwksUri, issuer: issuer))
        }
        logger.info(
            "Registered JWKS endpoint",
            metadata: [
                "jwksUri": .string(jwksUri),
                "issuer": .string(issuer),
            ]
        )
    }

    /// Register multiple endpoints discovered from OpenID configurations.
    public func registerEndpoints(from configurations: [OpenIDConfiguration]) {
        registeredEndpoints.withLock { endpoints in
            for config in configurations {
                endpoints.insert(
                    JWKSEndpoint(jwksUri: config.jwksUri, issuer: config.issuer)
                )
            }
        }
        logger.info(
            "Registered JWKS endpoints from OpenID configurations",
            metadata: ["count": .stringConvertible(configurations.count)]
        )
    }

    /// Stop refreshing a previously-registered endpoint.
    ///
    /// - Parameter jwksUri: The JWKS document URL to unregister.
    public func unregisterEndpoint(jwksUri: String) {
        registeredEndpoints.withLock { endpoints in
            endpoints = endpoints.filter { $0.jwksUri != jwksUri }
        }
        logger.info(
            "Unregistered JWKS endpoint",
            metadata: ["jwksUri": .string(jwksUri)]
        )
    }

    // MARK: - Service lifecycle

    /// Entry point called by `ServiceGroup`.
    ///
    /// Performs an initial refresh of every registered endpoint, then enters a
    /// timer loop that re-fetches on `configuration.refreshInterval` until
    /// graceful shutdown is triggered.
    public func run() async throws {
        logger.info(
            "Starting JWKS refresh service",
            metadata: ["interval": .stringConvertible(configuration.refreshInterval)]
        )

        await refreshAllEndpoints()

        let timer = AsyncTimerSequence(
            interval: configuration.refreshInterval,
            clock: ContinuousClock()
        ).cancelOnGracefulShutdown()

        for try await _ in timer {
            await refreshAllEndpoints()
        }

        logger.info("JWKS refresh service stopped")
    }

    // MARK: - Manual refresh

    /// Force an immediate refresh of every registered endpoint.
    ///
    /// - Returns: The number of endpoints that were successfully refreshed.
    @discardableResult
    public func forceRefreshAll() async -> Int {
        logger.info("Forcing refresh of all JWKS endpoints")
        return await refreshAllEndpoints()
    }

    // MARK: - Internal refresh logic

    /// Refresh all currently-registered endpoints concurrently.
    ///
    /// - Returns: The number of endpoints that were successfully refreshed.
    @discardableResult
    private func refreshAllEndpoints() async -> Int {
        let endpoints = registeredEndpoints.withLock { Array($0) }
        guard !endpoints.isEmpty else { return 0 }

        var successCount = 0

        await withTaskGroup(of: Bool.self) { group in
            for endpoint in endpoints {
                group.addTask {
                    await self.refreshEndpoint(endpoint)
                }
            }
            for await succeeded in group where succeeded {
                successCount += 1
            }
        }

        if successCount > 0 || endpoints.count > 0 {
            logger.debug(
                "JWKS refresh cycle complete",
                metadata: [
                    "refreshed": .stringConvertible(successCount),
                    "total": .stringConvertible(endpoints.count),
                ]
            )
        }

        return successCount
    }

    /// Fetch and update keys for a single endpoint.
    ///
    /// - Returns: `true` if the refresh succeeded.
    private func refreshEndpoint(_ endpoint: JWKSEndpoint) async -> Bool {
        do {
            let jwks = try await fetchJWKS(from: endpoint.jwksUri)
            try await keyManager.updateKeys(from: jwks, for: endpoint.jwksUri)
            logger.debug(
                "Refreshed JWKS",
                metadata: [
                    "jwksUri": .string(endpoint.jwksUri),
                    "issuer": .string(endpoint.issuer),
                ]
            )
            return true
        } catch {
            logger.error(
                "Failed to refresh JWKS",
                metadata: [
                    "jwksUri": .string(endpoint.jwksUri),
                    "issuer": .string(endpoint.issuer),
                    "error": .string(String(describing: error)),
                ]
            )
            return false
        }
    }

    // MARK: - HTTP fetch with retries

    /// Download a JWKS document, retrying on transient failures.
    private func fetchJWKS(from jwksUri: String) async throws -> JWKS {
        var lastError: Error?

        for attempt in 1...configuration.maxRetries {
            do {
                var request = HTTPClientRequest(url: jwksUri)
                request.method = .GET
                request.headers.add(name: "Accept", value: "application/json")
                request.headers.add(name: "User-Agent", value: USER_AGENT)

                let response = try await httpClient.execute(
                    request,
                    timeout: .seconds(Int64(configuration.requestTimeout.timeInterval))
                )

                guard response.status == .ok else {
                    let statusError = OAuth2Error.jwksError(
                        "JWKS request returned status \(response.status)"
                    )
                    if attempt == configuration.maxRetries { throw statusError }
                    lastError = statusError
                    logger.warning(
                        "JWKS fetch failed, retrying",
                        metadata: [
                            "attempt": .stringConvertible(attempt),
                            "maxRetries": .stringConvertible(configuration.maxRetries),
                            "status": .string("\(response.status)"),
                        ]
                    )
                    try await Task.sleep(for: configuration.retryDelay * attempt)
                    continue
                }

                let body = try await response.body.collect(upTo: 1024 * 1024)
                return try JSONDecoder().decode(JWKS.self, from: body)

            } catch let error as OAuth2Error {
                if attempt == configuration.maxRetries { throw error }
                lastError = error
                logger.warning(
                    "JWKS fetch failed, retrying",
                    metadata: [
                        "attempt": .stringConvertible(attempt),
                        "maxRetries": .stringConvertible(configuration.maxRetries),
                        "error": .string(String(describing: error)),
                    ]
                )
                try await Task.sleep(for: configuration.retryDelay * attempt)
            } catch {
                if attempt == configuration.maxRetries {
                    throw OAuth2Error.jwksError("JWKS request failed: \(error)")
                }
                lastError = error
                logger.warning(
                    "JWKS fetch failed, retrying",
                    metadata: [
                        "attempt": .stringConvertible(attempt),
                        "maxRetries": .stringConvertible(configuration.maxRetries),
                        "error": .string(String(describing: error)),
                    ]
                )
                try await Task.sleep(for: configuration.retryDelay * attempt)
            }
        }

        // Unreachable in practice — the loop always throws on the last attempt.
        throw OAuth2Error.jwksError(
            "JWKS request failed after \(configuration.maxRetries) attempts: "
                + String(describing: lastError)
        )
    }
}

// MARK: - Duration helpers

extension Duration {
    /// Convenience conversion to `Foundation.TimeInterval`.
    var timeInterval: TimeInterval {
        let (seconds, attoseconds) = self.components
        return TimeInterval(seconds)
            + TimeInterval(attoseconds) / 1_000_000_000_000_000_000
    }
}
