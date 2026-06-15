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
/// The service fetches fresh key sets and feeds them into a shared ``JWKSKeyManager``,
/// which performs in-place key rotation using jwt-kit's `removeAll(except:)` / `add(jwks:)`
/// primitives. Every ``OpenIDConnectClient`` that shares the same key manager will
/// immediately see rotated keys without any manual cache invalidation.
///
/// ## Refresh scheduling
///
/// Each endpoint is refreshed according to the `Cache-Control: max-age` value returned
/// by the JWKS server. The configured `refreshInterval` acts as a **ceiling**: if the
/// server advertises a TTL longer than `refreshInterval`, the configured value is used
/// instead. If the server returns no cache headers, `refreshInterval` is used as the
/// default. This means the service wakes up dynamically — one endpoint might refresh
/// every 15 minutes while another refreshes every 24 hours.
///
/// ## Lifecycle
///
/// `JWKSRefreshService` conforms to `ServiceLifecycle.Service`. Add it (or the
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
        /// Maximum interval between refreshes for any single endpoint.
        ///
        /// If a JWKS server returns `Cache-Control: max-age=N`, the effective TTL
        /// is `min(N seconds, refreshInterval)`. When no cache header is present,
        /// this value is used directly.
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

    /// Lightweight value that identifies a JWKS endpoint and tracks when it is next due.
    private struct JWKSEndpoint: Sendable {
        let jwksUri: String
        let issuer: String
        /// The earliest time at which this endpoint should next be fetched.
        /// Initialised to `.now` so the first run picks up all endpoints immediately.
        var nextRefreshAt: ContinuousClock.Instant

        init(jwksUri: String, issuer: String) {
            self.jwksUri = jwksUri
            self.issuer = issuer
            self.nextRefreshAt = ContinuousClock().now
        }
    }

    // MARK: - Stored properties

    private let httpClient: HTTPClient
    private let keyManager: JWKSKeyManager
    private let configuration: Configuration
    private let logger: Logger

    /// Thread-safe dictionary of endpoints keyed by JWKS URI.
    /// Using a dictionary (rather than a Set) allows mutating `nextRefreshAt` in place.
    private let registeredEndpoints: Mutex<[String: JWKSEndpoint]> = Mutex([:])

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
    /// If the endpoint is already registered, this is a no-op.
    ///
    /// - Parameters:
    ///   - jwksUri: The JWKS document URL.
    ///   - issuer: The issuer identifier (used only for logging).
    public func registerEndpoint(jwksUri: String, issuer: String) {
        registeredEndpoints.withLock { endpoints in
            guard endpoints[jwksUri] == nil else { return }
            endpoints[jwksUri] = JWKSEndpoint(jwksUri: jwksUri, issuer: issuer)
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
    ///
    /// Already-registered endpoints are left untouched.
    public func registerEndpoints(from configurations: [OpenIDConfiguration]) {
        registeredEndpoints.withLock { endpoints in
            for config in configurations {
                guard endpoints[config.jwksUri] == nil else { continue }
                endpoints[config.jwksUri] = JWKSEndpoint(jwksUri: config.jwksUri, issuer: config.issuer)
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
            _ = endpoints.removeValue(forKey: jwksUri)
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
    /// dynamic sleep loop. The service wakes at the earliest `nextRefreshAt`
    /// across all endpoints (capped at `configuration.refreshInterval`) and
    /// refreshes only the endpoints that are actually due. Graceful shutdown is
    /// handled by task cancellation, which causes `Task.sleep` to throw
    /// `CancellationError` and unwind the loop.
    public func run() async throws {
        logger.info(
            "Starting JWKS refresh service",
            metadata: ["maxInterval": .stringConvertible(configuration.refreshInterval)]
        )

        await refreshDueEndpoints()

        while true {
            try await Task.sleep(until: nextWakeupInstant(), clock: ContinuousClock())
            await refreshDueEndpoints()
        }
    }

    // MARK: - Manual refresh

    /// Force an immediate refresh of every registered endpoint, ignoring their
    /// current `nextRefreshAt` values.
    ///
    /// - Returns: The number of endpoints that were successfully refreshed.
    @discardableResult
    public func forceRefreshAll() async -> Int {
        logger.info("Forcing refresh of all JWKS endpoints")
        // Reset every endpoint so none is skipped by the due-time filter.
        let now = ContinuousClock().now
        registeredEndpoints.withLock { endpoints in
            for key in endpoints.keys {
                endpoints[key]?.nextRefreshAt = now
            }
        }
        return await refreshDueEndpoints()
    }

    // MARK: - Internal refresh logic

    /// The `ContinuousClock.Instant` at which the service should next wake.
    ///
    /// Returns the earliest `nextRefreshAt` across all registered endpoints,
    /// capped at `now + configuration.refreshInterval` so no endpoint can defer
    /// a refresh indefinitely.
    private func nextWakeupInstant() -> ContinuousClock.Instant {
        let now = ContinuousClock().now
        let cap = now + configuration.refreshInterval
        let earliest = registeredEndpoints.withLock { endpoints in
            endpoints.values.map(\.nextRefreshAt).min()
        }
        return min(earliest ?? cap, cap)
    }

    /// Refresh every endpoint whose `nextRefreshAt` is at or before now, concurrently.
    ///
    /// - Returns: The number of endpoints that were successfully refreshed.
    @discardableResult
    private func refreshDueEndpoints() async -> Int {
        let now = ContinuousClock().now
        let due = registeredEndpoints.withLock { endpoints in
            endpoints.values.filter { $0.nextRefreshAt <= now }
        }
        guard !due.isEmpty else { return 0 }

        var successCount = 0
        await withTaskGroup(of: Bool.self) { group in
            for endpoint in due {
                group.addTask { await self.refreshEndpoint(endpoint) }
            }
            for await succeeded in group where succeeded {
                successCount += 1
            }
        }

        logger.debug(
            "JWKS refresh cycle complete",
            metadata: [
                "refreshed": .stringConvertible(successCount),
                "due": .stringConvertible(due.count),
                "total": .stringConvertible(registeredEndpoints.withLock { $0.count }),
            ]
        )

        return successCount
    }

    /// Fetch and update keys for a single endpoint, then schedule its next refresh
    /// based on the server's `Cache-Control: max-age` (capped at `refreshInterval`).
    ///
    /// - Returns: `true` if the refresh succeeded.
    private func refreshEndpoint(_ endpoint: JWKSEndpoint) async -> Bool {
        do {
            let (jwks, maxAge) = try await fetchJWKS(from: endpoint.jwksUri)
            try await keyManager.updateKeys(from: jwks, for: endpoint.jwksUri)

            // Honour the server's advertised TTL, but never exceed the configured ceiling.
            let ttl =
                maxAge.map { min($0, configuration.refreshInterval) }
                ?? configuration.refreshInterval
            let nextRefresh = ContinuousClock().now + ttl

            registeredEndpoints.withLock { endpoints in
                endpoints[endpoint.jwksUri]?.nextRefreshAt = nextRefresh
            }

            logger.debug(
                "Refreshed JWKS",
                metadata: [
                    "jwksUri": .string(endpoint.jwksUri),
                    "issuer": .string(endpoint.issuer),
                    "ttl": .stringConvertible(ttl),
                    "cacheSource": .string(maxAge != nil ? "Cache-Control" : "default"),
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
    ///
    /// - Returns: The decoded `JWKS` and the `max-age` parsed from `Cache-Control`,
    ///   or `nil` if the header is absent or contains no valid `max-age` directive.
    private func fetchJWKS(from jwksUri: String) async throws -> (jwks: JWKS, maxAge: Duration?) {
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

                let maxAge = parseCacheMaxAge(from: response.headers)
                let body = try await response.body.collect(upTo: 1024 * 1024)
                let jwks = try JSON.decode(JWKS.self, from: body)
                return (jwks, maxAge)

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

        throw OAuth2Error.jwksError(
            "JWKS request failed after \(configuration.maxRetries) attempts: "
                + String(describing: lastError)
        )
    }

    /// Parse `Cache-Control: max-age=N` from response headers.
    ///
    /// Returns `nil` if the header is absent or contains no valid positive `max-age` directive.
    private func parseCacheMaxAge(from headers: HTTPHeaders) -> Duration? {
        guard let cacheControl = headers.first(name: "Cache-Control") else { return nil }
        for directive in cacheControl.split(separator: ",") {
            let trimmed = directive.trimmingCharacters(in: .whitespaces).lowercased()
            if trimmed.hasPrefix("max-age=") {
                let valueStr = trimmed.dropFirst("max-age=".count)
                if let seconds = Int(valueStr), seconds > 0 {
                    return .seconds(seconds)
                }
            }
        }
        return nil
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
