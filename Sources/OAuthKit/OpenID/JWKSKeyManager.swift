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

import JWTKit
import Logging
import Synchronization

/// Manages JWKS keys for multiple endpoints, giving each endpoint its own
/// isolated `JWTKeyCollection`.
///
/// ## Design
///
/// Each registered JWKS endpoint gets its own `JWTKeyCollection`. This means:
///
/// - **No kid collisions**: two providers that happen to publish the same `kid`
///   value are stored in separate collections and can never overwrite each other.
/// - **Atomic rotation**: refreshing one endpoint replaces its entire collection
///   in a single lock-protected assignment. There is no window where a key is
///   absent, and concurrent refreshes for different endpoints never interact.
///
/// `JWKSKeyManager` is `Sendable` and safe to share across concurrency domains.
public final class JWKSKeyManager: Sendable {

    private struct EndpointState: Sendable {
        let collection: JWTKeyCollection
        /// The set of `kid` values currently in the collection, used to detect
        /// whether a freshly-fetched JWKS actually differs from what we already have.
        let kidSet: Set<JWKIdentifier>
    }

    /// Thread-safe map from JWKS endpoint URI to its key collection and kid fingerprint.
    private let endpoints: Mutex<[String: EndpointState]>
    private let logger: Logger

    /// Create a new key manager.
    ///
    /// - Parameter logger: Logger for key management operations.
    public init(logger: Logger = Logger(label: "com.oauthkit.JWKSKeyManager")) {
        self.endpoints = Mutex([:])
        self.logger = logger
    }

    // MARK: - Key collection access

    /// Returns the `JWTKeyCollection` for the given JWKS endpoint, or `nil`
    /// if no keys have been loaded for that endpoint yet.
    ///
    /// The returned reference is a snapshot: concurrent calls to
    /// ``updateKeys(from:for:)`` replace the collection atomically, so an
    /// in-flight `verify` call always completes against a consistent key set.
    public func keys(for jwksUri: String) -> JWTKeyCollection? {
        endpoints.withLock { $0[jwksUri]?.collection }
    }

    // MARK: - Key lifecycle

    /// Replace the key collection for a JWKS endpoint with freshly-fetched keys.
    ///
    /// A new `JWTKeyCollection` is built from `jwks` entirely outside the lock
    /// (the only async step), then stored atomically via a single lock-protected
    /// assignment. There are no suspension points inside the critical section, so
    /// concurrent refreshes for different endpoints never interleave.
    ///
    /// If `jwks` contains no keys the existing collection for this endpoint is
    /// removed instead.
    ///
    /// - Parameters:
    ///   - jwks: The freshly-fetched JWKS for this endpoint.
    ///   - jwksUri: The canonical URI the JWKS was fetched from.
    public func updateKeys(from jwks: JWKS, for jwksUri: String) async throws {
        guard !jwks.keys.isEmpty else {
            endpoints.withLock { _ = $0.removeValue(forKey: jwksUri) }
            logger.debug(
                "Cleared JWKS keys (empty response)",
                metadata: ["jwksUri": .string(jwksUri)]
            )
            return
        }

        let newKids = Set(jwks.keys.compactMap(\.keyIdentifier))

        // Fast path: if the set of kids is identical to the last fetch, the
        // JWKS content has not changed. Skip all actor work.
        let existing = endpoints.withLock { $0[jwksUri] }
        if let existing, existing.kidSet == newKids {
            logger.debug(
                "JWKS keys unchanged, skipping update",
                metadata: ["jwksUri": .string(jwksUri)]
            )
            return
        }

        // Reuse the existing collection for in-place rotation (following the
        // jwt-kit example pattern); only allocate a new one on first load.
        let collection = existing?.collection ?? JWTKeyCollection()

        // Add new/updated keys — JWTKeyCollection overwrites existing keys with
        // the same kid, so this is safe to call on a live collection.
        try await collection.add(jwks: jwks)

        // Remove any keys from previous fetches that are no longer in the JWKS.
        await collection.removeAll(except: Array(newKids))

        endpoints.withLock { $0[jwksUri] = EndpointState(collection: collection, kidSet: newKids) }

        logger.debug(
            "Updated JWKS keys",
            metadata: [
                "jwksUri": .string(jwksUri),
                "keyCount": .stringConvertible(newKids.count),
            ]
        )
    }

    /// Remove all keys for a specific endpoint.
    ///
    /// - Parameter jwksUri: The endpoint whose keys should be removed.
    public func removeKeys(for jwksUri: String) {
        endpoints.withLock { _ = $0.removeValue(forKey: jwksUri) }
        logger.debug("Removed JWKS keys", metadata: ["jwksUri": .string(jwksUri)])
    }

    // MARK: - Queries

    /// Whether the manager holds a key collection for the given endpoint.
    ///
    /// Returns `false` if keys have not yet been loaded, or if the last fetch
    /// returned an empty JWKS.
    public func hasKeys(for jwksUri: String) -> Bool {
        endpoints.withLock { $0[jwksUri] != nil }
    }

    /// All JWKS endpoint URIs that currently have key collections loaded.
    public func registeredEndpoints() -> [String] {
        endpoints.withLock { Array($0.keys) }
    }
}
