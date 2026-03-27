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

/// Manages JWKS keys for multiple endpoints using a single shared `JWTKeyCollection`.
///
/// `JWKSKeyManager` leverages jwt-kit 5.4.0's `removeAll(except:)` and `add(jwks:)` APIs
/// to perform in-place key rotation without recreating the key collection. All
/// `OpenIDConnectClient` instances share the same underlying `JWTKeyCollection`,
/// so keys refreshed by the background `JWKSRefreshService` are immediately
/// available for token verification everywhere.
///
/// ## Key Rotation Flow
///
/// When keys are updated for an endpoint:
/// 1. New keys are added first (overwrites any existing keys with the same `kid`)
/// 2. Old keys that are no longer present in the JWKS are removed
///
/// This ordering ensures there is no window where a valid key is missing from
/// the collection.
public actor JWKSKeyManager {
    /// The shared key collection used for all token verification and signing.
    ///
    /// Because `JWTKeyCollection` is an actor and this is a `let` property,
    /// it can be accessed from any isolation domain without going through
    /// `JWKSKeyManager`'s own serialisation.
    private let keyCollection: JWTKeyCollection

    /// Tracks which `JWKIdentifier`s were loaded from each JWKS endpoint URI.
    private var endpointKeyIds: [String: Set<JWKIdentifier>]

    /// Logger for key management operations.
    private let logger: Logger

    /// Create a new key manager.
    ///
    /// - Parameter logger: Logger for key management operations.
    public init(logger: Logger = Logger(label: "com.oauthkit.JWKSKeyManager")) {
        self.keyCollection = JWTKeyCollection()
        self.endpointKeyIds = [:]
        self.logger = logger
    }

    // MARK: - Public — key collection access

    /// The underlying `JWTKeyCollection` shared across all clients.
    ///
    /// Use this to call `verify(_:as:)` or any other `JWTKeyCollection` method
    /// directly.  Because the property is `nonisolated` and the value is
    /// `Sendable` (actors are always `Sendable`), no `await` on the
    /// `JWKSKeyManager` actor is required — only the implicit `await` for the
    /// `JWTKeyCollection` actor itself.
    public nonisolated var keys: JWTKeyCollection {
        keyCollection
    }

    // MARK: - Public — key lifecycle

    /// Update the keys for a specific JWKS endpoint.
    ///
    /// This performs an atomic-style rotation:
    /// 1. **Add** the new keys first (existing keys with the same `kid` are
    ///    overwritten in place, so during the brief window between add and
    ///    remove both old and new keys coexist).
    /// 2. **Remove** any keys that belonged to this endpoint previously but
    ///    are no longer present in the new JWKS.
    ///
    /// Keys belonging to *other* endpoints are never touched.
    ///
    /// - Parameters:
    ///   - jwks: The freshly-fetched JWKS for this endpoint.
    ///   - jwksUri: The canonical URI the JWKS was fetched from.
    public func updateKeys(from jwks: JWKS, for jwksUri: String) async throws {
        let newKids = Self.extractKeyIds(from: jwks)

        // 1. Add new keys first so there is no gap in coverage.
        try await keyCollection.add(jwks: jwks)

        // 2. Compute the full set of key IDs we want to *keep*:
        //    - all new kids for this endpoint
        //    - all kids from every other endpoint
        var kidsToKeep = newKids
        for (uri, kids) in endpointKeyIds where uri != jwksUri {
            kidsToKeep.formUnion(kids)
        }

        // 3. Remove stale keys (clears default signer as well since we only
        //    use the collection for verification, not signing).
        await keyCollection.removeAll(except: Array(kidsToKeep))

        // 4. Update tracking state.
        endpointKeyIds[jwksUri] = newKids

        logger.debug(
            "Updated JWKS keys",
            metadata: [
                "jwksUri": .string(jwksUri),
                "keyCount": .stringConvertible(newKids.count),
            ]
        )
    }

    /// Remove all keys that were loaded from a specific endpoint.
    ///
    /// - Parameter jwksUri: The endpoint whose keys should be removed.
    public func removeKeys(for jwksUri: String) async {
        guard endpointKeyIds.removeValue(forKey: jwksUri) != nil else { return }

        var kidsToKeep: Set<JWKIdentifier> = []
        for (_, kids) in endpointKeyIds {
            kidsToKeep.formUnion(kids)
        }

        await keyCollection.removeAll(except: Array(kidsToKeep))

        logger.debug(
            "Removed JWKS keys",
            metadata: ["jwksUri": .string(jwksUri)]
        )
    }

    // MARK: - Public — queries

    /// Whether the manager has loaded at least one key for the given endpoint.
    ///
    /// - Parameter jwksUri: The JWKS endpoint URI to check.
    /// - Returns: `true` if keys have been loaded for this endpoint.
    public func hasKeys(for jwksUri: String) -> Bool {
        guard let kids = endpointKeyIds[jwksUri] else { return false }
        return !kids.isEmpty
    }

    /// All JWKS endpoint URIs that currently have keys loaded.
    public func registeredEndpoints() -> [String] {
        Array(endpointKeyIds.keys)
    }

    // MARK: - Private helpers

    /// Extract all `JWKIdentifier`s from a JWKS, skipping keys without a `kid`.
    private static func extractKeyIds(from jwks: JWKS) -> Set<JWKIdentifier> {
        Set(jwks.keys.compactMap { $0.keyIdentifier })
    }
}
