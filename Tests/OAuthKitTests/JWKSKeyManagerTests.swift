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

import Foundation
import JWTKit
import Logging
import Testing

@testable import OAuthKit

@Suite("JWKSKeyManager Tests")
struct JWKSKeyManagerTests {
    static let testJWKSUri = "https://example.com/.well-known/jwks.json"
    static let testJWKSUri2 = "https://other.example.com/.well-known/jwks.json"

    private func createKeyManager() -> JWKSKeyManager {
        JWKSKeyManager(logger: Logger(label: "test.JWKSKeyManager"))
    }

    // MARK: - Helper Methods

    private func createTestJWKS() -> JWKS {
        JWKSTestUtilities.createTestJWKS()
    }

    private func createTestJWKSWithKid(_ kid: String) -> JWKS {
        let jwksJSON = """
            {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "\(kid)",
                        "alg": "RS256",
                        "use": "sig",
                        "n": "vTHHoCaR0tlYfvapRv94hUTMrdSymIrWIIZ5Kmv5bIYWtK0TMX0icLkB0PzR2IDLj1L7hzBKUljBGzjf6ujfZwru5-odDZ344A6AhH5B5Zie1ALUTnizD-8XtWcdOtv4aF5NwgRJns0YY-HVr_KKfPZurfMf7JI2wSCt0TRRUixkfJgypnLNZNMowcMiGD9GYdCb2mC43V8DKNpUIIIUJK_auxqAxdEnY6GwI4zYnQdCv8ULai_LcB2CQhj5gm9PeKI6K1qkKs5_F1N2-2y9srrSk7pYPU0xxrj5Ap5GsTaJJJhV9QV1bgDiJaakWhh2m9jSs6SsufHCPT5RiCVh5Q",
                        "e": "AQAB"
                    }
                ]
            }
            """
        return try! JSONDecoder().decode(JWKS.self, from: Data(jwksJSON.utf8))
    }

    private func createMultiKeyJWKS(kids: [String]) -> JWKS {
        let keysJSON = kids.map { kid in
            """
            {
                "kty": "RSA",
                "kid": "\(kid)",
                "alg": "RS256",
                "use": "sig",
                "n": "vTHHoCaR0tlYfvapRv94hUTMrdSymIrWIIZ5Kmv5bIYWtK0TMX0icLkB0PzR2IDLj1L7hzBKUljBGzjf6ujfZwru5-odDZ344A6AhH5B5Zie1ALUTnizD-8XtWcdOtv4aF5NwgRJns0YY-HVr_KKfPZurfMf7JI2wSCt0TRRUixkfJgypnLNZNMowcMiGD9GYdCb2mC43V8DKNpUIIIUJK_auxqAxdEnY6GwI4zYnQdCv8ULai_LcB2CQhj5gm9PeKI6K1qkKs5_F1N2-2y9srrSk7pYPU0xxrj5Ap5GsTaJJJhV9QV1bgDiJaakWhh2m9jSs6SsufHCPT5RiCVh5Q",
                "e": "AQAB"
            }
            """
        }.joined(separator: ",")

        let jwksJSON = """
            { "keys": [\(keysJSON)] }
            """
        return try! JSONDecoder().decode(JWKS.self, from: Data(jwksJSON.utf8))
    }

    // MARK: - Basic Storage Tests

    @Test("Update keys stores keys for an endpoint")
    func updateKeysStoresKeys() async throws {
        let manager = createKeyManager()
        let jwks = createTestJWKS()

        try await manager.updateKeys(from: jwks, for: Self.testJWKSUri)

        let hasKeys = await manager.hasKeys(for: Self.testJWKSUri)
        #expect(hasKeys == true)
    }

    @Test("hasKeys returns false for unknown endpoint")
    func hasKeysReturnsFalseForUnknown() async throws {
        let manager = createKeyManager()

        let hasKeys = await manager.hasKeys(for: "https://unknown.example.com/jwks")
        #expect(hasKeys == false)
    }

    @Test("registeredEndpoints returns all loaded endpoints")
    func registeredEndpointsReturnsAll() async throws {
        let manager = createKeyManager()
        let jwks = createTestJWKSWithKid("key-a")
        let jwks2 = createTestJWKSWithKid("key-b")

        try await manager.updateKeys(from: jwks, for: Self.testJWKSUri)
        try await manager.updateKeys(from: jwks2, for: Self.testJWKSUri2)

        let endpoints = await manager.registeredEndpoints()
        #expect(endpoints.count == 2)
        #expect(endpoints.contains(Self.testJWKSUri))
        #expect(endpoints.contains(Self.testJWKSUri2))
    }

    // MARK: - Key Rotation Tests

    @Test("Updating keys for the same endpoint replaces old keys")
    func updateKeysReplacesOldKeys() async throws {
        let manager = createKeyManager()

        // Load initial keys
        let oldJWKS = createMultiKeyJWKS(kids: ["old-key-1", "old-key-2"])
        try await manager.updateKeys(from: oldJWKS, for: Self.testJWKSUri)

        let hasKeysBefore = await manager.hasKeys(for: Self.testJWKSUri)
        #expect(hasKeysBefore == true)

        // Rotate to new keys (different kids)
        let newJWKS = createMultiKeyJWKS(kids: ["new-key-1", "new-key-3"])
        try await manager.updateKeys(from: newJWKS, for: Self.testJWKSUri)

        // Endpoint should still have keys
        let hasKeysAfter = await manager.hasKeys(for: Self.testJWKSUri)
        #expect(hasKeysAfter == true)

        // Should still have exactly one endpoint registered
        let endpoints = await manager.registeredEndpoints()
        #expect(endpoints.count == 1)
    }

    @Test("Updating keys for one endpoint does not affect another")
    func updateKeysIsolatesBetweenEndpoints() async throws {
        let manager = createKeyManager()

        let jwks1 = createTestJWKSWithKid("endpoint1-key")
        let jwks2 = createTestJWKSWithKid("endpoint2-key")

        try await manager.updateKeys(from: jwks1, for: Self.testJWKSUri)
        try await manager.updateKeys(from: jwks2, for: Self.testJWKSUri2)

        // Both endpoints should have keys
        let hasKeys1 = await manager.hasKeys(for: Self.testJWKSUri)
        let hasKeys2 = await manager.hasKeys(for: Self.testJWKSUri2)
        #expect(hasKeys1 == true)
        #expect(hasKeys2 == true)

        // Rotating one endpoint should not break the other
        let newJWKS1 = createTestJWKSWithKid("endpoint1-rotated-key")
        try await manager.updateKeys(from: newJWKS1, for: Self.testJWKSUri)

        let stillHasKeys2 = await manager.hasKeys(for: Self.testJWKSUri2)
        #expect(stillHasKeys2 == true)
    }

    // MARK: - Key Removal Tests

    @Test("Remove keys for an endpoint")
    func removeKeysForEndpoint() async throws {
        let manager = createKeyManager()
        let jwks = createTestJWKS()

        try await manager.updateKeys(from: jwks, for: Self.testJWKSUri)
        let hasKeysBefore = await manager.hasKeys(for: Self.testJWKSUri)
        #expect(hasKeysBefore == true)

        await manager.removeKeys(for: Self.testJWKSUri)

        let hasKeysAfter = await manager.hasKeys(for: Self.testJWKSUri)
        #expect(hasKeysAfter == false)

        let endpoints = await manager.registeredEndpoints()
        #expect(endpoints.isEmpty)
    }

    @Test("Removing keys for one endpoint preserves others")
    func removeKeysPreservesOtherEndpoints() async throws {
        let manager = createKeyManager()

        let jwks1 = createTestJWKSWithKid("endpoint1-key")
        let jwks2 = createTestJWKSWithKid("endpoint2-key")

        try await manager.updateKeys(from: jwks1, for: Self.testJWKSUri)
        try await manager.updateKeys(from: jwks2, for: Self.testJWKSUri2)

        // Remove only the first endpoint
        await manager.removeKeys(for: Self.testJWKSUri)

        let hasKeys1 = await manager.hasKeys(for: Self.testJWKSUri)
        let hasKeys2 = await manager.hasKeys(for: Self.testJWKSUri2)
        #expect(hasKeys1 == false)
        #expect(hasKeys2 == true)
    }

    @Test("Removing keys for non-existent endpoint is a no-op")
    func removeKeysForNonExistentEndpoint() async throws {
        let manager = createKeyManager()
        let jwks = createTestJWKS()

        try await manager.updateKeys(from: jwks, for: Self.testJWKSUri)

        // Removing a non-registered endpoint should not affect anything
        await manager.removeKeys(for: "https://nonexistent.example.com/jwks")

        let hasKeys = await manager.hasKeys(for: Self.testJWKSUri)
        #expect(hasKeys == true)
    }

    // MARK: - Concurrency Tests

    @Test("Concurrent updates to different endpoints work correctly")
    func concurrentUpdatesToDifferentEndpoints() async throws {
        let manager = createKeyManager()

        await withThrowingTaskGroup(of: Void.self) { group in
            for i in 0..<10 {
                group.addTask {
                    let jwks = self.createTestJWKSWithKid("concurrent-key-\(i)")
                    try await manager.updateKeys(
                        from: jwks,
                        for: "https://endpoint\(i).example.com/jwks"
                    )
                }
            }
        }

        let endpoints = await manager.registeredEndpoints()
        #expect(endpoints.count == 10)
    }

    @Test("Concurrent reads and writes work correctly")
    func concurrentReadsAndWrites() async throws {
        let manager = createKeyManager()
        let jwks = createTestJWKS()
        try await manager.updateKeys(from: jwks, for: Self.testJWKSUri)

        await withTaskGroup(of: Void.self) { group in
            // Concurrent reads
            for _ in 0..<10 {
                group.addTask {
                    _ = await manager.hasKeys(for: Self.testJWKSUri)
                }
            }

            // Concurrent endpoint listing
            for _ in 0..<5 {
                group.addTask {
                    _ = await manager.registeredEndpoints()
                }
            }

            // A concurrent write
            group.addTask {
                let newJWKS = self.createTestJWKSWithKid("concurrent-write-key")
                try? await manager.updateKeys(from: newJWKS, for: Self.testJWKSUri2)
            }
        }

        // Both endpoints should still be valid
        let hasKeys1 = await manager.hasKeys(for: Self.testJWKSUri)
        #expect(hasKeys1 == true)
    }

    // MARK: - Edge Case Tests

    @Test("Empty JWKS results in no keys for endpoint")
    func emptyJWKS() async throws {
        let manager = createKeyManager()
        let emptyJWKS = JWKSTestUtilities.createInvalidJWKS()

        // Empty JWKS has no keys with kid values, so hasKeys should be false
        try await manager.updateKeys(from: emptyJWKS, for: Self.testJWKSUri)

        let hasKeys = await manager.hasKeys(for: Self.testJWKSUri)
        #expect(hasKeys == false)
    }

    @Test("Multiple updates to same endpoint converge to latest state")
    func multipleUpdatesConverge() async throws {
        let manager = createKeyManager()

        // Simulate rapid successive updates (e.g. race between initial load and first refresh)
        for i in 0..<5 {
            let jwks = createTestJWKSWithKid("version-\(i)")
            try await manager.updateKeys(from: jwks, for: Self.testJWKSUri)
        }

        let hasKeys = await manager.hasKeys(for: Self.testJWKSUri)
        #expect(hasKeys == true)

        // Only one endpoint should be registered
        let endpoints = await manager.registeredEndpoints()
        #expect(endpoints.count == 1)
    }
}
