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

import Foundation
import JWTKit
import Logging
import ServiceLifecycle

/// Test utilities for creating mock JWKS data
public struct JWKSTestUtilities {
    /// Create a test JWKS with a proper RSA key for testing
    public static func createTestJWKS() -> JWKS {
        // Use the actual RSA public key from JWTKit's tests - proven to work
        let jwksJSON = """
            {
                "keys": [
                    {
                        "kty": "RSA",
                        "kid": "test-key-1",
                        "alg": "RS256",
                        "use": "sig",
                        "n": "vTHHoCaR0tlYfvapRv94hUTMrdSymIrWIIZ5Kmv5bIYWtK0TMX0icLkB0PzR2IDLj1L7hzBKUljBGzjf6ujfZwru5-odDZ344A6AhH5B5Zie1ALUTnizD-8XtWcdOtv4aF5NwgRJns0YY-HVr_KKfPZurfMf7JI2wSCt0TRRUixkfJgypnLNZNMowcMiGD9GYdCb2mC43V8DKNpUIIIUJK_auxqAxdEnY6GwI4zYnQdCv8ULai_LcB2CQhj5gm9PeKI6K1qkKs5_F1N2-2y9srrSk7pYPU0xxrj5Ap5GsTaJJJhV9QV1bgDiJaakWhh2m9jSs6SsufHCPT5RiCVh5Q",
                        "e": "AQAB"
                    }
                ]
            }
            """

        do {
            return try JSONDecoder().decode(JWKS.self, from: Data(jwksJSON.utf8))
        } catch {
            // Fallback to empty JWKS if decoding fails
            return JWKS(keys: [])
        }
    }

    /// Create an invalid JWKS for error testing - uses empty keys array
    public static func createInvalidJWKS() -> JWKS {
        JWKS(keys: [])
    }
}

/// Run a `Service` inside a `ServiceGroup` for the duration of a test closure.
///
/// Mirrors the `testJobQueue` helper from swift-jobs: the service is started in
/// a background task, the test body runs, then graceful shutdown is triggered.
/// This guarantees the service never hangs indefinitely regardless of whether
/// the test body succeeds or throws.
///
/// ```swift
/// try await withService(factory) {
///     let count = await factory.jwksRefreshService.forceRefreshAll()
///     #expect(count >= 1)
/// }
/// ```
func withService<S: Service, Value>(
    _ service: S,
    _ test: () async throws -> Value
) async throws -> Value {
    try await withThrowingTaskGroup(of: Void.self) { group in
        let serviceGroup = ServiceGroup(
            configuration: .init(
                services: [service],
                gracefulShutdownSignals: [],
                logger: Logger(label: "test.ServiceGroup")
            )
        )
        group.addTask {
            try await serviceGroup.run()
        }
        let value = try await test()
        await serviceGroup.triggerGracefulShutdown()
        return value
    }
}
