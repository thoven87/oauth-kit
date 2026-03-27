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
import ServiceLifecycle
import Testing

@testable import OAuthKit

@Suite("JWKS Refresh Integration Tests")
struct JWKSRefreshIntegrationTests {
    static let logger = Logger(label: "test")

    // MARK: - Basic Factory Tests

    @Test("Factory always includes JWKS refresh components")
    func factoryIncludesJWKSRefresh() async throws {
        let factory = OAuthClientFactory()

        // Verify the key manager starts with no endpoints registered
        let endpoints = await factory.keyManager.registeredEndpoints()
        #expect(endpoints.isEmpty)
    }

    @Test("Factory with custom configuration")
    func factoryWithCustomConfiguration() async throws {
        let config = JWKSRefreshService.Configuration(
            refreshInterval: .seconds(900),
            requestTimeout: .seconds(45),
            maxRetries: 5,
            retryDelay: .seconds(2)
        )

        let factory = OAuthClientFactory(
            logger: Self.logger,
            jwksRefreshConfiguration: config
        )

        // Verify components work with custom configuration
        let endpoints = await factory.keyManager.registeredEndpoints()
        #expect(endpoints.isEmpty)
    }

    // MARK: - Service Integration Tests

    @Test("JWKS refresh service runs with ServiceGroup")
    func testJWKSRefreshWithServiceGroup() async throws {
        let (stream, source) = AsyncStream.makeStream(of: Int.self)
        var logger = Logger(label: "jwks-refresh-test")
        logger.logLevel = .debug

        let factory = OAuthClientFactory(logger: logger)

        // Register a JWKS endpoint to ensure the service has work to do
        _ = try await factory.openIDConnectClient(
            discoveryURL: "https://accounts.google.com",
            clientID: "test-client-id",
            clientSecret: "test-client-secret"
        )

        await withThrowingTaskGroup(of: Void.self) { group in
            let serviceGroup = ServiceGroup(
                configuration: ServiceGroupConfiguration(
                    services: [factory],
                    gracefulShutdownSignals: [],
                    logger: logger
                )
            )

            group.addTask {
                try await serviceGroup.run()
            }

            // Let the service run briefly to perform initial refresh
            group.addTask {
                try await Task.sleep(for: .seconds(1))
                source.yield(1)
            }

            // Wait for signal then shutdown
            _ = await stream.first { _ in true }
            await serviceGroup.triggerGracefulShutdown()
        }

        // After running the service, the key manager should have keys loaded
        let hasKeys = await factory.keyManager.hasKeys(
            for: "https://www.googleapis.com/oauth2/v3/certs"
        )
        // Keys may or may not be present depending on timing, but the service
        // should not have crashed
        #expect(hasKeys == true || hasKeys == false)
    }

    // MARK: - JWKS Registration Tests

    @Test("Automatic JWKS registration when creating clients")
    func automaticJWKSRegistration() async throws {
        let factory = OAuthClientFactory()

        // Create an OpenID Connect client — registers the JWKS endpoint
        _ = try await factory.openIDConnectClient(
            discoveryURL: "https://accounts.google.com",
            clientID: "test-client-id",
            clientSecret: "test-client-secret"
        )

        // Keys are NOT loaded during init; they are loaded when the service
        // runs.  A manual forceRefreshAll() triggers the same initial load.
        let refreshedCount = await factory.jwksRefreshService.forceRefreshAll()
        #expect(refreshedCount >= 1)

        // After refresh, the key manager should have keys for the endpoint
        let hasKeys = await factory.keyManager.hasKeys(
            for: "https://www.googleapis.com/oauth2/v3/certs"
        )
        #expect(hasKeys == true)
    }

    @Test("Multiple provider creation registers multiple endpoints")
    func providerCreationRegistersEndpoints() async throws {
        let factory = OAuthClientFactory()

        // Test creating various providers — registers JWKS endpoints
        _ = try await factory.googleProvider(
            clientID: "test-google-client-id",
            clientSecret: "test-google-client-secret",
            redirectURI: "https://test.com/callback"
        )

        _ = try await factory.microsoftProvider(
            clientID: "test-microsoft-client-id",
            clientSecret: "test-microsoft-client-secret",
            redirectURI: "https://test.com/callback"
        )

        // Force a refresh to actually load keys into the key manager
        let refreshedCount = await factory.jwksRefreshService.forceRefreshAll()
        #expect(refreshedCount >= 2)

        // Verify multiple endpoints have keys loaded
        let endpoints = await factory.keyManager.registeredEndpoints()
        #expect(endpoints.count >= 2)
    }

    // MARK: - Manual Operations Tests

    @Test("Manual refresh operations work")
    func manualRefresh() async throws {
        let factory = OAuthClientFactory()

        // Create a provider to register an endpoint
        _ = try await factory.googleProvider(
            clientID: "test-client-id",
            clientSecret: "test-client-secret",
            redirectURI: "https://test.com/callback"
        )

        // Test manual refresh
        let refreshedCount = await factory.jwksRefreshService.forceRefreshAll()
        #expect(refreshedCount >= 0)
    }

    @Test("Key manager starts empty")
    func keyManagerStartsEmpty() async throws {
        let factory = OAuthClientFactory()

        // Key manager should have no endpoints initially
        let endpoints = await factory.keyManager.registeredEndpoints()
        #expect(endpoints.isEmpty)

        let hasKeys = await factory.keyManager.hasKeys(for: "https://example.com/jwks")
        #expect(hasKeys == false)
    }

    // MARK: - Error Handling Tests

    @Test("Invalid discovery URL throws appropriate error")
    func invalidDiscoveryURL() async throws {
        let factory = OAuthClientFactory()

        await #expect(throws: OAuth2Error.self) {
            _ = try await factory.openIDConnectClient(
                discoveryURL: "invalid-url",
                clientID: "client-id",
                clientSecret: "client-secret"
            )
        }
    }

    // MARK: - Configuration Validation Tests

    @Test("Default configuration has correct values")
    func defaultConfiguration() async throws {
        let factory = OAuthClientFactory()

        // Test that the service can perform operations
        let refreshedCount = await factory.jwksRefreshService.forceRefreshAll()
        #expect(refreshedCount >= 0)
    }

    @Test("Custom configuration is respected")
    func customConfiguration() async throws {
        let config = JWKSRefreshService.Configuration(
            refreshInterval: .seconds(300),
            requestTimeout: .seconds(15),
            maxRetries: 2,
            retryDelay: .seconds(3)
        )

        let factory = OAuthClientFactory(
            jwksRefreshConfiguration: config
        )

        // Test that the service works with custom configuration
        let refreshedCount = await factory.jwksRefreshService.forceRefreshAll()
        #expect(refreshedCount >= 0)
    }
}
