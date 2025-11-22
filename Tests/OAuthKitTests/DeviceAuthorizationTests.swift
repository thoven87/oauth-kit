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
import Testing

@testable import OAuthKit

/// Tests for Device Authorization Response (RFC 8628)
struct DeviceAuthorizationTests {

    @Test("Device Authorization Response Creation")
    func testDeviceAuthorizationResponseCreation() throws {
        let response = DeviceAuthorizationResponse(
            deviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
            userCode: "WDJB-MJHT",
            verificationUri: "https://example.com/device",
            verificationUriComplete: "https://example.com/device?user_code=WDJB-MJHT",
            expiresIn: 1800,
            interval: 5
        )

        #expect(response.deviceCode == "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS")
        #expect(response.userCode == "WDJB-MJHT")
        #expect(response.verificationUri == "https://example.com/device")
        #expect(response.verificationUriComplete == "https://example.com/device?user_code=WDJB-MJHT")
        #expect(response.expiresIn == 1800)
        #expect(response.interval == 5)
    }

    @Test("Device Authorization Response JSON Decoding")
    func testDeviceAuthorizationResponseDecoding() throws {
        let jsonData = """
            {
                "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
                "user_code": "WDJB-MJHT",
                "verification_uri": "https://example.com/device",
                "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
                "expires_in": 1800,
                "interval": 5
            }
            """.data(using: .utf8)!

        let response = try JSONDecoder().decode(DeviceAuthorizationResponse.self, from: jsonData)

        #expect(response.deviceCode == "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS")
        #expect(response.userCode == "WDJB-MJHT")
        #expect(response.verificationUri == "https://example.com/device")
        #expect(response.verificationUriComplete == "https://example.com/device?user_code=WDJB-MJHT")
        #expect(response.expiresIn == 1800)
        #expect(response.interval == 5)
    }

    @Test("Device Authorization Response JSON Decoding Without Optional Fields")
    func testDeviceAuthorizationResponseDecodingMinimal() throws {
        let jsonData = """
            {
                "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
                "user_code": "WDJB-MJHT",
                "verification_uri": "https://example.com/device",
                "expires_in": 1800
            }
            """.data(using: .utf8)!

        let response = try JSONDecoder().decode(DeviceAuthorizationResponse.self, from: jsonData)

        #expect(response.deviceCode == "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS")
        #expect(response.userCode == "WDJB-MJHT")
        #expect(response.verificationUri == "https://example.com/device")
        #expect(response.verificationUriComplete == nil)
        #expect(response.expiresIn == 1800)
        #expect(response.interval == nil)
    }

    @Test("Device Authorization Response Expiration Date Calculation")
    func testExpirationDateCalculation() throws {
        let beforeCreation = Date()

        let response = DeviceAuthorizationResponse(
            deviceCode: "test-device-code",
            userCode: "TEST-CODE",
            verificationUri: "https://example.com/device",
            expiresIn: 300  // 5 minutes
        )

        let afterCreation = Date()

        // Expiration date should be approximately 5 minutes from now
        // Allow for some buffer time due to test execution
        let expectedEarliestExpiration = beforeCreation.addingTimeInterval(299.5)
        let expectedLatestExpiration = afterCreation.addingTimeInterval(300.5)

        #expect(response.expirationDate >= expectedEarliestExpiration)
        #expect(response.expirationDate <= expectedLatestExpiration)
    }

    @Test("Device Authorization Response Expiration Check - Not Expired")
    func testIsNotExpired() throws {
        let response = DeviceAuthorizationResponse(
            deviceCode: "test-device-code",
            userCode: "TEST-CODE",
            verificationUri: "https://example.com/device",
            expiresIn: 300  // 5 minutes
        )

        #expect(!response.isExpired)
    }

    @Test("Device Authorization Response Expiration Check - Expired")
    func testIsExpired() async throws {
        // Create a response that expires in 1 millisecond
        let response = DeviceAuthorizationResponse(
            deviceCode: "test-device-code",
            userCode: "TEST-CODE",
            verificationUri: "https://example.com/device",
            expiresIn: -1  // Already expired (negative value)
        )

        // Should be immediately expired
        #expect(response.isExpired)
    }

    @Test("Device Authorization Response Time Remaining")
    func testTimeRemaining() throws {
        let response = DeviceAuthorizationResponse(
            deviceCode: "test-device-code",
            userCode: "TEST-CODE",
            verificationUri: "https://example.com/device",
            expiresIn: 300  // 5 minutes
        )

        let timeRemaining = response.timeRemaining

        // Should be approximately 300 seconds (5 minutes)
        #expect(timeRemaining > 295)  // Allow for some execution time
        #expect(timeRemaining <= 300)
    }

    @Test("Device Authorization Response Time Remaining - Expired")
    func testTimeRemainingExpired() async throws {
        let response = DeviceAuthorizationResponse(
            deviceCode: "test-device-code",
            userCode: "TEST-CODE",
            verificationUri: "https://example.com/device",
            expiresIn: -1  // Already expired (negative value)
        )

        // Should return 0 for expired token
        #expect(response.timeRemaining == 0)
    }

    @Test("Device Authorization Response Polling Interval - With Value")
    func testPollingIntervalWithValue() throws {
        let response = DeviceAuthorizationResponse(
            deviceCode: "test-device-code",
            userCode: "TEST-CODE",
            verificationUri: "https://example.com/device",
            expiresIn: 1800,
            interval: 10
        )

        #expect(response.pollingInterval == 10.0)
    }

    @Test("Device Authorization Response Polling Interval - Default Fallback")
    func testPollingIntervalDefaultFallback() throws {
        let response = DeviceAuthorizationResponse(
            deviceCode: "test-device-code",
            userCode: "TEST-CODE",
            verificationUri: "https://example.com/device",
            expiresIn: 1800
                // No interval provided
        )

        // Should fallback to recommended 5 seconds
        #expect(response.pollingInterval == 5.0)
    }

    @Test("Device Flow Error Creation from Error Codes")
    func testDeviceFlowErrorFromErrorCode() throws {
        #expect(DeviceFlowError.from(errorCode: "authorization_pending") == .authorizationPending)
        #expect(DeviceFlowError.from(errorCode: "slow_down") == .slowDown)
        #expect(DeviceFlowError.from(errorCode: "expired_token") == .expiredToken)
        #expect(DeviceFlowError.from(errorCode: "access_denied") == .accessDenied)

        // Test unknown error handling
        let unknownError = DeviceFlowError.from(errorCode: "some_unknown_error")
        if case .unknown(let errorCode) = unknownError {
            #expect(errorCode == "some_unknown_error")
        } else {
            Issue.record("Expected unknown error case")
        }
    }

    @Test("Device Flow Error Descriptions")
    func testDeviceFlowErrorDescriptions() throws {
        #expect(DeviceFlowError.authorizationPending.description == "Authorization pending - user hasn't completed authorization yet")
        #expect(DeviceFlowError.slowDown.description == "Slow down - polling too frequently")
        #expect(DeviceFlowError.expiredToken.description == "Device authorization has expired")
        #expect(DeviceFlowError.accessDenied.description == "User denied the authorization request")
        #expect(DeviceFlowError.unknown("test_error").description == "Unknown device flow error: test_error")
    }

    @Test("Device Authorization Response JSON Encoding")
    func testDeviceAuthorizationResponseEncoding() throws {
        let response = DeviceAuthorizationResponse(
            deviceCode: "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
            userCode: "WDJB-MJHT",
            verificationUri: "https://example.com/device",
            verificationUriComplete: "https://example.com/device?user_code=WDJB-MJHT",
            expiresIn: 1800,
            interval: 5
        )

        let jsonData = try JSONEncoder().encode(response)
        let decodedResponse = try JSONDecoder().decode(DeviceAuthorizationResponse.self, from: jsonData)

        #expect(decodedResponse.deviceCode == response.deviceCode)
        #expect(decodedResponse.userCode == response.userCode)
        #expect(decodedResponse.verificationUri == response.verificationUri)
        #expect(decodedResponse.verificationUriComplete == response.verificationUriComplete)
        #expect(decodedResponse.expiresIn == response.expiresIn)
        #expect(decodedResponse.interval == response.interval)
    }
}
