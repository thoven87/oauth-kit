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

/// Response from device authorization endpoint (RFC 8628)
public struct DeviceAuthorizationResponse: Codable, Sendable {
    /// The device verification code
    public let deviceCode: String

    /// The end-user verification code
    public let userCode: String

    /// The end-user verification URI on the authorization server
    public let verificationUri: String

    /// A human-readable identifier or description of the device
    public let verificationUriComplete: String?

    /// The lifetime in seconds of the device_code and user_code
    public let expiresIn: Int

    /// The minimum amount of time in seconds that the client should wait between polling requests to the token endpoint
    public let interval: Int?

    /// Initialize a device authorization response
    /// - Parameters:
    ///   - deviceCode: The device verification code
    ///   - userCode: The end-user verification code
    ///   - verificationUri: The end-user verification URI
    ///   - verificationUriComplete: Optional complete verification URI with code embedded
    ///   - expiresIn: The lifetime in seconds of the codes
    ///   - interval: The minimum polling interval in seconds
    public init(
        deviceCode: String,
        userCode: String,
        verificationUri: String,
        verificationUriComplete: String? = nil,
        expiresIn: Int,
        interval: Int? = nil
    ) {
        self.deviceCode = deviceCode
        self.userCode = userCode
        self.verificationUri = verificationUri
        self.verificationUriComplete = verificationUriComplete
        self.expiresIn = expiresIn
        self.interval = interval
    }

    enum CodingKeys: String, CodingKey {
        case deviceCode = "device_code"
        case userCode = "user_code"
        case verificationUri = "verification_uri"
        case verificationUriComplete = "verification_uri_complete"
        case expiresIn = "expires_in"
        case interval
    }
}

/// Device flow specific errors (RFC 8628 Section 3.5)
public enum DeviceFlowError: Error, CustomStringConvertible {
    /// The authorization request is still pending
    case authorizationPending

    /// The client is polling too frequently and should slow down
    case slowDown

    /// The device authorization has expired
    case expiredToken

    /// The end user denied the authorization request
    case accessDenied

    /// Unknown or other device flow error
    case unknown(String)

    public var description: String {
        switch self {
        case .authorizationPending:
            return "Authorization pending - user hasn't completed authorization yet"
        case .slowDown:
            return "Slow down - polling too frequently"
        case .expiredToken:
            return "Device authorization has expired"
        case .accessDenied:
            return "User denied the authorization request"
        case .unknown(let error):
            return "Unknown device flow error: \(error)"
        }
    }

    /// Create device flow error from OAuth2 error string
    /// - Parameter errorCode: The OAuth2 error code from token response
    /// - Returns: Corresponding DeviceFlowError
    internal static func from(errorCode: String) -> DeviceFlowError {
        switch errorCode {
        case "authorization_pending":
            return .authorizationPending
        case "slow_down":
            return .slowDown
        case "expired_token":
            return .expiredToken
        case "access_denied":
            return .accessDenied
        default:
            return .unknown(errorCode)
        }
    }
}
