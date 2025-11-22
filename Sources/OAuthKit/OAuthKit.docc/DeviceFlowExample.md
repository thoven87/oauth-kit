# Device Flow CLI Example

A complete example of implementing OAuth2 Device Authorization Flow in a command-line application.

## Overview

The device authorization flow (RFC 8628) is perfect for CLI tools, desktop apps, and input-constrained devices. This example shows how to build a complete CLI application using OAuthKit's device flow support.

## Complete CLI Application

```swift
#!/usr/bin/env swift

import Foundation
import OAuthKit
import AsyncHTTPClient
import Logging

@main
struct OAuthCLI {
    static func main() async {
        // Configure logging
        LoggingSystem.bootstrap(StreamLogHandler.standardError)
        let logger = Logger(label: "oauth-cli")
        
        do {
            let cli = OAuthCLI()
            try await cli.run()
        } catch {
            print("❌ Error: \(error)")
            exit(1)
        }
    }
    
    func run() async throws {
        print("🔐 OAuth CLI Tool")
        print("================")
        
        // Create OAuth factory
        let oauthFactory = OAuthClientFactory()
        
        // Choose provider
        print("\nSelect OAuth provider:")
        print("1. Google")
        print("2. Microsoft")
        print("3. Auth0")
        print("Enter choice (1-3): ", terminator: "")
        
        guard let choice = readLine(),
              let providerNum = Int(choice),
              providerNum >= 1 && providerNum <= 3 else {
            throw CLIError.invalidInput("Invalid provider choice")
        }
        
        // Authenticate with selected provider
        let userInfo = try await authenticateWithProvider(providerNum, factory: oauthFactory)
        
        print("\n✅ Authentication successful!")
        print("👤 Welcome, \(userInfo.name)!")
        print("📧 Email: \(userInfo.email)")
        
        // Store tokens securely (in real app, use Keychain/secure storage)
        try saveTokens(userInfo.tokens)
        print("🔑 Tokens saved for future use")
    }
    
    private func authenticateWithProvider(_ providerNum: Int, factory: OAuthClientFactory) async throws -> UserInfo {
        switch providerNum {
        case 1:
            return try await authenticateWithGoogle(factory: factory)
        case 2:
            return try await authenticateWithMicrosoft(factory: factory)
        case 3:
            return try await authenticateWithAuth0(factory: factory)
        default:
            throw CLIError.invalidInput("Unsupported provider")
        }
    }
    
    private func authenticateWithGoogle(factory: OAuthClientFactory) async throws -> UserInfo {
        let provider = try await factory.googleProvider(
            clientID: getEnvVar("GOOGLE_CLIENT_ID"),
            clientSecret: getEnvVar("GOOGLE_CLIENT_SECRET"),
            redirectURI: "" // Not needed for device flow
        )
        
        print("\n🔍 Starting Google authentication...")
        
        // Request device authorization
        let deviceAuth = try await provider.requestDeviceAuthorization(
            scopes: ["openid", "profile", "email"]
        )
        
        print("\n📱 Please complete authentication:")
        print("   1. Visit: \(deviceAuth.verificationUri)")
        print("   2. Enter code: \(deviceAuth.userCode)")
        print("   3. Expires in: \(deviceAuth.expiresIn) seconds")
        
        if let completeUri = deviceAuth.verificationUriComplete {
            print("   Or visit: \(completeUri)")
        }
        
        print("\n⏳ Waiting for authorization...")
        
        // Poll for completion
        let (tokens, claims) = try await provider.pollForDeviceAuthorization(
            deviceCode: deviceAuth.deviceCode,
            interval: deviceAuth.interval ?? 5,
            timeout: TimeInterval(deviceAuth.expiresIn)
        )
        
        return UserInfo(
            name: claims.name ?? "Unknown",
            email: claims.email ?? "Unknown",
            tokens: tokens
        )
    }
    
    private func authenticateWithMicrosoft(factory: OAuthClientFactory) async throws -> UserInfo {
        let provider = try await factory.microsoftProvider(
            clientID: getEnvVar("MICROSOFT_CLIENT_ID"),
            clientSecret: getEnvVar("MICROSOFT_CLIENT_SECRET"),
            redirectURI: "", // Not needed for device flow
            tenantID: .common
        )
        
        print("\n🔍 Starting Microsoft authentication...")
        
        let deviceAuth = try await provider.requestDeviceAuthorization(
            scopes: ["openid", "profile", "email", "User.Read"]
        )
        
        print("\n📱 Please complete authentication:")
        print("   1. Visit: \(deviceAuth.verificationUri)")
        print("   2. Enter code: \(deviceAuth.userCode)")
        print("   3. Expires in: \(deviceAuth.expiresIn) seconds")
        
        print("\n⏳ Waiting for authorization...")
        
        let (tokens, claims) = try await provider.pollForDeviceAuthorization(
            deviceCode: deviceAuth.deviceCode,
            interval: deviceAuth.interval ?? 5,
            timeout: TimeInterval(deviceAuth.expiresIn)
        )
        
        return UserInfo(
            name: claims.name ?? "Unknown",
            email: claims.email ?? "Unknown",
            tokens: tokens
        )
    }
    
    private func authenticateWithAuth0(factory: OAuthClientFactory) async throws -> UserInfo {
        let provider = try await factory.auth0Provider(
            clientID: getEnvVar("AUTH0_CLIENT_ID"),
            clientSecret: getEnvVar("AUTH0_CLIENT_SECRET"),
            domain: getEnvVar("AUTH0_DOMAIN"),
            redirectURI: "" // Not needed for device flow
        )
        
        print("\n🔍 Starting Auth0 authentication...")
        
        let deviceAuth = try await provider.requestDeviceAuthorization(
            scopes: ["openid", "profile", "email"]
        )
        
        print("\n📱 Please complete authentication:")
        print("   1. Visit: \(deviceAuth.verificationUri)")
        print("   2. Enter code: \(deviceAuth.userCode)")
        print("   3. Expires in: \(deviceAuth.expiresIn) seconds")
        
        print("\n⏳ Waiting for authorization...")
        
        let (tokens, claims) = try await provider.pollForDeviceAuthorization(
            deviceCode: deviceAuth.deviceCode,
            interval: deviceAuth.interval ?? 5,
            timeout: TimeInterval(deviceAuth.expiresIn)
        )
        
        return UserInfo(
            name: claims.name ?? "Unknown",
            email: claims.email ?? "Unknown",
            tokens: tokens
        )
    }
    
    private func getEnvVar(_ name: String) -> String {
        guard let value = ProcessInfo.processInfo.environment[name], !value.isEmpty else {
            fatalError("❌ Missing required environment variable: \(name)")
        }
        return value
    }
    
    private func saveTokens(_ tokens: TokenResponse) throws {
        let tokensData = TokenStorage(
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresAt: Date().addingTimeInterval(Double(tokens.expiresIn ?? 3600))
        )
        
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        
        let data = try encoder.encode(tokensData)
        let tokenFile = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".oauth-cli-tokens.json")
        
        try data.write(to: tokenFile)
    }
}

struct UserInfo {
    let name: String
    let email: String
    let tokens: TokenResponse
}

struct TokenStorage: Codable {
    let accessToken: String
    let refreshToken: String?
    let expiresAt: Date
}

enum CLIError: Error, CustomStringConvertible {
    case invalidInput(String)
    case missingConfiguration(String)
    
    var description: String {
        switch self {
        case .invalidInput(let message):
            return "Invalid input: \(message)"
        case .missingConfiguration(let message):
            return "Configuration error: \(message)"
        }
    }
}
```

## Environment Setup

Create a `.env` file or export environment variables:

```bash
# Google OAuth2 (https://console.developers.google.com/)
export GOOGLE_CLIENT_ID="your-google-client-id"
export GOOGLE_CLIENT_SECRET="your-google-client-secret"

# Microsoft OAuth2 (https://portal.azure.com/)
export MICROSOFT_CLIENT_ID="your-microsoft-client-id"  
export MICROSOFT_CLIENT_SECRET="your-microsoft-client-secret"

# Auth0 OAuth2 (https://manage.auth0.com/)
export AUTH0_CLIENT_ID="your-auth0-client-id"
export AUTH0_CLIENT_SECRET="your-auth0-client-secret"
export AUTH0_DOMAIN="your-tenant.auth0.com"
```

## Package.swift Configuration

```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "oauth-cli",
    platforms: [.macOS(.v13)],
    dependencies: [
        .package(url: "https://github.com/thoven87/oauth-kit.git", from: "1.0.0"),
        .package(url: "https://github.com/swift-server/async-http-client.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0")
    ],
    targets: [
        .executableTarget(
            name: "oauth-cli",
            dependencies: [
                .product(name: "OAuthKit", package: "oauth-kit"),
                .product(name: "AsyncHTTPClient", package: "async-http-client"),
                .product(name: "Logging", package: "swift-log")
            ]
        )
    ]
)
```

## Usage

1. **Setup credentials**: Configure OAuth applications in provider consoles
2. **Export environment variables**: Set client IDs, secrets, and domains
3. **Run the CLI**:
   ```bash
   swift run oauth-cli
   ```
4. **Follow prompts**: Select provider and complete device authentication
5. **Tokens saved**: Access and refresh tokens stored for future use

## Advanced Features

### Token Refresh

```swift
func refreshTokensIfNeeded() async throws {
    let tokenFile = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent(".oauth-cli-tokens.json")
    
    guard FileManager.default.fileExists(atPath: tokenFile.path) else {
        throw CLIError.missingConfiguration("No saved tokens found")
    }
    
    let data = try Data(contentsOf: tokenFile)
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    
    let savedTokens = try decoder.decode(TokenStorage.self, from: data)
    
    // Check if token needs refresh (5 minutes before expiry)
    if savedTokens.expiresAt.timeIntervalSinceNow < 300 {
        guard let refreshToken = savedTokens.refreshToken else {
            throw CLIError.missingConfiguration("No refresh token available")
        }
        
        print("🔄 Refreshing access token...")
        
        // Refresh with appropriate provider
        let provider = try await recreateProvider()
        let (newTokens, _) = try await provider.refreshAccessToken(refreshToken: refreshToken)
        
        // Save new tokens
        try saveTokens(newTokens)
        print("✅ Tokens refreshed successfully")
    }
}
```

### API Calls with Stored Tokens

```swift
func makeAuthenticatedAPICall() async throws {
    let tokens = try loadStoredTokens()
    
    var request = HTTPClientRequest(url: "https://api.example.com/user")
    request.headers.add(name: "Authorization", value: "Bearer \(tokens.accessToken)")
    
    let httpClient = HTTPClient(eventLoopGroupProvider: .singleton)
    defer {
        try? httpClient.syncShutdown()
    }
    
    let response = try await httpClient.execute(request, timeout: .seconds(30))
    let data = try await response.body.collect(upTo: 1024 * 1024)
    
    print("API Response: \(String(buffer: data))")
}
```

### Error Handling

```swift
func handleDeviceFlowErrors() async {
    do {
        let (tokens, claims) = try await provider.pollForDeviceAuthorization(deviceCode: deviceCode)
        // Success
    } catch DeviceFlowError.authorizationPending {
        print("⏳ Still waiting for user authorization...")
    } catch DeviceFlowError.slowDown {
        print("⚠️  Polling too fast, slowing down...")
    } catch DeviceFlowError.expiredToken {
        print("⏰ Device code expired, please try again")
    } catch DeviceFlowError.accessDenied {
        print("❌ User denied authorization")
    } catch {
        print("💥 Unexpected error: \(error)")
    }
}
```

## Device Flow Benefits for CLI Tools

1. **No Browser Redirect**: Perfect for headless environments
2. **Cross-Device**: User can authenticate on phone while CLI runs on server
3. **User-Friendly**: Simple code entry vs complex redirect URLs
4. **Secure**: No need to handle redirect URIs or local servers
5. **Scriptable**: Can be automated with proper error handling

This example demonstrates a production-ready CLI tool using OAuthKit's device authorization flow with proper error handling, token storage, and refresh logic.