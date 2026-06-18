# OAuthKit

A Swift OAuth2 and OpenID Connect client library with modern async/await support, built on top of JWT-Kit, compatible with Linux and macOS.

[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fthoven87%2Foauth-kit%2Fbadge%3Ftype%3Dswift-versions)](https://swiftpackageindex.com/thoven87/oauth-kit)
[![](https://img.shields.io/endpoint?url=https%3A%2F%2Fswiftpackageindex.com%2Fapi%2Fpackages%2Fthoven87%2Foauth-kit%2Fbadge%3Ftype%3Dplatforms)](https://swiftpackageindex.com/thoven87/oauth-kit)

## Features

- OAuth 2.0 Authorization Code Flow with PKCE
- OAuth 2.0 Client Credentials Flow
- OAuth 2.0 Device Authorization Flow (RFC 8628)
- OAuth 2.0 Token Exchange (RFC 8693), Introspection (RFC 7662), and Revocation (RFC 7009)
- OpenID Connect with JWT validation and auto-discovery
- Automatic JWKS refresh with per-endpoint key isolation and `Cache-Control`-driven scheduling
- Multi-Factor Authentication support (Okta push, SMS, TOTP)
- 15+ built-in providers: Google, Microsoft, Auth0, Discord, GitHub, Apple, Okta, AWS Cognito, and more
- Google Service Account authentication and domain-wide delegation
- Framework-agnostic — works with Vapor, Hummingbird, raw SwiftNIO, or any Swift server
- Swift 6 strict concurrency

## Requirements

- Swift 6.0+
- macOS 13+ / Linux

## Installation

Add OAuthKit to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/thoven87/oauth-kit.git", from: "1.0.0")
]
```

Then add it to your target:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "OAuthKit", package: "oauth-kit")
    ]
)
```

## Quick Start

```swift
import OAuthKit
import ServiceLifecycle

// OAuthClientFactory manages the HTTP client, JWKS refresh service, and all providers.
let oauthKit = OAuthClientFactory()

// Creating a provider automatically registers its JWKS endpoint for background refresh.
let googleProvider = try await oauthKit.googleProvider(
    clientID: "your-google-client-id",
    clientSecret: "your-google-client-secret",
    redirectURI: "https://your-app.com/auth/google/callback"
)

// Generate a PKCE authorization URL.
let (authURL, codeVerifier) = try googleProvider.generateAuthURL(
    state: UUID().uuidString,
    scopes: ["openid", "profile", "email"]
)

// After the user is redirected back, exchange the code for tokens.
let (tokenResponse, claims) = try await googleProvider.exchangeCode(
    code: authorizationCode,
    codeVerifier: codeVerifier
)

// Run the JWKS refresh service (typically inside a ServiceGroup).
try await oauthKit.run()
```

## Documentation

Full documentation is available on the [Swift Package Index](https://swiftpackageindex.com/thoven87/oauth-kit/documentation/oauthkit), including:

- [OpenID Connect guide](Sources/OAuthKit/OAuthKit.docc/OpenIDConnect.md)
- [JWKS Refresh Service](Sources/OAuthKit/OAuthKit.docc/JWKSRefresh.md)
- [Device Authorization Flow](Sources/OAuthKit/OAuthKit.docc/DeviceFlowExample.md)
- [Token Refresh](Sources/OAuthKit/OAuthKit.docc/RefreshTokenSupport.md)
- [Okta MFA](Sources/OAuthKit/OAuthKit.docc/OktaMFA.md)
- [Vapor integration](Sources/OAuthKit/OAuthKit.docc/VaporIntegration.md)
- [Hummingbird integration](Sources/OAuthKit/OAuthKit.docc/HummingbirdIntegration.md)
- [SwiftNIO integration](Sources/OAuthKit/OAuthKit.docc/NIOIntegration.md)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This library is released under the Apache 2.0 license.
