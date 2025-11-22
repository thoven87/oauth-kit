# ``OAuthKit``

A comprehensive Swift OAuth2 and OpenID Connect client library with modern async/await support.

## Overview

OAuthKit is a powerful, type-safe OAuth2 and OpenID Connect client library built for modern Swift applications. It provides seamless integration with popular OAuth providers while maintaining full compatibility with any Swift server framework.

### Recent Improvements

**✅ API Consistency Fixed**: All OAuth providers now have a consistent `refreshAccessToken(refreshToken:)` method directly on the provider, eliminating the previous inconsistency where only Google had this convenience method while others required accessing `provider.client.refreshToken()`.

**✅ Device Authorization Flow**: Full support for RFC 8628 Device Authorization Flow has been implemented, enabling authentication for input-constrained devices like smart TVs, IoT devices, CLI tools, and gaming consoles.

**✅ Okta MFA Support**: Complete multi-factor authentication support for Okta, including push notifications with number challenges, SMS codes, TOTP tokens, and polling mechanisms for enterprise authentication workflows.

### Key Features

- **OAuth 2.0 Authorization Code Flow** with PKCE support
- **OAuth 2.0 Client Credentials Flow** for server-to-server authentication
- **OAuth 2.0 Device Authorization Flow** for input-constrained devices (RFC 8628)
- **OpenID Connect** support with JWT validation and auto-discovery
- **Multi-Factor Authentication (MFA)** with Okta push notifications and challenge flows
- **15+ Built-in Providers** including Google, Microsoft, Discord, GitHub, and more
- **Service Account Support** for Google Workspace and other enterprise APIs
- **Framework Agnostic** - works with Vapor, Hummingbird, and any Swift server
- **Modern async/await** API built for Swift concurrency
- **Type Safety** with comprehensive error handling and validation
- **Cross-platform** support for macOS and Linux

### Supported Providers

OAuthKit includes built-in support for these popular OAuth providers:

| Provider | Type | Features |
|----------|------|----------|
| **Google** | OIDC | Sign-In + Service Account + Workspace APIs |
| **Microsoft** | OIDC | Multi-tenant support + Graph API |
| **Auth0** | OIDC | Enterprise identity + Management API |
| **Discord** | OAuth2 | Gaming platform + Bot permissions |
| **LinkedIn** | OAuth2 | Professional networking + Profile API |
| **GitLab** | OAuth2 | Self-hosted support + Projects API |
| **Dropbox** | OAuth2 | File storage + Content API |
| **Apple** | OAuth2 | Sign in with Apple + JWT verification |
| **GitHub** | OAuth2 | Developer platform + Repository access |
| **Facebook** | OAuth2 | Social platform + Graph API |
| **Slack** | OAuth2 | Workspace integration + API access |
| **AWS Cognito** | OIDC | Serverless authentication |
| **Okta** | OIDC | Enterprise identity management |
| **KeyCloak** | OAuth2 | Self-hosted identity server |

## Getting Started

### Installation

Add OAuthKit to your Swift package dependencies:

```swift
dependencies: [
    .package(url: "https://github.com/thoven87/oauth-kit.git", from: "1.0.0")
]
```

### Quick Start

```swift
import OAuthKit

// Initialize OAuthKit
let oauthKit = OAuthClientFactory()

// Create a Google OAuth provider
let googleProvider = try await oauthKit.googleProvider(
    clientID: "your-google-client-id",
    clientSecret: "your-google-client-secret",
    redirectURI: "https://your-app.com/callback"
)

// Generate authorization URL
let (authURL, codeVerifier) = try googleProvider.generateAuthURL(
    state: UUID().uuidString,
    scopes: ["openid", "profile", "email"]
)

// Exchange authorization code for tokens
let (tokenResponse, claims) = try await googleProvider.exchangeCode(
    code: authCode,
    codeVerifier: codeVerifier
)
```

## Topics

### Core Components

- ``OAuthClientFactory``
- ``OAuth2Client``
- ``OpenIDConnectClient``
- ``TokenResponse``
- ``OAuth2Error``

### OAuth2 Providers

- ``GoogleOAuthProvider``
- ``MicrosoftOAuthProvider``
- ``Auth0OAuthProvider``
- ``DiscordOAuthProvider``
- ``LinkedInOAuthProvider``
- ``GitLabOAuthProvider``
- ``DropboxOAuthProvider``
- ``AppleOAuthProvider``
- ``GitHubOAuthProvider``
- ``FacebookOAuthProvider``
- ``SlackOAuthProvider``
- ``AWSCognitoOAuthProvider``
- ``OktaOAuthProvider``
- ``KeyCloakOAuthProvider``

### Configuration Types

- ``MicrosoftTenantIDKind``
- ``DiscordPermissions``
- ``GitLabScope``
- ``DropboxScope``
- ``Auth0Connection``

### Service Account Support

- ``GoogleServiceAccountCredentials``

### OpenID Connect

- ``OpenIDDiscoveryService``
- ``IDTokenClaims``
- ``JWKSet``

### Integration Guides

- <doc:VaporIntegration>
- <doc:HummingbirdIntegration>
- <doc:NIOIntegration>

### Token Management

- <doc:RefreshTokenSupport>

### OpenID Connect

- <doc:OpenIDConnect>
- <doc:DeviceFlowExample>

### Enterprise Authentication

- <doc:OktaMFA>

## Advanced Usage

### Enterprise Features

OAuthKit provides enterprise-grade features for production applications:

- **Multi-tenant Support**: Microsoft Azure AD with flexible tenant configuration
- **Service Accounts**: Google Workspace automation and API access
- **PKCE Security**: Enhanced security for public clients
- **Token Management**: Automatic refresh and validation
- **Custom Instances**: Self-hosted GitLab, KeyCloak, and other providers

### Error Handling

```swift
do {
    let tokenResponse = try await provider.exchangeCode(...)
} catch OAuth2Error.configurationError(let message) {
    // Handle configuration issues
} catch OAuth2Error.networkError(let message) {
    // Handle network failures  
} catch OAuth2Error.responseError(let message) {
    // Handle API response errors
}
```

## Security Best Practices

- Always use HTTPS in production
- Implement PKCE for public clients
- Validate state parameters to prevent CSRF attacks
- Store tokens securely and implement proper rotation
- Use appropriate scopes with principle of least privilege
- Validate ID tokens when using OpenID Connect