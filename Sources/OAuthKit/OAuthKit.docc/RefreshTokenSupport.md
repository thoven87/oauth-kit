# Refresh Token Support

Learn about refresh token support across different OAuth providers in OAuthKit.

## Overview

OAuthKit provides comprehensive refresh token support across all OAuth2 and OpenID Connect providers. Refresh tokens allow you to obtain new access tokens without requiring users to re-authenticate, enabling long-lived integrations while maintaining security.

## Understanding OAuth2 vs OpenID Connect

Before diving into refresh token implementations, it's important to understand the difference between OAuth2 and OpenID Connect providers:

### OAuth2 Providers
- **Purpose**: Authorization - "What can you access?"
- **Tokens**: Access tokens, refresh tokens only
- **User Identity**: Retrieved via API endpoints (e.g., `/users/@me`, `/user`)
- **ID Token Claims**: Not supported (OAuth2 doesn't include ID tokens)
- **Examples**: Discord, GitHub, Facebook, LinkedIn, Dropbox, Slack

### OpenID Connect (OIDC) Providers  
- **Purpose**: Authentication + Authorization - "Who are you?" + "What can you access?"
- **Tokens**: Access tokens, refresh tokens, **ID tokens**
- **User Identity**: Available in ID token claims + API endpoints
- **ID Token Claims**: Contains user identity information (sub, name, email, etc.)
- **Examples**: Google, Microsoft, Auth0, AWS Cognito, Okta

This is why OAuth2 providers return `(tokenResponse, nil)` from `refreshAccessToken()` - they don't provide ID token claims because ID tokens are an OpenID Connect feature, not part of the OAuth2 specification.

## Provider Categories

### OpenID Connect Providers

These providers use the `OpenIDConnectClient` and return both token response and ID token claims:

| Provider | Refresh Method | Typical Scopes Required |
|----------|----------------|-------------------------|
| **Google** | `provider.refreshAccessToken(refreshToken:)` | `offline_access` (automatic with `accessType: .offline`) |
| **Microsoft** | `provider.refreshAccessToken(refreshToken:)` | `offline_access` |
| **Auth0** | `provider.refreshAccessToken(refreshToken:)` | `offline_access` |
| **AWS Cognito** | `provider.refreshAccessToken(refreshToken:)` | `offline_access` |
| **Okta** | `provider.refreshAccessToken(refreshToken:)` | `offline_access` |

### OAuth2 Providers

These providers use the `OAuth2Client` and return only token response (no ID token claims):

| Provider | Refresh Method | Notes |
|----------|----------------|-------|
| **Discord** | `provider.refreshAccessToken(refreshToken:)` | Returns `(TokenResponse, nil)` - get user info via `getUserProfile()` |
| **GitHub** | `provider.refreshAccessToken(refreshToken:)` | Returns `(TokenResponse, nil)` - get user info via `getUserProfile()` |
| **Facebook** | `provider.refreshAccessToken(refreshToken:)` | Returns `(TokenResponse, nil)` - get user info via `getUserProfile()` |
| **LinkedIn** | `provider.refreshAccessToken(refreshToken:)` | Returns `(TokenResponse, nil)` - get user info via `getUserProfile()` |
| **GitLab** | `provider.refreshAccessToken(refreshToken:)` | Returns `(TokenResponse, nil)` - get user info via API calls |
| **Dropbox** | `provider.refreshAccessToken(refreshToken:)` | Returns `(TokenResponse, nil)` - get user info via API calls |
| **Slack** | `provider.refreshAccessToken(refreshToken:)` | Returns `(TokenResponse, nil)` - get user info via API calls |

### Special Cases

| Provider | Notes |
|----------|-------|
| **Apple** | Uses JWT-based client authentication; refresh follows the same `provider.refreshAccessToken(refreshToken:)` API. |

## Implementation Examples

### Google (OpenID Connect)

```swift
let provider = try await oauthFactory.googleProvider(
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    redirectURI: "your-redirect-uri"
)

// Request tokens with offline access
let (authURL, codeVerifier) = try provider.generateAuthURL(
    state: "state",
    accessType: .offline, // This ensures refresh token is included
    scopes: ["openid", "profile", "email"]
)

// Later, refresh the token
let (newTokens, claims) = try await provider.refreshAccessToken(
    refreshToken: storedRefreshToken
)
```

### Microsoft (OpenID Connect)

```swift
let provider = try await oauthFactory.microsoftProvider(
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    redirectURI: "your-redirect-uri",
    tenantKind: .common
)

// Request tokens with offline access
let (authURL, codeVerifier) = try provider.generateAuthorizationURL(
    state: "state",
    scopes: ["openid", "profile", "email", "offline_access"]
)

// Later, refresh the token
let (newTokens, claims) = try await provider.refreshAccessToken(refreshToken: storedRefreshToken)
```

### Discord (OAuth2)

```swift
let provider = oauthFactory.discordProvider(
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    redirectURI: "your-redirect-uri"
)

// Later, refresh the token
let (newTokens, _) = try await provider.refreshAccessToken(refreshToken: storedRefreshToken)
```

### GitHub (OAuth2)

```swift
let provider = oauthFactory.githubProvider(
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    redirectURI: "your-redirect-uri"
)

// Later, refresh the token
let (newTokens, _) = try await provider.refreshAccessToken(refreshToken: storedRefreshToken)
// Note: GitHub is OAuth2-only, so no ID token claims are returned (hence the _)

// To get user information, use the API:
let userProfile = try await provider.getUserProfile(accessToken: newTokens.accessToken)
```

## Generic Refresh Implementation

For applications that support multiple providers, you can create a generic refresh function:

```swift
// Convenience accessor — replace with your config/DI approach in production.
private func env(_ key: String) -> String {
    guard let v = ProcessInfo.processInfo.environment[key], !v.isEmpty else {
        fatalError("Missing required environment variable: \(key)")
    }
    return v
}

func refreshTokenForProvider(
    _ providerName: String,
    refreshToken: String,
    oauthFactory: OAuthClientFactory
) async throws -> (tokenResponse: TokenResponse, claims: IDTokenClaims?) {
    switch providerName.lowercased() {
    case "google":
        let provider = try await oauthFactory.googleProvider(
            clientID: env("GOOGLE_CLIENT_ID"),
            clientSecret: env("GOOGLE_CLIENT_SECRET"),
            redirectURI: env("GOOGLE_REDIRECT_URI")
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)

    case "microsoft":
        let provider = try await oauthFactory.microsoftProvider(
            clientID: env("MICROSOFT_CLIENT_ID"),
            clientSecret: env("MICROSOFT_CLIENT_SECRET"),
            redirectURI: env("MICROSOFT_REDIRECT_URI"),
            tenantKind: .common
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)

    case "auth0":
        let provider = try await oauthFactory.auth0Provider(
            domain: env("AUTH0_DOMAIN"),
            clientID: env("AUTH0_CLIENT_ID"),
            clientSecret: env("AUTH0_CLIENT_SECRET"),
            redirectURI: env("AUTH0_REDIRECT_URI")
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)

    case "okta":
        let provider = try await oauthFactory.oktaProvider(
            domain: env("OKTA_DOMAIN"),
            clientID: env("OKTA_CLIENT_ID"),
            clientSecret: env("OKTA_CLIENT_SECRET"),
            redirectURI: env("OKTA_REDIRECT_URI")
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)

    case "cognito":
        let provider = try await oauthFactory.awsCognitoProvider(
            region: env("COGNITO_REGION"),
            userPoolID: env("COGNITO_USER_POOL_ID"),
            clientID: env("COGNITO_CLIENT_ID"),
            clientSecret: ProcessInfo.processInfo.environment["COGNITO_CLIENT_SECRET"],
            redirectURI: env("COGNITO_REDIRECT_URI")
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)

    case "discord":
        let provider = oauthFactory.discordProvider(
            clientID: env("DISCORD_CLIENT_ID"),
            clientSecret: env("DISCORD_CLIENT_SECRET"),
            redirectURI: env("DISCORD_REDIRECT_URI")
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)

    case "github":
        let provider = oauthFactory.githubProvider(
            clientID: env("GITHUB_CLIENT_ID"),
            clientSecret: env("GITHUB_CLIENT_SECRET"),
            redirectURI: env("GITHUB_REDIRECT_URI")
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)

    case "facebook":
        let provider = try await oauthFactory.facebookProvider(
            appID: env("FACEBOOK_CLIENT_ID"),
            appSecret: env("FACEBOOK_CLIENT_SECRET"),
            redirectURI: env("FACEBOOK_REDIRECT_URI")
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)

    case "linkedin":
        let provider = try await oauthFactory.linkedinProvider(
            clientID: env("LINKEDIN_CLIENT_ID"),
            clientSecret: env("LINKEDIN_CLIENT_SECRET"),
            redirectURI: env("LINKEDIN_REDIRECT_URI")
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)

    case "gitlab":
        let provider = try await oauthFactory.gitlabProvider(
            clientID: env("GITLAB_CLIENT_ID"),
            clientSecret: env("GITLAB_CLIENT_SECRET"),
            redirectURI: env("GITLAB_REDIRECT_URI"),
            customInstance: nil
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)

    case "dropbox":
        let provider = oauthFactory.dropboxProvider(
            clientID: env("DROPBOX_CLIENT_ID"),
            clientSecret: env("DROPBOX_CLIENT_SECRET"),
            redirectURI: env("DROPBOX_REDIRECT_URI")
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)

    case "slack":
        let provider = oauthFactory.slackProvider(
            clientID: env("SLACK_CLIENT_ID"),
            clientSecret: env("SLACK_CLIENT_SECRET"),
            redirectURI: env("SLACK_REDIRECT_URI")
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)

    default:
        throw OAuth2Error.configurationError("Unsupported provider for token refresh: \(providerName)")
    }
}
```

## Automatic Token Refresh

Here's a Hummingbird 2 middleware that automatically refreshes tokens before they expire.
See <doc:HummingbirdIntegration> for the full session model and context setup.

```swift
import Configuration
import Hummingbird
import HummingbirdAuth
import OAuthKit

/// Refreshes an expired Google access token before the request reaches
/// downstream route handlers.
///
/// `ConfigReader` is `Sendable` — storing a pre-scoped reader in the middleware
/// avoids resolving credentials on every request.
struct TokenRefreshMiddleware: RouterMiddleware {
    typealias Context = AppRequestContext

    let oauthKit: OAuthClientFactory
    /// Pre-scoped reader for the active provider's credentials.
    let providerConfig: ConfigReader

    func handle(
        _ request: Request,
        context: Context,
        next: (Request, Context) async throws -> Response
    ) async throws -> Response {
        if var user = context.sessions.session?.authenticatedUser,
           let refreshToken = user.refreshToken {
            do {
                let provider = try await oauthKit.googleProvider(
                    clientID: try providerConfig.require("client_id"),
                    clientSecret: try providerConfig.require("client_secret"),
                    redirectURI: try providerConfig.require("redirect_uri")
                )
                let newTokens = try await provider.refreshAccessToken(
                    refreshToken: refreshToken
                )
                user = AppRequestContext.Session.AuthenticatedUser(
                    id: user.id,
                    name: user.name,
                    email: user.email,
                    accessToken: newTokens.accessToken,
                    refreshToken: newTokens.refreshToken ?? user.refreshToken,
                    idToken: newTokens.idToken ?? user.idToken,
                    provider: user.provider
                )
                context.sessions.setSession(.authenticated(user), expiresIn: .minutes(30))
            } catch {
                context.logger.warning("Token refresh failed: \(error)")
                // Let the request continue — downstream handlers can check
                // whether the access token is still usable.
            }
        }
        return try await next(request, context)
    }
}
```

Wire it into a route group after `SessionMiddleware`:

```swift
router.group()
    .add(middleware: TokenRefreshMiddleware(
        oauthKit: oauthKit,
        providerConfig: reader.scoped(to: "google")
    ))
```

## Best Practices

### 1. Secure Storage
Always store refresh tokens securely:
- Encrypt refresh tokens when storing in databases
- Use secure session storage
- Never expose refresh tokens in client-side code

### 2. Proper Scopes
Request appropriate scopes for refresh tokens:
- **OpenID Connect**: Include `offline_access` scope
- **Google**: Use `accessType: .offline` parameter
- **Microsoft**: Include `offline_access` in scopes

### 3. Token Rotation
Handle refresh token rotation properly:
- Always check for new refresh tokens in the response
- Update stored refresh tokens when new ones are provided
- Some providers rotate refresh tokens on each use

### 4. Error Handling
Implement proper error handling:
```swift
do {
    let (newTokens, _) = try await provider.refreshAccessToken(refreshToken: refreshToken)
    // Update stored tokens
} catch OAuth2Error.responseError(let message) where message.contains("invalid_grant") {
    // Refresh token is invalid - redirect to re-authentication
    throw AuthenticationError.refreshTokenExpired
} catch {
    // Other errors - retry or fallback
    throw AuthenticationError.tokenRefreshFailed(error)
}
```

### 5. Timing
Refresh tokens proactively:
- Refresh tokens 5-10 minutes before expiry
- Don't wait until the token is completely expired
- Handle race conditions in multi-threaded environments

## Provider-Specific Notes

### Google
- Automatically includes refresh tokens when `accessType: .offline` is used
- Refresh tokens don't expire but can be revoked
- New refresh tokens are not always returned on refresh

### Microsoft
- Requires `offline_access` scope for refresh tokens
- Supports both personal and work/school accounts
- Refresh tokens are valid for 90 days by default

### Discord
- Refresh tokens expire after 30 days
- New refresh token is returned with each refresh
- Bot tokens don't use refresh tokens

### GitHub
- Refresh tokens are optional and must be explicitly requested
- Refresh tokens expire after 6 months of inactivity
- Fine-grained personal access tokens are recommended for long-term access

### Facebook
- Uses long-lived access tokens (60 days) instead of refresh tokens
- Exchange short-lived tokens for long-lived ones
- No traditional refresh token flow
- OAuth2 provider - no ID token claims, use `getUserProfile()` for user info

## Device Flow and Refresh Tokens

Device authorization flow (RFC 8628) also supports refresh tokens. When using device flow with OpenID Connect providers, you can refresh tokens the same way:

```swift
// Device flow with Google
let deviceAuth = try await provider.requestDeviceAuthorization(
    scopes: ["openid", "profile", "email", "offline_access"]
)

// Complete device authorization flow...
let (tokens, claims) = try await provider.pollForDeviceAuthorization(
    deviceCode: deviceAuth.deviceCode
)

// Later, refresh the tokens
let (refreshedTokens, updatedClaims) = try await provider.refreshAccessToken(
    refreshToken: tokens.refreshToken!
)
```

### Getting User Information

**OpenID Connect Providers** provide user info in two ways:
```swift
// From ID token claims (immediate, no API call needed)
let (tokenResponse, claims) = try await provider.refreshAccessToken(refreshToken: refreshToken)
let userName = claims?.name
let userEmail = claims?.email

// From API endpoint (requires additional API call)
let userProfile = try await provider.getUserProfile(accessToken: tokenResponse.accessToken)
```

**OAuth2 Providers** only provide user info via API endpoints:
```swift
// No ID token claims available
let (tokenResponse, _) = try await provider.refreshAccessToken(refreshToken: refreshToken)

// Must use API endpoint to get user info
let userProfile = try await provider.getUserProfile(accessToken: tokenResponse.accessToken)
let userName = userProfile.name  // Structure varies by provider
```