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

| Provider | Current Method | Ideal Method | Notes |
|----------|----------------|--------------|-------|
| **Apple** | Custom implementation | `provider.refreshAccessToken(refreshToken:)` | Uses JWT-based authentication |

## Current Implementation Examples

**Note**: These examples show the current inconsistent API. In an ideal world, all providers would have `refreshAccessToken()` directly on the provider.

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
    tenantID: .common
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
let provider = try await oauthFactory.discordProvider(
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    redirectURI: "your-redirect-uri"
)

// Later, refresh the token
let (newTokens, _) = try await provider.refreshAccessToken(refreshToken: storedRefreshToken)
```

### GitHub (OAuth2)

```swift
let provider = try await oauthFactory.githubProvider(
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

For applications that support multiple providers, you can create a generic refresh function that handles the current API inconsistency:

```swift
func refreshTokenForProvider(
    _ providerName: String,
    refreshToken: String,
    oauthFactory: OAuthClientFactory
) async throws -> (tokenResponse: TokenResponse, claims: IDTokenClaims?) {
    
    switch providerName.lowercased() {
    // OpenID Connect Providers with custom refresh methods
    case "google":
        let provider = try await oauthFactory.googleProvider(
            clientID: Environment.get("GOOGLE_CLIENT_ID")!,
            clientSecret: Environment.get("GOOGLE_CLIENT_SECRET")!,
            redirectURI: Environment.get("GOOGLE_REDIRECT_URI")!
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)
        
    // OpenID Connect Providers using client.refreshToken
    case "microsoft":
        let provider = try await oauthFactory.microsoftProvider(
            clientID: Environment.get("MICROSOFT_CLIENT_ID")!,
            clientSecret: Environment.get("MICROSOFT_CLIENT_SECRET")!,
            redirectURI: Environment.get("MICROSOFT_REDIRECT_URI")!,
            tenantID: .common
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)
        
    case "auth0":
        let provider = try await oauthFactory.auth0Provider(
            clientID: Environment.get("AUTH0_CLIENT_ID")!,
            clientSecret: Environment.get("AUTH0_CLIENT_SECRET")!,
            domain: Environment.get("AUTH0_DOMAIN")!,
            redirectURI: Environment.get("AUTH0_REDIRECT_URI")!
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)
        
    case "okta":
        let provider = try await oauthFactory.oktaProvider(
            clientID: Environment.get("OKTA_CLIENT_ID")!,
            clientSecret: Environment.get("OKTA_CLIENT_SECRET")!,
            domain: Environment.get("OKTA_DOMAIN")!,
            redirectURI: Environment.get("OKTA_REDIRECT_URI")!
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)
        
    case "cognito":
        let provider = try await oauthFactory.awsCognitoProvider(
            clientID: Environment.get("COGNITO_CLIENT_ID")!,
            clientSecret: Environment.get("COGNITO_CLIENT_SECRET")!,
            region: Environment.get("COGNITO_REGION")!,
            userPoolID: Environment.get("COGNITO_USER_POOL_ID")!,
            redirectURI: Environment.get("COGNITO_REDIRECT_URI")!
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)
        
    // OAuth2 Providers
    case "discord":
        let provider = try await oauthFactory.discordProvider(
            clientID: Environment.get("DISCORD_CLIENT_ID")!,
            clientSecret: Environment.get("DISCORD_CLIENT_SECRET")!,
            redirectURI: Environment.get("DISCORD_REDIRECT_URI")!
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)
        
    case "github":
        let provider = try await oauthFactory.githubProvider(
            clientID: Environment.get("GITHUB_CLIENT_ID")!,
            clientSecret: Environment.get("GITHUB_CLIENT_SECRET")!,
            redirectURI: Environment.get("GITHUB_REDIRECT_URI")!
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)
        
    case "facebook":
        let provider = try await oauthFactory.facebookProvider(
            clientID: Environment.get("FACEBOOK_CLIENT_ID")!,
            clientSecret: Environment.get("FACEBOOK_CLIENT_SECRET")!,
            redirectURI: Environment.get("FACEBOOK_REDIRECT_URI")!
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)
        
    case "linkedin":
        let provider = try await oauthFactory.linkedInProvider(
            clientID: Environment.get("LINKEDIN_CLIENT_ID")!,
            clientSecret: Environment.get("LINKEDIN_CLIENT_SECRET")!,
            redirectURI: Environment.get("LINKEDIN_REDIRECT_URI")!
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)
        
    case "gitlab":
        let provider = try await oauthFactory.gitlabProvider(
            clientID: Environment.get("GITLAB_CLIENT_ID")!,
            clientSecret: Environment.get("GITLAB_CLIENT_SECRET")!,
            redirectURI: Environment.get("GITLAB_REDIRECT_URI")!,
            customInstance: nil
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)
        
    case "dropbox":
        let provider = try await oauthFactory.dropboxProvider(
            clientID: Environment.get("DROPBOX_CLIENT_ID")!,
            clientSecret: Environment.get("DROPBOX_CLIENT_SECRET")!,
            redirectURI: Environment.get("DROPBOX_REDIRECT_URI")!
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)
        
    case "slack":
        let provider = try await oauthFactory.slackProvider(
            clientID: Environment.get("SLACK_CLIENT_ID")!,
            clientSecret: Environment.get("SLACK_CLIENT_SECRET")!,
            redirectURI: Environment.get("SLACK_REDIRECT_URI")!
        )
        return try await provider.refreshAccessToken(refreshToken: refreshToken)
        
    default:
        throw OAuth2Error.configurationError("Unsupported provider for token refresh: \(providerName)")
    }
}
```

## Automatic Token Refresh

Here's a middleware example that automatically refreshes tokens when needed:

```swift
struct TokenRefreshMiddleware: AsyncMiddleware {
    let oauthFactory: OAuthClientFactory
    
    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        // Check if token needs refresh
        guard let refreshToken = request.session.data["refresh_token"],
              let expiresAt = request.session.data["token_expires_at"],
              let provider = request.session.data["provider"],
              let expiryTime = Double(expiresAt) else {
            return try await next.respond(to: request)
        }
        
        // Refresh if token expires within 5 minutes
        let now = Date().timeIntervalSince1970
        if now >= expiryTime - 300 {
            do {
                let (newTokens, _) = try await refreshTokenForProvider(
                    provider,
                    refreshToken: refreshToken,
                    oauthFactory: oauthFactory
                )
                
                // Update session with new tokens
                request.session.data["access_token"] = newTokens.accessToken
                if let newRefreshToken = newTokens.refreshToken {
                    request.session.data["refresh_token"] = newRefreshToken
                }
                if let expiresIn = newTokens.expiresIn {
                    request.session.data["token_expires_at"] = String(now + Double(expiresIn))
                }
                
            } catch {
                // Log error and potentially redirect to re-authentication
                request.logger.error("Token refresh failed: \(error)")
                throw Abort(.unauthorized, reason: "Token refresh failed")
            }
        }
        
        return try await next.respond(to: request)
    }
}
```

## API Standardization Proposal

To improve developerBest Practices

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