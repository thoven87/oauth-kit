# OAuthKit

A Swift OAuth2 and OpenID Connect client library with modern async/await support, built on top of JWT-Kit which works on Linux.

## Features

- OAuth 2.0 authorization code flow with PKCE support
- OAuth 2.0 client credentials flow
- OpenID Connect support with JWT validation
- Google Sign-In integration
- Microsoft 365 / Azure AD Sign-In integration
- Sign-in with Apple
- Sign-in with Slack
- Sign-in with Facebook
- Sign-in with GitHub
- Sign-in with Okta
- Sign-in with AWS Cognito
- Sign-in with KeyCloak 
- Auto-discovery of OpenID Connect provider configuration
- Token refresh support
- Fully asynchronous API using Swift's modern async/await pattern
- Cross-platform support (macOS and Linux)

## Requirements

- Swift 6.0+
- Linux / macOS

## Installation

Add OAuthKit as a dependency to your `Package.swift`:

```swift
.package(url: "https://github.com/thoven87/oauth-kit.git", from: "1.0.0")
```

And then add the dependency to your target:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "OAuthKit", package: "oauth-kit")
    ]
),
```

## Usage Examples

### Basic OAuth2 Client

```swift
import OAuthKit

// Initialize OAuthKit
let oauthKit = OAuthKit()

// Create an OAuth2 client
let oauth2Client = oauthKit.oauth2Client(
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    tokenEndpoint: "https://auth.example.com/oauth2/token",
    authorizationEndpoint: "https://auth.example.com/oauth2/authorize",
    redirectURI: "https://your-app.example.com/callback",
    scope: "profile email offline_access"
)

// Generate a PKCE code challenge and verifier
let (codeVerifier, codeChallenge) = OAuth2Client.generatePKCE()

// Generate an authorization URL for the user to visit
let authURL = try oauth2Client.authorizationURL(
    state: "random-state-value",
    codeChallenge: codeChallenge
)

print("Visit this URL to authorize: \(authURL)")

// After the user authorizes and is redirected back to your app with a code,
// exchange the code for tokens:
let tokenResponse = try await oauth2Client.exchangeCode(
    code: "authorization-code-from-callback",
    codeVerifier: codeVerifier
)

print("Access token: \(tokenResponse.accessToken)")
```

### Google Sign-In

```swift
import OAuthKit

// Initialize OAuthKit
let oauthKit = OAuthKit()

// Create Google OAuth provider
let googleProvider = try await oauthKit.googleProvider(
    clientID: "some-client-id",  // From Google Cloud Console
    clientSecret: "some-client-secret", // From Google Cloud Console
    redirectURI: "https://example.com/callback" // Must match Google Console
)

// Generate a Google Sign-In URL with recommended parameters
let (googleAuthURL, googleCodeVerifier) = try googleProvider.signInURL(
    state: UUID().uuidString,
    prompt: .selectAccount, // Force account selection screen
    loginHint: "user@example.com" // Optional: pre-fill email
)

print("Google Sign-In URL: \(googleAuthURL)")

// In your callback handler, after receiving the code from Google:
let (tokenResponse, claims) = try await googleProvider.exchangeCode(
    code: "authorization-code-from-google",
    codeVerifier: googleCodeVerifier
)

// Get the user's Google profile info
let profile = try await googleProvider.getUserProfile(
    accessToken: tokenResponse.accessToken
)

print("Authenticated user: \(profile.name ?? "Unknown")")
print("Email: \(profile.email ?? "Not provided")")
print("Picture URL: \(profile.picture ?? "None")")
```

### Microsoft 365 / Azure AD Sign-In

```swift
// Initialize OAuthKit
let oauthKit = OAuthKit()

// Create Microsoft OAuth provider
// For multi-tenant applications (works with any Microsoft account):
let microsoftProvider = oauthKit.microsoftMultiTenantProvider(
    clientID: "your-azure-client-id",  // From Azure portal
    clientSecret: "your-azure-client-secret", // From Azure portal
    redirectURI: "https://your-app.example.com/ms-callback", // Must match Azure portal
    scope: "openid profile email User.Read" // Include Graph API permissions as needed
)

// Alternatively, for single-tenant (organization-specific) applications:
/*
let microsoftProvider = try await microsoftProvider.microsoftProvider(
    clientID: "your-azure-client-id",
    clientSecret: "your-azure-client-secret",
    tenantID: "your-tenant-id", // Specific to your organization
    redirectURI: "https://your-app.example.com/ms-callback",
    scope: "openid profile email User.Read"
)
*/

// Generate a Microsoft Sign-In URL with recommended parameters
let (msAuthURL, msCodeVerifier) = try microsoftProvider.signInURL(
    state: UUID().uuidString,
    prompt: .selectAccount, // Force account selection
    domainHint: .organizations // Hint for work/school accounts, use .consumers for personal accounts
)

print("Microsoft Sign-In URL: \(msAuthURL)")

// In your callback handler, after receiving the code from Microsoft:
let (tokenResponse, claims) = try await microsoftProvider.exchangeCode(
    code: "authorization-code-from-microsoft",
    codeVerifier: msCodeVerifier
)

// Get the user's Microsoft profile info
let profile = try await microsoftProvider.getUserProfile(
    accessToken: tokenResponse.accessToken
)

print("Authenticated user: \(profile.name ?? "Unknown")")
print("Email: \(profile.email ?? "Not provided")")
print("Tenant ID: \(profile.tenantId ?? "None")")

// Call Microsoft Graph API for additional information
let graphData = try await microsoftProvider.callGraphAPI(
    accessToken: tokenResponse.accessToken,
    endpoint: "/me", // Get basic profile
    httpClient: httpClient,
    logger: logger
)

print("Graph API data: \(graphData)")
```

### OpenID Connect Client

```swift
// Initialize OAuthKit
let oauthKit = OAuthKit()

// Create an OpenID Connect client with auto-discovery
let oidcClient = try await oauthKit.openIDConnectClient(
    discoveryURL: "https://accounts.google.com",  // Uses .well-known/openid-configuration
    clientID: "your-google-client-id",
    clientSecret: "your-google-client-secret",
    redirectURI: "https://your-app.example.com/callback",
    scope: "openid profile email"
)

// Generate a PKCE code challenge and verifier
let (codeVerifier, codeChallenge) = OAuth2Client.generatePKCE()

// Generate an authorization URL with a nonce for OIDC
let nonce = UUID().uuidString
let authURL = try oidcClient.authorizationURL(
    state: "random-state-value",
    codeChallenge: codeChallenge,
    additionalParameters: ["nonce": nonce]
)

print("Visit this URL to authorize: \(authURL)")

// After the user authorizes and is redirected back to your app with a code,
// exchange the code for tokens and validate the ID token:
let (tokenResponse, claims) = try await oidcClient.exchangeCode(
    code: "authorization-code-from-callback",
    codeVerifier: codeVerifier
)

print("Access token: \(tokenResponse.accessToken)")
print("Authenticated user: \(claims.sub ?? "unknown")")
print("User's email: \(claims.email ?? "not provided")")

// Get more user information from the UserInfo endpoint
let userInfo = try await oidcClient.getUserInfo(accessToken: tokenResponse.accessToken)
print("User info: \(userInfo)")
```

### Client Credentials Flow

```swift
// Initialize OAuthKit
let oauthKit = OAuthKit()

// Create an OAuth2 client for client credentials flow
let oauth2Client = oauthKit.oauth2Client(
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    tokenEndpoint: "https://auth.example.com/oauth2/token",
    scope: "api:read api:write"
)

// Request a token using client credentials
let tokenResponse = try await oauth2Client.clientCredentials()

print("Access token: \(tokenResponse.accessToken)")
```

### Token Refresh

```swift
// Refresh an expired token
if tokenResponse.isExpired() {
    guard let refreshToken = tokenResponse.refreshToken else {
        print("No refresh token available")
        return
    }
    
    let newTokenResponse = try await oauth2Client.refreshToken(refreshToken)
    print("New access token: \(newTokenResponse.accessToken)")
}
```

## Setting Up Google Sign-In

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to "APIs & Services" > "Credentials"
4. Click "Create Credentials" > "OAuth client ID"
5. Select "Web application" as the application type
6. Enter a name for your client
7. Add your authorized redirect URIs (e.g., `https://your-app.example.com/google-callback`)
8. Click "Create"
9. Copy your Client ID and Client Secret for use with OAuthKit

## Setting Up Microsoft 365 / Azure AD Sign-In

1. Go to the [Azure Portal](https://portal.azure.com/)
2. Navigate to "Azure Active Directory" > "App registrations"
3. Click "New registration"
4. Enter a name for your application
5. Select the appropriate supported account type:
   - "Accounts in this organizational directory only" for single-tenant apps
   - "Accounts in any organizational directory" for multi-tenant organizational apps
   - "Accounts in any organizational directory and personal Microsoft accounts" for consumer+work accounts
6. Add your redirect URI (e.g., `https://your-app.example.com/ms-callback`)
7. Click "Register"
8. Note your "Application (client) ID" shown on the overview page
9. For the client secret:
   - Go to "Certificates & secrets"
   - Click "New client secret"
   - Add a description and select an expiration
   - Click "Add"
   - **Important**: Copy the secret value immediately (you won't be able to see it later)
10. For Microsoft Graph API permissions:
    - Go to "API permissions"
    - Click "Add a permission"
    - Select "Microsoft Graph"
    - Choose "Delegated permissions"
    - Add the permissions your app needs (e.g., User.Read, email, profile, etc.)
    - Click "Add permissions"

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This library is released under the Apache 2.0 license.
