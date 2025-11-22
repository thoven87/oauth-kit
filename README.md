# OAuthKit

A Swift OAuth2 and OpenID Connect client library with modern async/await support, built on top of JWT-Kit that works on Linux too.

## Features

### Core OAuth2 & OpenID Connect
- OAuth 2.0 authorization code flow with PKCE support
- OAuth 2.0 client credentials flow
- OAuth 2.0 device authorization grant (RFC 8628)
- **OAuth 2.0 Token Exchange (RFC 8693)**
- **OAuth 2.0 Token Introspection (RFC 7662)**
- **OAuth 2.0 Token Revocation (RFC 7009)**
- OpenID Connect support with JWT validation
- Auto-discovery of OpenID Connect provider configuration
- Token refresh support
- Fully asynchronous API using Swift's modern async/await pattern

### Provider Integrations
- Google Sign-In integration
- Google Service Account authentication
- Microsoft 365 / Azure AD Sign-In integration
- Auth0 Sign-In integration
- Discord Sign-In integration
- LinkedIn Sign-In integration
- GitLab Sign-In integration
- Dropbox Sign-In integration
- Sign-in with Apple
- Sign-in with Slack
- Sign-in with Facebook
- Sign-in with GitHub
- Sign-in with Okta
- Sign-in with AWS Cognito
- Sign-in with KeyCloak

### Platform Support
- Cross-platform support (macOS and Linux)
- Swift 6.0+ with strict concurrency support

## What's New in v1.1

🚀 **New RFC Implementations:**
- **Token Exchange (RFC 8693)**: Secure token delegation for microservices
- **Token Introspection (RFC 7662)**: Validate and inspect token metadata
- **Token Revocation (RFC 7009)**: Properly invalidate tokens

See [RFC_IMPLEMENTATIONS.md](RFC_IMPLEMENTATIONS.md) for detailed usage examples.

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

// Initialize OAuth
let oauthClient = OAuthClientFactory()

// Create an OAuth2 client
let oauth2Client = oauthKit.oauth2Client(
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    tokenEndpoint: "https://auth.example.com/oauth2/token",
    authorizationEndpoint: "https://auth.example.com/oauth2/authorize",
    redirectURI: "https://your-app.example.com/callback",
)

// Generate a PKCE code challenge and verifier
let (codeVerifier, codeChallenge) = OAuth2Client.generatePKCE()

// Generate an authorization URL for the user to visit
let authURL = try oauth2Client.generateAuthorizationURL(
    state: "random-state-value",
    codeChallenge: codeChallenge,
    scopes: ["profile", "email", "offline_access"]
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
let oauthClient = OAuthClientFactory()

// Create Google OAuth provider
let googleProvider = try await oauthClient.googleProvider(
    clientID: "some-client-id",  // From Google Cloud Console
    clientSecret: "some-client-secret", // From Google Cloud Console
    redirectURI: "https://example.com/callback" // Must match Google Console
)

// Generate a Google Sign-In URL with recommended parameters
let (googleAuthURL, googleCodeVerifier) = try googleProvider.generateAuthURL(
    state: UUID().uuidString,
    prompt: .selectAccount, // Force account selection screen
    loginHint: "user@example.com" // Optional: pre-fill email,
    scopes: ["profile", "email", "offline_access"]
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

### Google Service Account Authentication

For server-to-server authentication without user interaction. There are three ways to authenticate:

#### Method 1: Using GoogleServiceAccountCredentials object

```swift
import OAuthKit

// Initialize OAuthKit
let oauthKit = OAuthClientFactory()

// Load service account credentials from JSON string
let serviceAccountJSON = """
{
    "type": "service_account",
    "project_id": "your-project-id",
    "private_key_id": "your-private-key-id",
    "private_key": "-----BEGIN PRIVATE KEY-----\\nYour-Private-Key\\n-----END PRIVATE KEY-----\\n",
    "client_email": "your-service-account@your-project-id.iam.gserviceaccount.com",
    "client_id": "your-client-id",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
    "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/your-service-account%40your-project-id.iam.gserviceaccount.com",
    "universe_domain": "googleapis.com"
}
"""

let credentials = try GoogleServiceAccountCredentials(from: serviceAccountJSON)

// Create Google provider
let provider = try await oauthKit.googleProvider(
    clientID: "dummy",
    clientSecret: "dummy",
    redirectURI: "http://localhost"
)

// Authenticate with service account
let scopes = [
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/bigquery"
]

let tokenResponse = try await provider.authenticateWithServiceAccount(
    credentials: credentials,
    scopes: scopes
)

print("Service account access token: \(tokenResponse.accessToken)")
```

#### Method 2: Using JSON string directly (Convenience method)

```swift
// Authenticate directly with JSON string
let tokenResponse = try await provider.authenticateWithServiceAccount(
    credentialsJSON: serviceAccountJSON,
    scopes: scopes
)

print("Service account access token: \(tokenResponse.accessToken)")
```

#### Method 3: Using file path (Convenience method, Recommended)

```swift
// Authenticate using file path
let tokenResponse = try await provider.authenticateWithServiceAccount(
    credentialsFilePath: "/path/to/service-account.json",
    scopes: scopes
)

)
```

#### Method 4: Direct JWT Authentication (No Token Exchange)

For more efficient authentication, you can create JWTs directly without token exchange:

```swift
// Create JWT for Google Cloud Storage API
let jwt = try await provider.createServiceAccountJWTToken(
    credentials: credentials,
    audience: "https://storage.googleapis.com/"
)

// Use JWT directly in API calls
var request = HTTPClientRequest(url: "https://storage.googleapis.com/storage/v1/b?project=your-project-id")
request.headers.add(name: "Authorization", value: "Bearer \(jwt)")

// Direct JWT with JSON string
let jwtFromJSON = try await provider.createServiceAccountJWTToken(
    credentialsJSON: serviceAccountJSON,
    audience: "https://bigquery.googleapis.com/"
)

// Direct JWT with file path
let jwtFromFile = try await provider.createServiceAccountJWTToken(
    credentialsFilePath: "/path/to/service-account.json",
    audience: "https://www.googleapis.com/auth/cloud-platform"
)

// Direct JWT with additional claims
let customJWT = try await provider.createServiceAccountJWTToken(
    credentials: credentials,
    audience: "https://your-api.googleapis.com/",
    additionalClaims: [
        "department": "engineering",
        "role": "service"
    ]
)
```

#### Domain-Wide Delegation

All methods support domain-wide delegation by adding a `subject` parameter:

```swift
// Using credentials object
let delegatedTokenResponse1 = try await provider.authenticateWithServiceAccount(
    credentials: credentials,
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    subject: "user@yourdomain.com"
)

// Using JSON string
let delegatedTokenResponse2 = try await provider.authenticateWithServiceAccount(
    credentialsJSON: serviceAccountJSON,
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    subject: "user@yourdomain.com"
)

// Using file path
let delegatedTokenResponse3 = try await provider.authenticateWithServiceAccount(
    credentialsFilePath: "/path/to/service-account.json",
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    subject: "user@yourdomain.com"
)

// Direct JWT with domain-wide delegation
let delegatedJWT = try await provider.createServiceAccountJWTToken(
    credentials: credentials,
    audience: "https://www.googleapis.com/auth/gmail.readonly",
    subject: "user@yourdomain.com"
)

// Use JWT directly for Gmail API
var gmailRequest = HTTPClientRequest(url: "https://gmail.googleapis.com/gmail/v1/users/me/messages")
gmailRequest.headers.add(name: "Authorization", value: "Bearer \(delegatedJWT)")
```

### Microsoft 365 / Azure AD Sign-In

```swift
// Initialize OAuthKit
let oauthKit = OAuthClientFactory()

// Create Microsoft OAuth provider with different tenant configurations:

// Multi-tenant (personal + work/school accounts) - DEFAULT
let microsoftProvider = try await oauthKit.microsoftProvider(
    clientID: "your-azure-client-id",  // From Azure portal
    clientSecret: "your-azure-client-secret", // From Azure portal
    redirectURI: "https://your-app.example.com/ms-callback" // Must match Azure portal
    // tenantKind defaults to .common
)

// Personal Microsoft accounts only (@outlook.com, @hotmail.com, @live.com)
let consumerProvider = try await oauthKit.microsoftProvider(
    clientID: "your-azure-client-id",
    clientSecret: "your-azure-client-secret",
    redirectURI: "https://your-app.example.com/ms-callback",
    tenantKind: .consumers
)

// Work/school accounts only (any organization)
let orgProvider = try await oauthKit.microsoftProvider(
    clientID: "your-azure-client-id",
    clientSecret: "your-azure-client-secret",
    redirectURI: "https://your-app.example.com/ms-callback",
    tenantKind: .organizations
)

// Specific tenant by ID (single-tenant application)
let specificProvider = try await oauthKit.microsoftProvider(
    clientID: "your-azure-client-id",
    clientSecret: "your-azure-client-secret",
    redirectURI: "https://your-app.example.com/ms-callback",
    tenantKind: .custom("8eaef023-2b34-4da1-9baa-8bc8c9d6a490") // Your tenant ID
)

// Specific tenant by domain
let domainProvider = try await oauthKit.microsoftProvider(
    clientID: "your-azure-client-id",
    clientSecret: "your-azure-client-secret",
    redirectURI: "https://your-app.example.com/ms-callback",
    tenantKind: .custom("contoso.com") // Your organization's domain
)

// Using string literals (also supported)
let stringLiteralProvider = try await oauthKit.microsoftProvider(
    clientID: "your-azure-client-id",
    clientSecret: "your-azure-client-secret",
    redirectURI: "https://your-app.example.com/ms-callback",
    tenantKind: "common" // Automatically converted to .common
)

// Generate a Microsoft Sign-In URL with recommended parameters
let (msAuthURL, msCodeVerifier) = try microsoftProvider.generateAuthorizationURL(
    state: UUID().uuidString,
    prompt: .selectAccount, // Force account selection
    domainHint: .organizations, // Hint for work/school accounts, use .consumers for personal accounts
    scopes: ["openid", "profile", "email", "User.Read"] // Include Graph API permissions as needed
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

### Auth0 Sign-In

```swift
import OAuthKit

// Initialize OAuthKit
let oauthKit = OAuthClientFactory()

// Create Auth0 OAuth provider
let auth0Provider = try await oauthKit.auth0Provider(
    domain: "dev-123456.us.auth0.com",  // Your Auth0 domain
    clientID: "your-auth0-client-id",  // From Auth0 dashboard
    clientSecret: "your-auth0-client-secret", // From Auth0 dashboard
    redirectURI: "https://your-app.example.com/auth0-callback"
)

// Generate an Auth0 Sign-In URL with recommended parameters
let (auth0URL, auth0CodeVerifier) = try auth0Provider.generateAuthorizationURL(
    state: UUID().uuidString,
    connection: Auth0Connection.google.rawValue, // Optional: force specific connection
    audience: "https://your-api.example.com", // Optional: API identifier
    scopes: ["openid", "profile", "email", "read:users"]
)

print("Auth0 Sign-In URL: \(auth0URL)")

// In your callback handler, after receiving the code from Auth0:
let (tokenResponse, claims) = try await auth0Provider.exchangeCode(
    code: "authorization-code-from-auth0",
    codeVerifier: auth0CodeVerifier
)

// Get the user's Auth0 profile info
let profile = try await auth0Provider.getUserProfile(
    accessToken: tokenResponse.accessToken
)

print("Authenticated user: \(profile.name ?? "Unknown")")
print("Email: \(profile.email ?? "Not provided")")
print("Auth0 ID: \(profile.sub)")

// Call Auth0 Management API (requires management API token)
let userData: Auth0ManagementUser = try await auth0Provider.callManagementAPI(
    accessToken: managementApiToken, // Must have management API audience
    endpoint: "/api/v2/users/\(profile.sub)"
)
```

### Discord Sign-In

```swift
import OAuthKit

// Initialize OAuthKit
let oauthKit = OAuthClientFactory()

// Create Discord OAuth provider
let discordProvider = oauthKit.discordProvider(
    clientID: "your-discord-client-id",  // From Discord Developer Portal
    clientSecret: "your-discord-client-secret", // From Discord Developer Portal
    redirectURI: "https://your-app.example.com/discord-callback"
)

// Generate a Discord Sign-In URL with recommended parameters
let (discordURL, discordCodeVerifier) = try discordProvider.generateAuthorizationURL(
    state: UUID().uuidString,
    prompt: .consent, // Force consent screen
    permissions: .manageChannels, // Bot permissions using enum
    scopes: ["identify", "email", "guilds", "connections"]
)

print("Discord Sign-In URL: \(discordURL)")

// In your callback handler, after receiving the code from Discord:
let tokenResponse = try await discordProvider.exchangeCode(
    code: "authorization-code-from-discord",
    codeVerifier: discordCodeVerifier
)

// Get the user's Discord profile info
let profile = try await discordProvider.getUserProfile(
    accessToken: tokenResponse.accessToken
)

print("Discord user: \(profile.username)#\(profile.discriminator)")
print("Email: \(profile.email ?? "Not provided")")
print("User ID: \(profile.id)")

// Get user's Discord servers (requires 'guilds' scope)
let guilds = try await discordProvider.getUserGuilds(
    accessToken: tokenResponse.accessToken
)

print("User is in \(guilds.count) Discord servers")

// Get user's connected accounts (requires 'connections' scope)
let connections = try await discordProvider.getUserConnections(
    accessToken: tokenResponse.accessToken
)

print("Connected accounts: \(connections.map { "\($0.type): \($0.name)" }.joined(separator: ", "))")

// Discord Permissions Examples using OptionSet
let basicBotPerms = DiscordPermissions.basicBot
let moderationBotPerms = DiscordPermissions.moderationBot
let musicBotPerms = DiscordPermissions.musicBot

print("Basic bot permissions: \(basicBotPerms.rawValue)")
print("Moderation bot permissions: \(moderationBotPerms.rawValue)")
print("Music bot permissions: \(musicBotPerms.rawValue)")

// Check specific permissions using OptionSet contains
let hasManageMessages = moderationBotPerms.contains(.manageMessages)
print("Moderation bot can manage messages: \(hasManageMessages)")

// Custom permission combinations using array literal syntax
let customPerms: DiscordPermissions = [.sendMessages, .manageChannels, .kickMembers]
print("Custom permissions: \(customPerms.rawValue)")

// Adding permissions using OptionSet union
let extendedPerms = basicBotPerms.union([.manageMessages, .moderateMembers])
print("Extended permissions: \(extendedPerms.rawValue)")
```

### LinkedIn Sign-In

```swift
import OAuthKit

// Initialize OAuthKit
let oauthKit = OAuthClientFactory()

// Create LinkedIn OAuth provider
let linkedinProvider = oauthKit.linkedinProvider(
    clientID: "your-linkedin-client-id",  // From LinkedIn Developer Console
    clientSecret: "your-linkedin-client-secret", // From LinkedIn Developer Console
    redirectURI: "https://your-app.example.com/linkedin-callback"
)

// Generate a LinkedIn Sign-In URL
let (linkedinURL, linkedinCodeVerifier) = try linkedinProvider.generateAuthorizationURL(
    state: UUID().uuidString,
    scopes: ["openid", "profile", "email"]
)

print("LinkedIn Sign-In URL: \(linkedinURL)")

// In your callback handler, after receiving the code from LinkedIn:
let tokenResponse = try await linkedinProvider.exchangeCode(
    code: "authorization-code-from-linkedin",
    codeVerifier: linkedinCodeVerifier
)

// Get complete user profile (includes email)
let completeProfile = try await linkedinProvider.getCompleteUserProfile(
    accessToken: tokenResponse.accessToken
)

print("LinkedIn user: \(completeProfile.fullName ?? "Unknown")")
print("Email: \(completeProfile.email ?? "Not provided")")
print("Profile picture: \(completeProfile.profilePictureURL ?? "None")")

// Or get profile and email separately if needed
let profile = try await linkedinProvider.getUserProfile(accessToken: tokenResponse.accessToken)
let email = try await linkedinProvider.getUserEmail(accessToken: tokenResponse.accessToken)
```

### GitLab Sign-In

```swift
import OAuthKit

// Initialize OAuthKit
let oauthKit = OAuthClientFactory()

// Create GitLab OAuth provider (GitLab.com)
let gitlabProvider = oauthKit.gitlabProvider(
    clientID: "your-gitlab-client-id",  // From GitLab application settings
    clientSecret: "your-gitlab-client-secret", // From GitLab application settings
    redirectURI: "https://your-app.example.com/gitlab-callback"
)

// For self-hosted GitLab instances
let customInstance = GitLabOAuthProvider.CustomInstance(baseURL: "https://gitlab.yourcompany.com")
let selfHostedProvider = oauthKit.gitlabProvider(
    clientID: "your-gitlab-client-id",
    clientSecret: "your-gitlab-client-secret",
    redirectURI: "https://your-app.example.com/gitlab-callback",
    customInstance: customInstance
)

// Generate a GitLab Sign-In URL
let (gitlabURL, gitlabCodeVerifier) = try gitlabProvider.generateAuthorizationURL(
    state: UUID().uuidString,
    scopes: [.readUser, .readRepository, .api]
)

print("GitLab Sign-In URL: \(gitlabURL)")

// In your callback handler, after receiving the code from GitLab:
let tokenResponse = try await gitlabProvider.exchangeCode(
    code: "authorization-code-from-gitlab",
    codeVerifier: gitlabCodeVerifier
)

// Get the user's GitLab profile info
let profile = try await gitlabProvider.getUserProfile(
    accessToken: tokenResponse.accessToken
)

print("GitLab user: \(profile.username)")
print("Name: \(profile.name)")
print("Email: \(profile.email ?? "Not provided")")

// Get user's projects
let projects = try await gitlabProvider.getUserProjects(
    accessToken: tokenResponse.accessToken,
    owned: true,
    visibility: .public
)

print("User has \(projects.count) public projects")

// Get user's groups
let groups = try await gitlabProvider.getUserGroups(
    accessToken: tokenResponse.accessToken
)

print("User is in \(groups.count) groups")
```

### Dropbox Sign-In

```swift
import OAuthKit

// Initialize OAuthKit
let oauthKit = OAuthClientFactory()

// Create Dropbox OAuth provider
let dropboxProvider = oauthKit.dropboxProvider(
    clientID: "your-dropbox-app-key",  // From Dropbox App Console
    clientSecret: "your-dropbox-app-secret", // From Dropbox App Console
    redirectURI: "https://your-app.example.com/dropbox-callback"
)

// Generate a Dropbox Sign-In URL
let (dropboxURL, dropboxCodeVerifier) = try dropboxProvider.generateAuthorizationURL(
    state: UUID().uuidString,
    scopes: [.filesMetadataRead, .filesContentRead, .accountInfoRead]
)

print("Dropbox Sign-In URL: \(dropboxURL)")

// In your callback handler, after receiving the code from Dropbox:
let tokenResponse = try await dropboxProvider.exchangeCode(
    code: "authorization-code-from-dropbox",
    codeVerifier: dropboxCodeVerifier
)

// Get the user's Dropbox account info
let account = try await dropboxProvider.getCurrentAccount(
    accessToken: tokenResponse.accessToken
)

print("Dropbox user: \(account.name.displayName)")
print("Email: \(account.email)")
print("Account ID: \(account.accountId)")

// Get space usage
let spaceUsage = try await dropboxProvider.getSpaceUsage(
    accessToken: tokenResponse.accessToken
)

print("Used space: \(spaceUsage.used) bytes")

// List files in root folder
let folderContents = try await dropboxProvider.listFolder(
    accessToken: tokenResponse.accessToken,
    path: "",
    recursive: false
)

print("Root folder contains \(folderContents.entries.count) items")

// Create a folder
let newFolder = try await dropboxProvider.createFolder(
    accessToken: tokenResponse.accessToken,
    path: "/MyNewFolder"
)

print("Created folder: \(newFolder.metadata.name)")
```

### OpenID Connect Client

```swift
// Initialize OAuthKit
let oauthKit = OAuthClientFactory()

// Create an OpenID Connect client with auto-discovery
let oidcClient = try await oauthKit.openIDConnectClient(
    discoveryURL: "https://accounts.google.com",  // Uses .well-known/openid-configuration
    clientID: "your-google-client-id",
    clientSecret: "your-google-client-secret",
    redirectURI: "https://your-app.example.com/callback",
)

// Generate a PKCE code challenge and verifier
let (codeVerifier, codeChallenge) = OAuth2Client.generatePKCE()

// Generate an authorization URL with a nonce for OIDC
let nonce = UUID().uuidString
let authURL = try oidcClient.generateAuthorizationURL(
    state: "random-state-value",
    codeChallenge: codeChallenge,
    additionalParameters: ["nonce": nonce],
    scopes: ["openid", "profile", email"]
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
let oauthKit = OAuthClientFactory()

// Create an OAuth2 client for client credentials flow
let oauth2Client = oauthKit.oauth2Client(
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    tokenEndpoint: "https://auth.example.com/oauth2/token",
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

## Setting Up Google Service Account

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Navigate to "IAM & Admin" > "Service Accounts"
3. Click "Create Service Account"
4. Fill in the service account details
5. Grant necessary roles/permissions to the service account
6. Click "Create and Continue"
7. Click "Done" to finish creating the service account
8. Click on the created service account
9. Go to the "Keys" tab
10. Click "Add Key" > "Create new key"
11. Select "JSON" format and click "Create"
12. Download and securely store the JSON key file

For domain-wide delegation (optional):
1. In the service account details, enable "Domain-wide delegation"
2. In Google Workspace Admin Console, go to Security > API Controls > Domain-wide Delegation
3. Add the service account's client ID with required scopes

## Setting Up Microsoft 365 / Azure AD Sign-In

1. Go to the [Azure Portal](https://portal.azure.com/)
2. Navigate to "Azure Active Directory" > "App registrations"
3. Click "New registration"
4. Enter a name for your application
5. Select the appropriate supported account type (this determines which `MicrosoftTenantIDKind` you'll use):
   - **"Accounts in this organizational directory only"** → Use `.custom("your-tenant-id")` for single-tenant
   - **"Accounts in any organizational directory"** → Use `.organizations` for work/school accounts only
   - **"Accounts in any organizational directory and personal Microsoft accounts"** → Use `.common` (default) for multi-tenant
   - **"Personal Microsoft accounts only"** → Use `.consumers` for personal accounts only
6. Add your redirect URI (e.g., `https://your-app.example.com/ms-callback`)
7. Click "Register"
8. Note your "Application (client) ID" shown on the overview page
9. **Important for single-tenant apps**: Also note your "Directory (tenant) ID" from the overview page
10. For the client secret:
    - Go to "Certificates & secrets"
    - Click "New client secret"
    - Add a description and select an expiration
    - Click "Add"
    - **Important**: Copy the secret value immediately (you won't be able to see it later)
11. For Microsoft Graph API permissions:
    - Go to "API permissions"
    - Click "Add a permission"
    - Select "Microsoft Graph"
    - Choose "Delegated permissions"
    - Add the permissions your app needs (e.g., User.Read, email, profile, etc.)
    - Click "Add permissions"

### Choosing the Right Tenant Configuration

Use the following guide to select the appropriate `tenantKind` parameter:

- **`.common`** (default): Multi-tenant app accepting both personal (@outlook.com, @hotmail.com) and work/school accounts
- **`.consumers`**: Only personal Microsoft accounts (good for consumer apps)
- **`.organizations`**: Only work/school accounts from any organization (good for B2B apps)
- **`.custom("your-tenant-id")`**: Single-tenant app for a specific organization only
- **`.custom("yourdomain.com")`**: Single-tenant app using your organization's domain name

**Note**: The tenant configuration in your code must match the "Supported account types" setting in Azure portal.

## Setting Up Auth0 Sign-In

1. Go to the [Auth0 Dashboard](https://manage.auth0.com/)
2. Create a new application or select an existing one
3. Go to the "Settings" tab
4. Note your **Domain** and **Client ID**
5. Generate or note your **Client Secret**
6. Add your callback URL to "Allowed Callback URLs" (e.g., `https://your-app.example.com/auth0-callback`)
7. Add your app's domain to "Allowed Web Origins" if using PKCE from a web app
8. Configure your desired connections (social, enterprise, database) in the "Connections" tab
9. Set up any required APIs in the "APIs" section if you need to access Auth0 Management API

## Setting Up Discord Sign-In

1. Go to the [Discord Developer Portal](https://discord.com/developers/applications)
2. Click "New Application" or select an existing one
3. Go to the "OAuth2" section in the sidebar
4. Note your **Client ID** and **Client Secret**
5. Add your redirect URI to "Redirects" (e.g., `https://your-app.example.com/discord-callback`)
6. In the "OAuth2 URL Generator", select the scopes your app needs:
   - `identify`: Basic user info (username, avatar, etc.)
   - `email`: User's email address
   - `guilds`: List of servers the user is in
   - `connections`: User's connected accounts (Twitch, YouTube, etc.)
7. If you're building a bot, also configure the "Bot" section and set appropriate permissions:
   - Use `DiscordPermissions.basicBot` for simple bots
   - Use `DiscordPermissions.moderationBot` for moderation features
   - Use `DiscordPermissions.musicBot` for voice channel bots
   - Use specific permissions like `.manageChannels`, `.kickMembers`, etc.

## Setting Up GitLab Sign-In

### For GitLab.com

1. Go to [GitLab.com](https://gitlab.com) and sign in
2. Click on your avatar in the top right, then select **Edit profile**
3. In the left sidebar, select **Applications**
4. Click **Add new application**
5. Fill in the application details:
   - **Name**: Your application name
   - **Redirect URI**: Your callback URL (e.g., `https://your-app.example.com/gitlab-callback`)
   - **Scopes**: Select the permissions your app needs:
     - `read_user`: Read user profile information
     - `read_repository`: Read repository data
     - `api`: Full API access
     - `read_api`: Read-only API access
6. Click **Save application**
7. Note your **Application ID** (client ID) and **Secret**

### For Self-Hosted GitLab

The process is the same, but you'll use your GitLab instance URL and configure the `CustomInstance`:

```swift
let customInstance = GitLabOAuthProvider.CustomInstance(baseURL: "https://gitlab.yourcompany.com")
let provider = oauthKit.gitlabProvider(
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    redirectURI: "https://your-app.com/callback",
    customInstance: customInstance
)
```

## Setting Up Dropbox Sign-In

1. Go to the [Dropbox App Console](https://www.dropbox.com/developers/apps)
2. Click **Create app**
3. Choose your app configuration:
   - **Choose an API**: Dropbox API
   - **Choose the type of access you need**:
     - App folder: Access to a single folder
     - Full Dropbox: Access to all files and folders
   - **Name your app**: Enter a unique name
4. Click **Create app**
5. In your app settings:
   - Note your **App key** (client ID) and **App secret**
   - Add your redirect URI to **Redirect URIs**
6. Configure permissions in the **Permissions** tab:
   - `account_info.read`: Read account information
   - `files.metadata.read`: Read file and folder metadata
   - `files.content.read`: Read file contents
   - `files.content.write`: Write file contents
   - `sharing.read`: Read sharing information
   - `sharing.write`: Create and modify shared links

## Setting Up LinkedIn Sign-In

1. Go to the [LinkedIn Developer Console](https://www.linkedin.com/developers/)
2. Click "Create App" or select an existing app
3. Fill in the required information and verify your identity
4. Go to the "Auth" tab
5. Note your **Client ID** and **Client Secret**
6. Add your redirect URL to "Authorized redirect URLs for your app" (e.g., `https://your-app.example.com/linkedin-callback`)
7. In the "Products" tab, add the products you need:
   - **Sign In with LinkedIn using OpenID Connect**: For basic authentication
   - **Share on LinkedIn**: If you need to post content
   - **Marketing Developer Platform**: For marketing APIs
8. Configure the required scopes in your app:
   - `openid`: Required for OpenID Connect
   - `profile`: Basic profile information
   - `email`: User's email address

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This library is released under the Apache 2.0 license.
