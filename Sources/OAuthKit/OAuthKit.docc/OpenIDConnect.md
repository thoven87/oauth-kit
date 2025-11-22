# OpenID Connect

Learn about OpenID Connect support in OAuthKit and how to use the generic OpenID Connect client.

## Overview

OpenID Connect (OIDC) is an identity layer built on top of OAuth 2.0 that enables clients to verify the identity of users and obtain basic profile information. While OAuth 2.0 focuses on authorization ("what can you access?"), OpenID Connect adds authentication ("who are you?").

OAuthKit provides a generic `OpenIDConnectClient` that works with any OpenID Connect provider through automatic discovery and standardized JWT validation.

## OAuth 2.0 vs OpenID Connect

| Aspect | OAuth 2.0 | OpenID Connect |
|--------|-----------|----------------|
| **Purpose** | Authorization | Authentication + Authorization |
| **Question** | "What can you access?" | "Who are you?" + "What can you access?" |
| **Tokens** | Access token, Refresh token | Access token, Refresh token, **ID token** |
| **User Info** | Via API endpoints | Via ID token claims + API endpoints |
| **Scopes** | Custom scopes | `openid` + profile scopes |
| **Standards** | RFC 6749 | Built on OAuth 2.0 + additional specs |

## The OpenID Connect Client

OAuthKit provides a generic `OpenIDConnectClient` that can work with any OIDC-compliant provider:

```swift
import OAuthKit

// Create client with automatic discovery
let client = try await OpenIDConnectClient(
    httpClient: HTTPClient.shared,
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    discoveryURL: "https://your-provider.com/.well-known/openid_configuration",
    redirectURI: "your-redirect-uri",
    logger: Logger(label: "OIDC")
)

// Or with manual configuration
let configuration = OpenIDConfiguration(
    authorizationEndpoint: "https://provider.com/auth",
    tokenEndpoint: "https://provider.com/token",
    userinfoEndpoint: "https://provider.com/userinfo",
    jwksUri: "https://provider.com/.well-known/jwks.json",
    issuer: "https://provider.com"
)

let client = try await OpenIDConnectClient(
    httpClient: HTTPClient.shared,
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    configuration: configuration,
    redirectURI: "your-redirect-uri",
    logger: Logger(label: "OIDC")
)
```

## Basic OpenID Connect Flow

```swift
// 1. Generate authorization URL
let (authURL, codeVerifier) = try client.generateAuthorizationURL(
    state: UUID().uuidString,
    scopes: ["openid", "profile", "email"]
)

// 2. Redirect user to authURL...

// 3. Exchange authorization code for tokens + claims
let (tokenResponse, claims) = try await client.exchangeCode(
    code: authorizationCode,
    codeVerifier: codeVerifier
)

// 4. Access user information from ID token claims
print("User ID: \(claims.sub?.value ?? "N/A")")
print("Name: \(claims.name ?? "N/A")")
print("Email: \(claims.email ?? "N/A")")
```

## ID Tokens and Claims

ID tokens are JWT tokens that contain claims about the user's identity. OAuthKit automatically validates these tokens and provides strongly-typed access to claims:

### Standard Claims

```swift
// Required claims
let userID = claims.sub?.value                 // Subject (user identifier)
let issuer = claims.iss?.value                 // Token issuer
let audience = claims.aud                      // Intended audience
let expiration = claims.exp?.value             // Token expiration
let issuedAt = claims.iat?.value               // When token was issued

// Profile claims (with 'profile' scope)
let name = claims.name                         // Full name
let givenName = claims.givenName               // First name
let familyName = claims.familyName             // Last name
let nickname = claims.nickname                 // Nickname
let preferredUsername = claims.preferredUsername
let picture = claims.picture                   // Profile picture URL
let website = claims.website                   // Website URL
let gender = claims.gender                     // Gender
let birthdate = claims.birthdate               // Birth date
let locale = claims.locale                     // Locale
let zoneinfo = claims.zoneinfo                 // Time zone

// Email claims (with 'email' scope)
let email = claims.email                       // Email address
let emailVerified = claims.emailVerified       // Email verification status

// Phone claims (with 'phone' scope)
let phoneNumber = claims.phoneNumber           // Phone number
let phoneVerified = claims.phoneNumberVerified // Phone verification status

// Address claims (with 'address' scope)
let address = claims.address?.formatted        // Full formatted address
let street = claims.address?.streetAddress     // Street address
let city = claims.address?.locality            // City
let state = claims.address?.region             // State/region
let postal = claims.address?.postalCode        // Postal code
let country = claims.address?.country          // Country
```

### Security Claims

```swift
// Security-related claims
let nonce = claims.nonce                       // Nonce for replay protection
let authTime = claims.authTime                 // When authentication occurred
let acr = claims.acr                           // Authentication context class
let amr = claims.amr                           // Authentication methods used
let azp = claims.azp                           // Authorized party
```

## OpenID Connect Scopes

OpenID Connect defines standard scopes that determine which claims are included:

| Scope | Claims Included | Description |
|-------|-----------------|-------------|
| `openid` | `sub` | **Required** - provides user identifier |
| `profile` | `name`, `family_name`, `given_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` | Basic profile information |
| `email` | `email`, `email_verified` | Email address and verification status |
| `address` | `address` | Physical mailing address |
| `phone` | `phone_number`, `phone_number_verified` | Phone number and verification |

```swift
// Request specific scopes
let (authURL, codeVerifier) = try client.generateAuthorizationURL(
    state: "state",
    scopes: ["openid", "profile", "email", "address", "phone"]
)
```

## Automatic Token Validation

OAuthKit automatically validates all ID tokens:

```swift
// These validations happen automatically:
// ✅ JWT signature verification using provider's public keys
// ✅ Issuer validation (matches expected provider)
// ✅ Audience validation (matches your client ID)
// ✅ Expiration time validation (token not expired)
// ✅ Not before time validation (token is valid now)
// ✅ Algorithm validation (only secure algorithms accepted)

let (tokenResponse, claims) = try await client.exchangeCode(
    code: code,
    codeVerifier: codeVerifier
)
// If this succeeds, the token is guaranteed to be valid and authentic
```

## UserInfo Endpoint

In addition to ID token claims, you can fetch additional user information from the UserInfo endpoint:

```swift
// Get additional user info via UserInfo endpoint
let userInfo = try await client.getUserInfo(accessToken: tokenResponse.accessToken)

// This may include additional claims not in the ID token
print("Additional user info: \(userInfo)")
```

## Discovery Service

OAuthKit includes automatic discovery of OpenID Connect configuration:

```swift
let discoveryService = OpenIDDiscoveryService(
    httpClient: HTTPClient.shared,
    logger: Logger(label: "Discovery")
)

// Fetch configuration from discovery endpoint
let configuration = try await discoveryService.fetchConfiguration(
    from: "https://your-provider.com/.well-known/openid_configuration"
)

print("Authorization endpoint: \(configuration.authorizationEndpoint)")
print("Token endpoint: \(configuration.tokenEndpoint)")
print("Supported scopes: \(configuration.scopesSupported ?? [])")
print("Supported algorithms: \(configuration.idTokenSigningAlgValuesSupported)")
```

## Refresh Tokens

Refresh tokens work the same way as OAuth2 but return updated ID token claims:

```swift
// Refresh access token and get updated user claims
let (newTokens, updatedClaims) = try await client.refreshToken(
    storedRefreshToken,
    additionalParameters: [:]
)

// Claims may have been updated since original authentication
let currentName = updatedClaims?.name
let currentEmail = updatedClaims?.email
```

## Security Best Practices

### Nonce Validation

```swift
// Generate nonce for enhanced security
let nonce = UUID().uuidString

let (authURL, codeVerifier) = try client.generateAuthorizationURL(
    state: "state",
    additionalParameters: ["nonce": nonce],
    scopes: ["openid", "profile", "email"]
)

// After token exchange, verify nonce matches
let (tokens, claims) = try await client.exchangeCode(code: code, codeVerifier: codeVerifier)
guard claims.nonce == nonce else {
    throw OAuth2Error.tokenValidationError("Nonce mismatch - possible replay attack")
}
```

### State Parameter

```swift
// Always use state parameter to prevent CSRF attacks
let state = UUID().uuidString
let (authURL, codeVerifier) = try client.generateAuthorizationURL(
    state: state,
    scopes: ["openid", "profile", "email"]
)

// Verify state parameter on callback (implementation depends on your framework)
```

## Error Handling

```swift
do {
    let (tokens, claims) = try await client.exchangeCode(code: code, codeVerifier: codeVerifier)
    // Use validated claims
} catch OAuth2Error.tokenValidationError(let message) {
    // ID token validation failed
    print("Token validation failed: \(message)")
} catch OAuth2Error.jwksError(let message) {
    // Failed to fetch or use public keys for validation
    print("Key validation error: \(message)")
} catch OAuth2Error.configurationError(let message) {
    // Discovery or configuration issue
    print("Configuration error: \(message)")
} catch {
    // Other OAuth2 errors
    print("OAuth error: \(error)")
}
```

## Working with Any OIDC Provider

The `OpenIDConnectClient` works with any compliant OpenID Connect provider:

```swift
// Generic provider setup
let client = try await OpenIDConnectClient(
    httpClient: HTTPClient.shared,
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    discoveryURL: "https://any-oidc-provider.com/.well-known/openid_configuration",
    redirectURI: "your-redirect-uri",
    logger: Logger(label: "OIDC")
)

// Standard OIDC flow works the same regardless of provider
let (authURL, codeVerifier) = try client.generateAuthorizationURL(
    state: "state",
    scopes: ["openid", "profile", "email"]
)
```

## Configuration Structure

The `OpenIDConfiguration` structure contains all discovered endpoints and capabilities:

```swift
public struct OpenIDConfiguration {
    public let authorizationEndpoint: String           // Where to send auth requests
    public let tokenEndpoint: String                   // Where to exchange tokens
    public let userinfoEndpoint: String?               // UserInfo endpoint (optional)
    public let jwksUri: String                         // Public keys for JWT validation
    public let issuer: String                          // Expected issuer in tokens
    public let scopesSupported: [String]?              // Supported scopes
    public let responseTypesSupported: [String]        // Supported response types
    public let grantTypesSupported: [String]?          // Supported grant types
    public let subjectTypesSupported: [String]         // Subject identifier types
    public let idTokenSigningAlgValuesSupported: [String] // Supported signing algorithms
    public let endSessionEndpoint: String?             // Logout endpoint (optional)
}
```

## Device Authorization Flow (RFC 8628)

OpenID Connect supports the device authorization flow for input-constrained devices like smart TVs, IoT devices, gaming consoles, and CLI tools.

### Basic Device Flow

```swift
// 1. Request device authorization
let deviceAuth = try await client.requestDeviceAuthorization(
    scopes: ["openid", "profile", "email"]
)

print("Go to: \(deviceAuth.verificationUri)")
print("Enter code: \(deviceAuth.userCode)")

// 2. Poll for completion (manual polling)
do {
    let (tokens, claims) = try await client.exchangeDeviceCode(deviceAuth.deviceCode)
    print("Authentication successful!")
    print("User: \(claims.name ?? "N/A")")
} catch DeviceFlowError.authorizationPending {
    // User hasn't completed authorization yet
} catch DeviceFlowError.slowDown {
    // Polling too frequently
} catch DeviceFlowError.expiredToken {
    // Device code has expired
} catch DeviceFlowError.accessDenied {
    // User denied the request
}
```

### Automatic Polling

```swift
// Request device authorization
let deviceAuth = try await client.requestDeviceAuthorization(
    scopes: ["openid", "profile", "email"]
)

print("Please visit: \(deviceAuth.verificationUri)")
print("Enter this code: \(deviceAuth.userCode)")
if let completeUri = deviceAuth.verificationUriComplete {
    print("Or visit: \(completeUri)")
}

// Poll automatically until complete
let (tokens, claims) = try await client.pollForDeviceAuthorization(
    deviceCode: deviceAuth.deviceCode,
    interval: deviceAuth.interval ?? 5,
    timeout: TimeInterval(deviceAuth.expiresIn)
)

print("Welcome, \(claims.name ?? "User")!")
```

### Device Flow with Provider

```swift
// Example with Google
let provider = try await oauthFactory.googleProvider(
    clientID: "your-client-id",
    clientSecret: "your-client-secret",
    redirectURI: "" // Not needed for device flow
)

let deviceAuth = try await provider.requestDeviceAuthorization(
    scopes: ["openid", "profile", "email"]
)

print("Visit: \(deviceAuth.verificationUri)")
print("Code: \(deviceAuth.userCode)")

let (tokens, claims) = try await provider.pollForDeviceAuthorization(
    deviceCode: deviceAuth.deviceCode
)
```

### Device Flow Error Handling

```swift
do {
    let (tokens, claims) = try await client.pollForDeviceAuthorization(
        deviceCode: deviceCode
    )
    // Success
} catch DeviceFlowError.authorizationPending {
    // Still waiting for user to authorize
} catch DeviceFlowError.slowDown {
    // Polling too fast - should increase interval
} catch DeviceFlowError.expiredToken {
    // Device code expired - need new authorization
} catch DeviceFlowError.accessDenied {
    // User explicitly denied authorization
} catch {
    // Other OAuth2 errors
}
```

This generic approach means you can integrate with any OpenID Connect provider without needing provider-specific code, while still getting the benefits of automatic discovery, token validation, and strongly-typed claims access.