# JWKS Refresh Service

Automatically refresh JSON Web Key Sets (JWKS) from OpenID Connect providers to ensure JWT signature verification always uses current public keys.

## Overview

The JWKS Refresh Service provides automatic rotation of public keys used for JWT signature verification in OAuth and OpenID Connect flows. This ensures that your application can handle key rotations performed by identity providers without manual intervention.

## Key Components

- **JWKSKeyManager**: Actor that wraps a single shared `JWTKeyCollection`, tracking which keys belong to which endpoint and performing in-place rotation via jwt-kit's `removeAll(except:)` / `add(jwks:)` APIs.
- **JWKSRefreshService**: Background service that periodically fetches fresh JWKS from registered endpoints and feeds them into the key manager.

## Quick Start

### Basic Setup

```swift
import OAuthKit
import ServiceLifecycle

// Create OAuthKit — a shared JWKSKeyManager is created automatically
let oauthKit = OAuthClientFactory()

// Create OAuth providers — their JWKS endpoints are registered for refresh
let googleProvider = try await oauthKit.googleProvider(
    clientID: "your-google-client-id",
    clientSecret: "your-google-client-secret",
    redirectURI: "https://your-app.com/auth/google/callback"
)

// Start the refresh service with graceful shutdown support
try await oauthKit.run()
```

### Custom Configuration

You can customize the refresh behavior:

```swift
let refreshConfig = JWKSRefreshService.Configuration(
    refreshInterval: .seconds(900),  // 15 minutes
    requestTimeout: .seconds(45),    // HTTP timeout
    maxRetries: 5,                   // Retry failed requests
    retryDelay: .seconds(2)          // Base delay between retries
)

let oauthKit = OAuthClientFactory(
    logger: Logger(label: "my-app.oauth"),
    jwksRefreshConfiguration: refreshConfig
)
```

## Service Lifecycle Integration

The JWKS refresh service implements the `Service` protocol from `swift-service-lifecycle`, providing proper startup, shutdown, and signal handling.

### Standalone Service

```swift
// Run just the refresh service
try await oauthKit.run()
```

### With Other Services

```swift
let serviceGroup = ServiceGroup(
    configuration: ServiceGroupConfiguration(
        services: [
            oauthKit,
            MyDatabaseService(),
            MyWebServerService()
        ],
        gracefulShutdownSignals: [.sigterm, .sigint],
        logger: logger
    )
)

try await serviceGroup.run()
```

## How It Works

### Automatic Registration

When you create OpenID Connect clients, their JWKS endpoints are automatically registered with the refresh service:

```swift
let oauthKit = OAuthClientFactory()

// This automatically registers the Google JWKS endpoint
let googleProvider = try await oauthKit.googleProvider(
    clientID: "client-id",
    clientSecret: "client-secret",
    redirectURI: "redirect-uri"
)
```

### In-Place Key Rotation

When the refresh service fetches a new JWKS for an endpoint, the ``JWKSKeyManager`` performs an in-place rotation on the shared `JWTKeyCollection`:

1. **Add** new keys first — existing keys with the same `kid` are overwritten, so both old and new keys briefly coexist.
2. **Remove** stale keys that are no longer present in the updated JWKS, while preserving keys from other endpoints.

Because every ``OpenIDConnectClient`` shares the same underlying `JWTKeyCollection` (via `keyManager.keys`), rotated keys are immediately available for token verification everywhere — no cache invalidation or expiry logic required.

### JWT Validation

Token verification is a single call into the shared key collection:

```swift
let claims = try await keyManager.keys.verify(idToken, as: IDTokenClaims.self)
```

## Manual Operations

### Force Refresh

Manually refresh all registered endpoints:

```swift
let refreshedCount = await oauthKit.jwksRefreshService.forceRefreshAll()
print("Refreshed \(refreshedCount) JWKS endpoints")
```

### Register Additional Endpoints

Register custom JWKS endpoints not covered by built-in providers:

```swift
oauthKit.jwksRefreshService.registerEndpoint(
    jwksUri: "https://custom-provider.com/.well-known/jwks.json",
    issuer: "https://custom-provider.com"
)
```

### Query Key Manager State

```swift
// Check if keys are loaded for an endpoint
let hasKeys = await oauthKit.keyManager.hasKeys(
    for: "https://accounts.google.com/oauth2/v3/certs"
)

// List all endpoints with loaded keys
let endpoints = await oauthKit.keyManager.registeredEndpoints()
```

## Configuration Options

### JWKSRefreshService.Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `refreshInterval` | 30 minutes | How often to re-fetch every registered JWKS endpoint |
| `requestTimeout` | 30 seconds | HTTP timeout for JWKS requests |
| `maxRetries` | 3 | Maximum retry attempts for failed requests |
| `retryDelay` | 1 second | Base delay between retry attempts (multiplied by attempt number) |

## Error Handling

The service includes robust error handling:

- **Network failures**: Automatic retries with linear backoff
- **Invalid JWKS**: Detailed error logging; previously-loaded keys remain in the collection
- **Provider downtime**: Existing keys stay valid until the next successful refresh

## Best Practices

### Production Deployment

1. **Use ServiceLifecycle**: Ensure proper startup/shutdown handling
2. **Monitor logs**: Watch for JWKS refresh failures
3. **Configure alerts**: Set up monitoring for service health
4. **Tune intervals**: Adjust refresh intervals based on provider key rotation frequency

### Development

1. **Shorter intervals**: Use faster refresh for testing key rotation
2. **Force refresh**: Manually trigger refresh during testing
3. **Debug logging**: Enable verbose logging for troubleshooting

### Security

1. **HTTPS only**: JWKS endpoints should always use HTTPS
2. **Validate sources**: Only register trusted JWKS endpoints
3. **Monitor changes**: Log key rotations for security auditing