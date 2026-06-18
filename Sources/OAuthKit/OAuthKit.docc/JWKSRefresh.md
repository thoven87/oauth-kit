# JWKS Refresh Service

Automatically refresh JSON Web Key Sets (JWKS) from OpenID Connect providers to ensure JWT signature verification always uses current public keys.

## Overview

The JWKS Refresh Service provides automatic rotation of public keys used for JWT signature verification in OAuth and OpenID Connect flows. This ensures that your application can handle key rotations performed by identity providers without manual intervention.

## Key Components

- **JWKSKeyManager**: Manages one isolated `JWTKeyCollection` per JWKS endpoint, preventing cross-provider `kid` collisions and enabling atomic per-endpoint key rotation.
- **JWKSRefreshService**: Background service that periodically fetches fresh JWKS documents, honouring each server's `Cache-Control: max-age` header so endpoints refresh on their own schedule.

## Quick Start

### Basic Setup

```swift
import OAuthKit
import ServiceLifecycle

// Create OAuthKit — a JWKSKeyManager and refresh service are created automatically
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

You can customize the refresh behaviour:

```swift
let refreshConfig = JWKSRefreshService.Configuration(
    refreshInterval: .seconds(900),  // ceiling — server Cache-Control may be shorter
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

When you create OpenID Connect clients or providers, their JWKS endpoints are automatically registered with the refresh service:

```swift
let oauthKit = OAuthClientFactory()

// This automatically registers the Google JWKS endpoint
let googleProvider = try await oauthKit.googleProvider(
    clientID: "client-id",
    clientSecret: "client-secret",
    redirectURI: "redirect-uri"
)
```

### Per-Endpoint Key Rotation

Each JWKS endpoint gets its own isolated `JWTKeyCollection`. When a fresh JWKS is fetched:

1. A new `JWTKeyCollection` is built from the fetched keys entirely before any shared state is touched.
2. The new collection atomically replaces the previous one for that endpoint in a single lock-protected assignment.

Because each endpoint is isolated, two providers that happen to publish the same `kid` value can never overwrite each other's keys.

### Cache-Driven Scheduling

After each successful fetch the service reads the server's `Cache-Control: max-age` response header and uses that value as the next refresh interval, capped at the configured `refreshInterval`. When no cache header is present, `refreshInterval` is used directly.

This means different endpoints may refresh on very different schedules — a provider advertising `max-age=86400` (24 h) won't be fetched unnecessarily every 30 minutes.

### JWT Validation

Token verification goes through the ``OpenIDConnectClient``, which looks up the correct key collection for its issuer automatically:

```swift
let claims = try await oidcClient.validateIDToken(idToken)
```

## Manual Operations

### Force Refresh

Manually refresh all registered endpoints — useful when a JWT arrives with an unknown `kid`:

```swift
let refreshedCount = await oauthKit.forceRefreshAll()
print("Refreshed \(refreshedCount) JWKS endpoints")
```

## Configuration Options

### JWKSRefreshService.Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `refreshInterval` | 30 minutes | Maximum interval between refreshes. Shortened automatically when the server returns a smaller `Cache-Control: max-age`. |
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
4. **Tune intervals**: Adjust `refreshInterval` as a ceiling; most providers will drive shorter cycles via `Cache-Control`

### Development

1. **Shorter intervals**: Use a smaller `refreshInterval` for testing key rotation
2. **Force refresh**: Call `forceRefreshAll()` to trigger an immediate refresh during testing
3. **Debug logging**: Enable verbose logging for troubleshooting

### Security

1. **HTTPS only**: JWKS endpoints should always use HTTPS
2. **Validate sources**: Only register trusted JWKS endpoints
3. **Monitor changes**: Log key rotations for security auditing
