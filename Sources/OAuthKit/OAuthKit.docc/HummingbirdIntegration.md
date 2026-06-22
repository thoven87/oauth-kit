# Hummingbird Integration

Integrate OAuthKit with Hummingbird 2 using `HummingbirdAuth` for session management and `swift-configuration` for credential configuration.

## Overview

This guide shows how to add OAuth2 sign-in to a Hummingbird 2 application. It uses:

- **OAuthKit** for OAuth provider communication
- **HummingbirdAuth** for session middleware and request context protocols
- **swift-configuration** for reading credentials from environment variables and `.env` files
- **ServiceLifecycle** — `OAuthClientFactory` is a `Service`; JWKS keys stay fresh automatically

## Installation

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.0.0"),
    .package(url: "https://github.com/hummingbird-project/hummingbird-auth.git", from: "2.0.0"),
    .package(url: "https://github.com/thoven87/oauth-kit.git", from: "1.0.0"),
    .package(url: "https://github.com/apple/swift-configuration.git", from: "1.0.0"),
],
targets: [
    .executableTarget(
        name: "App",
        dependencies: [
            .product(name: "Configuration", package: "swift-configuration"),
            .product(name: "Hummingbird", package: "hummingbird"),
            .product(name: "HummingbirdAuth", package: "hummingbird-auth"),
            .product(name: "OAuthKit", package: "oauth-kit"),
        ]
    )
]
```

## Request Context and Session Model

Model the session as a typed enum nested inside `AppRequestContext`. A session is either
in-progress (handshake) or authenticated — never both:

```swift
import Hummingbird
import HummingbirdAuth

struct AppRequestContext: SessionRequestContext, RequestContext {

    enum Session: Sendable, Codable {

        /// Short-lived OAuth state — valid only during the redirect/callback round-trip.
        struct OAuthHandshake: Sendable, Codable {
            let state: String
            let codeVerifier: String?
            let provider: String
        }

        /// Persistent user identity after authentication succeeds.
        struct AuthenticatedUser: Sendable, Codable {
            let id: String
            let name: String
            let email: String
            let accessToken: String
            let refreshToken: String?
            /// Raw ID token — needed to build the provider end-session URL on logout.
            let idToken: String?
            /// Which provider authenticated this user ("google", "microsoft", etc.).
            let provider: String
        }

        case handshake(OAuthHandshake)
        case authenticated(AuthenticatedUser)

        var handshake: OAuthHandshake? {
            guard case .handshake(let h) = self else { return nil }
            return h
        }

        var authenticatedUser: AuthenticatedUser? {
            guard case .authenticated(let u) = self else { return nil }
            return u
        }
    }

    let sessions: SessionContext<Session>
    var coreContext: CoreRequestContextStorage

    init(source: ApplicationRequestContextSource) {
        sessions = .init()
        coreContext = .init(source: source)
    }
}
```

> **Why an enum?** `HummingbirdAuth` sessions store one typed value per cookie.
> Modelling the two possible states as cases makes illegal combinations impossible —
> a session in the handshake phase can't accidentally carry user data, and vice versa.
> It also means the OAuth `state` parameter is stored per-session, so there is no
> need for a global `Mutex` dictionary.

## Configuration

`swift-configuration` provides a `ConfigReader` that reads from command-line arguments,
environment variables, a `.env` file, and in-memory defaults — in priority order:

```swift
import Configuration
import Hummingbird

@main struct App {
    static func main() async throws {
        // Sources are queried in the order listed; first non-nil value wins.
        let reader = try await ConfigReader(providers: [
            CommandLineArgumentsProvider(),
            EnvironmentVariablesProvider(),
            EnvironmentVariablesProvider(environmentFilePath: ".env", allowMissing: true),
            InMemoryProvider(values: [
                "http.serverName": "my-app",
            ])
        ])
        let app = try await buildApplication(reader: reader)
        try await app.runService()
    }
}
```

`EnvironmentVariablesProvider` maps key components to environment variable names
automatically: `google.client_id` → `GOOGLE_CLIENT_ID`, `microsoft.redirect_uri` →
`MICROSOFT_REDIRECT_URI`. Scoped readers and env vars compose naturally:

```swift
let googleCfg = reader.scoped(to: "google")
let clientID  = googleCfg.string(forKey: "client_id")  // reads GOOGLE_CLIENT_ID
```

## Application Setup

Pass `oauthKit` directly to `Application` via `services:` — no external `ServiceGroup`
is required. `app.runService()` manages the HTTP server and all registered services together:

```swift
import Configuration
import Hummingbird
import HummingbirdAuth
import Logging
import OAuthKit

func buildApplication(reader: ConfigReader) async throws -> some ApplicationProtocol {
    let logger = Logger(label: "app")
    let oauthKit = OAuthClientFactory(logger: logger)
    let persist = MemoryPersistDriver()

    let router = Router(context: AppRequestContext.self)
    router.addMiddleware {
        LogRequestsMiddleware(.info)
        SessionMiddleware(storage: persist)
    }

    configureOAuthRoutes(router, reader: reader, oauthKit: oauthKit)
    configureProtectedRoutes(router)

    // oauthKit is a Service — adding it via `services:` keeps JWKS keys refreshed
    // automatically alongside the HTTP server.
    return Application(
        router: router,
        configuration: ApplicationConfiguration(reader: reader.scoped(to: "http")),
        services: [oauthKit],
        logger: logger
    )
}
```

## OAuth Routes

Because OAuth handshake state is stored in the session cookie, no global `Mutex` dictionary
is needed. Each browser tab has its own session and therefore its own isolated OAuth state.

```swift
func configureOAuthRoutes(
    _ router: Router<AppRequestContext>,
    reader: ConfigReader,
    oauthKit: OAuthClientFactory
) {
    // Step 1 — redirect the browser to the provider.
    router.get("auth/:provider") { request, context async throws -> Response in
        let provider = try context.parameters.require("provider")
        let state = UUID().uuidString

        let (authURL, codeVerifier) = try await makeAuthURL(
            provider: provider,
            state: state,
            reader: reader,
            oauthKit: oauthKit
        )

        // Store the handshake in the session — replaces any previous state.
        context.sessions.setSession(.handshake(.init(
            state: state,
            codeVerifier: codeVerifier,
            provider: provider
        )))

        return .redirect(to: authURL.absoluteString, type: .normal)
    }

    // Step 2 — handle the provider callback.
    router.get("auth/:provider/callback") { request, context async throws -> Response in
        let queryParams = request.uri.queryParameters

        guard let handshake = context.sessions.session?.handshake else {
            throw HTTPError(.badRequest, message: "No OAuth session in progress")
        }
        guard handshake.state == queryParams.get("state") else {
            throw HTTPError(.badRequest, message: "Invalid or expired state parameter")
        }
        guard let code = queryParams.get("code") else {
            throw HTTPError(.badRequest, message: "Authorization code required")
        }

        let (tokenResponse, claims) = try await exchangeCode(
            provider: handshake.provider,
            code: code,
            codeVerifier: handshake.codeVerifier,
            reader: reader,
            oauthKit: oauthKit
        )

        context.sessions.setSession(.authenticated(.init(
            id: claims?.sub?.value ?? UUID().uuidString,
            name: claims?.name ?? "Unknown",
            email: claims?.email ?? "",
            accessToken: tokenResponse.accessToken,
            refreshToken: tokenResponse.refreshToken,
            idToken: tokenResponse.idToken,
            provider: handshake.provider
        )))

        return .redirect(to: "/dashboard", type: .normal)
    }

    // Logout — clear the local session, then optionally redirect to the provider's
    // end-session endpoint (SSO logout) if the provider supports it.
    router.post("logout") { request, context async throws -> Response in
        let user = context.sessions.session?.authenticatedUser
        context.sessions.clearSession()

        if let user, let idToken = user.idToken,
           let endURL = try? await makeEndSessionURL(
                provider: user.provider,
                idToken: idToken,
                postLogoutRedirectURI: "http://localhost:8080/",
                reader: reader,
                oauthKit: oauthKit
           ) {
            return .redirect(to: endURL.absoluteString, type: .normal)
        }

        return .redirect(to: "/", type: .normal)
    }
}
```

### Provider helpers

```swift
/// A small extension so missing config keys throw instead of returning nil.
private extension ConfigReader {
    func require(_ key: String) throws -> String {
        guard let value = string(forKey: key), !value.isEmpty else {
            throw OAuth2Error.configurationError("Missing required configuration key: '\(key)'")
        }
        return value
    }
}

/// Build the end-session (SSO logout) URL.
/// Returns `nil` for providers that don't advertise `end_session_endpoint` (e.g. GitHub).
func makeEndSessionURL(
    provider: String,
    idToken: String,
    postLogoutRedirectURI: String,
    reader: ConfigReader,
    oauthKit: OAuthClientFactory
) async throws -> URL? {
    switch provider.lowercased() {
    case "google":
        let cfg = reader.scoped(to: "google")
        let p = try await oauthKit.googleProvider(
            clientID: try cfg.require("client_id"),
            clientSecret: try cfg.require("client_secret"),
            redirectURI: try cfg.require("redirect_uri")
        )
        return try? p.revokeToken(
            idToken: idToken,
            postLogoutRedirectURI: postLogoutRedirectURI,
            state: nil
        )
    case "microsoft":
        let cfg = reader.scoped(to: "microsoft")
        let p = try await oauthKit.microsoftProvider(
            clientID: try cfg.require("client_id"),
            clientSecret: try cfg.require("client_secret"),
            redirectURI: try cfg.require("redirect_uri"),
            tenantKind: .common
        )
        return try? p.endSessionURL(
            idToken: idToken,
            postLogoutRedirectURI: postLogoutRedirectURI
        )
    default:
        return nil
    }
}

func makeAuthURL(
    provider: String,
    state: String,
    reader: ConfigReader,
    oauthKit: OAuthClientFactory
) async throws -> (URL, String?) {
    switch provider.lowercased() {
    case "google":
        let cfg = reader.scoped(to: "google")
        let p = try await oauthKit.googleProvider(
            clientID: try cfg.require("client_id"),
            clientSecret: try cfg.require("client_secret"),
            redirectURI: try cfg.require("redirect_uri")
        )
        let (url, verifier) = try p.generateAuthURL(
            state: state,
            scopes: ["openid", "profile", "email"]
        )
        return (url, verifier)

    case "microsoft":
        let cfg = reader.scoped(to: "microsoft")
        let p = try await oauthKit.microsoftProvider(
            clientID: try cfg.require("client_id"),
            clientSecret: try cfg.require("client_secret"),
            redirectURI: try cfg.require("redirect_uri"),
            tenantKind: .common
        )
        let (url, verifier) = try p.generateAuthorizationURL(
            state: state,
            scopes: ["openid", "profile", "email", "User.Read"]
        )
        return (url, verifier)

    case "github":
        let cfg = reader.scoped(to: "github")
        let p = oauthKit.githubProvider(
            clientID: try cfg.require("client_id"),
            clientSecret: try cfg.require("client_secret"),
            redirectURI: try cfg.require("redirect_uri")
        )
        let (url, verifier) = try p.signInURL(
            state: state,
            scopes: ["user:email", "read:user"]
        )
        return (url, verifier)

    default:
        throw HTTPError(.badRequest, message: "Unsupported provider: \(provider)")
    }
}

func exchangeCode(
    provider: String,
    code: String,
    codeVerifier: String?,
    reader: ConfigReader,
    oauthKit: OAuthClientFactory
) async throws -> (TokenResponse, IDTokenClaims?) {
    switch provider.lowercased() {
    case "google":
        let cfg = reader.scoped(to: "google")
        let p = try await oauthKit.googleProvider(
            clientID: try cfg.require("client_id"),
            clientSecret: try cfg.require("client_secret"),
            redirectURI: try cfg.require("redirect_uri")
        )
        let (tokenResponse, claims) = try await p.exchangeCode(
            code: code, codeVerifier: codeVerifier
        )
        return (tokenResponse, claims)

    case "microsoft":
        let cfg = reader.scoped(to: "microsoft")
        let p = try await oauthKit.microsoftProvider(
            clientID: try cfg.require("client_id"),
            clientSecret: try cfg.require("client_secret"),
            redirectURI: try cfg.require("redirect_uri"),
            tenantKind: .common
        )
        let (tokenResponse, claims) = try await p.exchangeCode(
            code: code, codeVerifier: codeVerifier
        )
        return (tokenResponse, claims)

    case "github":
        let cfg = reader.scoped(to: "github")
        let p = oauthKit.githubProvider(
            clientID: try cfg.require("client_id"),
            clientSecret: try cfg.require("client_secret"),
            redirectURI: try cfg.require("redirect_uri")
        )
        let tokenResponse = try await p.exchangeCode(
            code: code, codeVerifier: codeVerifier
        )
        return (tokenResponse, nil)

    default:
        throw HTTPError(.badRequest, message: "Unsupported provider: \(provider)")
    }
}
```

## Protected Routes

Check the session's `authenticatedUser` to guard routes:

```swift
func configureProtectedRoutes(_ router: Router<AppRequestContext>) {
    router.group("dashboard").get { request, context async throws -> Response in
        guard let user = context.sessions.session?.authenticatedUser else {
            return .redirect(to: "/", type: .normal)
        }
        return Response(
            status: .ok,
            body: .init(byteBuffer: .init(string: "Welcome, \(user.name)!"))
        )
    }

    router.group("api").get("user") { request, context async throws -> AppRequestContext.Session.AuthenticatedUser in
        guard let user = context.sessions.session?.authenticatedUser else {
            throw HTTPError(.unauthorized)
        }
        return user
    }
}
```

## Environment Configuration

`EnvironmentVariablesProvider` converts dot-separated config keys to uppercase environment
variable names. The `.env` file uses the same names:

```bash
# .env — never commit this file
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8080/auth/google/callback

MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
MICROSOFT_REDIRECT_URI=http://localhost:8080/auth/microsoft/callback

GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_REDIRECT_URI=http://localhost:8080/auth/github/callback

# Hummingbird HTTP server
HTTP_HOST=0.0.0.0
HTTP_PORT=8080
```

## Token Refresh

Refresh expired access tokens in a middleware. Inject the scoped `ConfigReader` at
initialisation time — `ConfigReader` is `Sendable` so it is safe to store:

```swift
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
                let p = try await oauthKit.googleProvider(
                    clientID: try providerConfig.require("client_id"),
                    clientSecret: try providerConfig.require("client_secret"),
                    redirectURI: try providerConfig.require("redirect_uri")
                )
                let newTokens = try await p.refreshAccessToken(refreshToken: refreshToken)
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
            }
        }
        return try await next(request, context)
    }
}
```

Wire it into a route group:

```swift
router.group()
    .add(middleware: TokenRefreshMiddleware(
        oauthKit: oauthKit,
        providerConfig: reader.scoped(to: "google")
    ))
```

## Error Handling

Map `OAuth2Error` to HTTP responses:

```swift
extension OAuth2Error: HTTPResponseError {
    public var status: HTTPResponse.Status {
        switch self {
        case .configurationError:   return .internalServerError
        case .networkError:         return .badGateway
        case .responseError,
             .invalidResponse:      return .badRequest
        case .tokenError:           return .unauthorized
        default:                    return .internalServerError
        }
    }

    public var headers: HTTPFields { [:] }
}
```

## Security Best Practices

1. **HTTPS only** — never serve OAuth callbacks over plain HTTP in production
2. **State validation** — the `state` parameter is stored in the session and checked on callback, preventing CSRF by design
3. **Short session expiry** — set `defaultSessionExpiration` on `SessionMiddleware` and call `setSession(_:expiresIn:)` with an explicit TTL
4. **Persistent sessions** — replace `MemoryPersistDriver` with a Redis-backed driver in production so sessions survive restarts
5. **Secure cookies** — configure `SessionCookieParameters` with `secure: true` and `sameSite: .lax` in production. OAuth callbacks are top-level cross-site GET redirects; `sameSite: .strict` prevents the browser from sending the session cookie on the callback and breaks the flow
6. **Never log tokens** — access and refresh tokens are credentials; keep them out of log output
