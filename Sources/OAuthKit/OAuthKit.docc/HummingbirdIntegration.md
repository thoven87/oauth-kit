# Hummingbird Integration

Integrate OAuthKit with Hummingbird 2 using `HummingbirdAuth` for session management.

## Overview

This guide shows how to add OAuth2 sign-in to a Hummingbird 2 application. It uses:

- **OAuthKit** for OAuth provider communication
- **HummingbirdAuth** for session middleware, authenticator middleware, and request context protocols
- **ServiceLifecycle** to wire services (OAuthKit's `OAuthClientFactory` is itself a `Service`)

## Installation

```swift
// Package.swift
dependencies: [
    .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.0.0"),
    .package(url: "https://github.com/hummingbird-project/hummingbird-auth.git", from: "2.0.0"),
    .package(url: "https://github.com/thoven87/oauth-kit.git", from: "1.0.0"),
],
targets: [
    .executableTarget(
        name: "App",
        dependencies: [
            .product(name: "Hummingbird", package: "hummingbird"),
            .product(name: "HummingbirdAuth", package: "hummingbird-auth"),
            .product(name: "OAuthKit", package: "oauth-kit"),
        ]
    )
]
```

## Session Model

`HummingbirdAuth`'s sessions store **one typed value** per request. Define a `UserSession` struct that holds everything you want to persist across requests:

```swift
import HummingbirdAuth
import OAuthKit

/// The authenticated user stored in the session.
/// `Sendable` (not `Authenticatable`) — the old HB1 protocol is removed.
struct UserSession: Codable, Sendable {
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

/// Short-lived OAuth handshake data stored separately (e.g. a signed cookie
/// or an in-process Mutex dictionary) — NOT in the user session.
struct OAuthHandshake: Sendable {
    let state: String
    let codeVerifier: String?
    let provider: String
}

/// Request context: session key = String (cookie value), identity = UserSession.
typealias AppRequestContext = BasicSessionRequestContext<String, UserSession>
```

> **Why a separate `OAuthHandshake`?** Sessions in HummingbirdAuth store one value; a dictionary-style API does not exist. Short-lived OAuth state (the `state` and `code_verifier` parameters) should live outside the session — for example in a signed cookie or in a server-side `Mutex`-protected dictionary that is cleaned up after the callback.

## Application Setup

```swift
import Hummingbird
import HummingbirdAuth
import OAuthKit
import ServiceLifecycle
import Synchronization

// In-process store for pending OAuth handshakes, keyed by `state` parameter.
// Replace with Redis or a database in production.
let pendingHandshakes: Mutex<[String: OAuthHandshake]> = Mutex([:])

func buildApplication() async throws -> some ApplicationProtocol {
    // Hummingbird's built-in Environment merges process env with a .env file.
    // Keys are lowercased automatically; require(_:) throws instead of crashing.
    let env = try await Environment().merging(with: Environment.dotEnv(".env"))
    let oauthKit = OAuthClientFactory()
    let persist = MemoryPersistDriver()
    let sessionStorage = SessionStorage<UserSession>(persist)

    let router = Router(context: AppRequestContext.self)
    router.addMiddleware {
        LogRequestsMiddleware(.info)
        SessionMiddleware(storage: sessionStorage)
    }

    configureOAuthRoutes(router, oauthKit: oauthKit)
    configureProtectedRoutes(router)

    let app = Application(router: router, configuration: .init(address: .hostname("127.0.0.1", port: 8080)))

    // OAuthClientFactory is a Service — add it to the ServiceGroup so JWKS
    // keys are kept refreshed automatically.
    return ServiceGroup(
        configuration: .init(
            services: [oauthKit, app],
            gracefulShutdownSignals: [.sigterm, .sigint],
            logger: Logger(label: "app")
        )
    )
}
```

## OAuth Routes

### Initiating the flow

```swift
func configureOAuthRoutes(
    _ router: Router<AppRequestContext>,
    oauthKit: OAuthClientFactory
) {
    // Step 1 — redirect the browser to the provider.
    router.get("auth/:provider") { request, context async throws -> Response in
        let providerName = try context.parameters.require("provider")

        let state = UUID().uuidString
        let (authURL, codeVerifier) = try await makeAuthURL(
            provider: providerName,
            state: state,
            oauthKit: oauthKit
        )

        // Store the handshake state until the callback arrives.
        pendingHandshakes.withLock {
            $0[state] = OAuthHandshake(
                state: state,
                codeVerifier: codeVerifier,
                provider: providerName
            )
        }

        return Response(status: .seeOther, headers: [.location: authURL.absoluteString])
    }

    // Step 2 — handle the provider callback.
    router.get("auth/:provider/callback") { request, context async throws -> Response in
        let queryParams = request.uri.queryParameters

        guard let receivedState = queryParams.get("state"),
              let handshake = pendingHandshakes.withLock({ $0.removeValue(forKey: receivedState) })
        else {
            throw HTTPError(.badRequest, message: "Invalid or expired state parameter")
        }

        guard let code = queryParams.get("code") else {
            throw HTTPError(.badRequest, message: "Authorization code required")
        }

        let (tokenResponse, claims) = try await exchangeCode(
            provider: handshake.provider,
            code: code,
            codeVerifier: handshake.codeVerifier,
            oauthKit: oauthKit
        )

        let session = UserSession(
            id: claims?.sub?.value ?? UUID().uuidString,
            name: claims?.name ?? "Unknown",
            email: claims?.email ?? "",
            accessToken: tokenResponse.accessToken,
            refreshToken: tokenResponse.refreshToken,
            idToken: tokenResponse.idToken,
            provider: handshake.provider
        )

        // Store the user session — one typed value, no dictionary.
        context.sessions.setSession(session, expiresIn: .minutes(30))

        return Response(status: .seeOther, headers: [.location: "/dashboard"])
    }

    // Logout — two layers:
    // 1. Clear the local session (always).
    // 2. Redirect to the provider's end-session endpoint if available (SSO logout),
    //    so the provider also invalidates the session on its side.
    router.post("logout") { request, context async throws -> Response in
        let session = context.sessions.session
        context.sessions.clearSession()

        // If we stored an ID token, build the provider end-session URL.
        // endSessionURL uses the OIDC discovery `end_session_endpoint`;
        // not all providers support this (GitHub doesn't, Google/Microsoft do).
        if let idToken = session?.idToken,
           let providerName = session?.provider {
            if let endSessionURL = try? await makeEndSessionURL(
                provider: providerName,
                idToken: idToken,
                postLogoutRedirectURI: "http://localhost:8080/",
                oauthKit: oauthKit
            ) {
                return Response(status: .seeOther, headers: [.location: endSessionURL.absoluteString])
            }
        }

        return Response(status: .seeOther, headers: [.location: "/"])
    }
}
```

### Provider helpers

```swift
/// Build the provider end-session (SSO logout) URL.
/// Only OIDC providers that advertise `end_session_endpoint` in their
/// discovery document support this — GitHub and other OAuth-only providers
/// do not. Falls back to `nil` so the caller can skip the redirect.
func makeEndSessionURL(
    provider: String,
    idToken: String,
    postLogoutRedirectURI: String,
    oauthKit: OAuthClientFactory
) async throws -> URL? {
    let env = try await Environment().merging(with: Environment.dotEnv(".env"))
    switch provider.lowercased() {
    case "google":
        let p = try await oauthKit.googleProvider(
            clientID: try env.require("google_client_id"),
            clientSecret: try env.require("google_client_secret"),
            redirectURI: try env.require("google_redirect_uri")
        )
        return try? p.revokeToken(
            idToken: idToken,
            postLogoutRedirectURI: postLogoutRedirectURI,
            state: nil
        )
    case "microsoft":
        let p = try await oauthKit.microsoftProvider(
            clientID: try env.require("microsoft_client_id"),
            clientSecret: try env.require("microsoft_client_secret"),
            redirectURI: try env.require("microsoft_redirect_uri"),
            tenantKind: .common
        )
        return try? p.endSessionURL(
            idToken: idToken,
            postLogoutRedirectURI: postLogoutRedirectURI
        )
    default:
        return nil  // provider doesn't support end-session
    }
}

func makeAuthURL(
    provider: String,
    state: String,
    oauthKit: OAuthClientFactory
) async throws -> (URL, String?) {
    // Environment is Hummingbird's built-in type.
    // Keys are lowercased; require(_:) throws Environment.Error if missing.
    let env = try await Environment().merging(with: Environment.dotEnv(".env"))

    switch provider.lowercased() {
    case "google":
        let p = try await oauthKit.googleProvider(
            clientID: try env.require("google_client_id"),
            clientSecret: try env.require("google_client_secret"),
            redirectURI: try env.require("google_redirect_uri")
        )
        let (url, verifier) = try p.generateAuthURL(
            state: state,
            scopes: ["openid", "profile", "email"]
        )
        return (url, verifier)

    case "microsoft":
        let p = try await oauthKit.microsoftProvider(
            clientID: try env.require("microsoft_client_id"),
            clientSecret: try env.require("microsoft_client_secret"),
            redirectURI: try env.require("microsoft_redirect_uri"),
            tenantKind: .common
        )
        let (url, verifier) = try p.generateAuthorizationURL(
            state: state,
            scopes: ["openid", "profile", "email", "User.Read"]
        )
        return (url, verifier)

    case "github":
        let p = oauthKit.githubProvider(
            clientID: try env.require("github_client_id"),
            clientSecret: try env.require("github_client_secret"),
            redirectURI: try env.require("github_redirect_uri")
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
    oauthKit: OAuthClientFactory
) async throws -> (TokenResponse, IDTokenClaims?) {
    let env = try await Environment().merging(with: Environment.dotEnv(".env"))

    switch provider.lowercased() {
    case "google":
        let p = try await oauthKit.googleProvider(
            clientID: try env.require("google_client_id"),
            clientSecret: try env.require("google_client_secret"),
            redirectURI: try env.require("google_redirect_uri")
        )
        let (tokenResponse, claims) = try await p.exchangeCode(
            code: code, codeVerifier: codeVerifier
        )
        return (tokenResponse, claims)

    case "microsoft":
        let p = try await oauthKit.microsoftProvider(
            clientID: try env.require("microsoft_client_id"),
            clientSecret: try env.require("microsoft_client_secret"),
            redirectURI: try env.require("microsoft_redirect_uri"),
            tenantKind: .common
        )
        let (tokenResponse, claims) = try await p.exchangeCode(
            code: code, codeVerifier: codeVerifier
        )
        return (tokenResponse, claims)

    case "github":
        let p = oauthKit.githubProvider(
            clientID: try env.require("github_client_id"),
            clientSecret: try env.require("github_client_secret"),
            redirectURI: try env.require("github_redirect_uri")
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

Use `SessionAuthenticator` to restore the user from the session on each request:

```swift
func configureProtectedRoutes(_ router: Router<AppRequestContext>) {
    let protected = router.group()
        .add(middleware: SessionAuthenticator { (id: String, context) async throws -> UserSession? in
            // Load from your database using `id` (the session cookie value).
            // In this example we return the session value stored by setSession(_:).
            return context.sessions.session
        })
        .add(middleware: IsAuthenticatedMiddleware<AppRequestContext>())

    protected.get("dashboard") { request, context async throws -> Response in
        let user = try context.requireIdentity()
        return Response(
            status: .ok,
            body: .init(byteBuffer: .init(string: "Welcome, \(user.name)!"))
        )
    }

    protected.get("api/user") { request, context async throws -> UserSession in
        try context.requireIdentity()
    }
}
```

## Environment Configuration

Hummingbird ships a built-in `Environment` type that reads process environment
variables and can merge in a `.env` file. Keys are **lowercased** automatically,
and `require(_:)` throws `Environment.Error` (instead of calling `fatalError`):

```swift
// Read process env merged with .env file (async because of file I/O).
let env = try await Environment().merging(with: Environment.dotEnv(".env"))

// Access optionally:
let id = env.get("google_client_id")

// Access required (throws if missing):
let secret = try env.require("google_client_secret")
```

```bash
# .env (never commit this file)
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8080/auth/google/callback

MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
MICROSOFT_REDIRECT_URI=http://localhost:8080/auth/microsoft/callback

GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_REDIRECT_URI=http://localhost:8080/auth/github/callback
```

## Token Refresh

Refresh expired access tokens in a middleware:

```swift
struct TokenRefreshMiddleware<Context: SessionRequestContext>: RouterMiddleware
where Context.Session == UserSession {

    let oauthKit: OAuthClientFactory
    /// OAuth credentials injected at init time — Environment can't be awaited
    /// inside a middleware `handle` call, so pass values in up front.
    let clientID: String
    let clientSecret: String
    let redirectURI: String

    func handle(
        _ request: Request,
        context: Context,
        next: (Request, Context) async throws -> Response
    ) async throws -> Response {
        // Only refresh if there is an active session with a refresh token.
        if var session = context.sessions.session,
           let refreshToken = session.refreshToken {
            do {
                // Build the provider using the credentials injected at init time.
                let googleProvider = try await oauthKit.googleProvider(
                    clientID: clientID,
                    clientSecret: clientSecret,
                    redirectURI: redirectURI
                )
                let newTokens = try await googleProvider.refreshAccessToken(
                    refreshToken: refreshToken
                )
                session = UserSession(
                    id: session.id,
                    name: session.name,
                    email: session.email,
                    accessToken: newTokens.accessToken,
                    refreshToken: newTokens.refreshToken ?? session.refreshToken,
                    idToken: newTokens.idToken ?? session.idToken,
                    provider: session.provider
                )
                context.sessions.setSession(session, expiresIn: .minutes(30))
            } catch {
                context.logger.warning("Token refresh failed: \(error)")
            }
        }
        return try await next(request, context)
    }
}
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
2. **State validation** — always verify the `state` parameter to prevent CSRF; the `pendingHandshakes` dictionary above provides this
3. **Short-lived handshake store** — expire entries in `pendingHandshakes` after ~10 minutes to avoid memory leaks
4. **Persistent sessions** — replace `MemoryPersistDriver` with a Redis-backed driver in production so sessions survive restarts
5. **Secure cookies** — configure `SessionCookieParameters` with `secure: true` and `sameSite: .strict` in production
6. **Never log tokens** — access and refresh tokens are credentials; keep them out of log output
