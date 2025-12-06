# Hummingbird Integration

Learn how to integrate OAuthKit with the Hummingbird web framework using proper session management.

## Overview

OAuthKit provides excellent integration with Hummingbird, Swift's modern, lightweight web framework. This guide demonstrates how to implement OAuth2 authentication in your Hummingbird applications using `HummingbirdAuth` for session management and proper async/await patterns.

## Basic Setup

### Installation

Add both OAuthKit and Hummingbird dependencies to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/hummingbird-project/hummingbird.git", from: "2.0.0"),
    .package(url: "https://github.com/hummingbird-project/hummingbird-auth.git", from: "2.0.0"),
    .package(url: "https://github.com/thoven87/oauth-kit.git", from: "1.0.0")
],
targets: [
    .executableTarget(
        name: "App",
        dependencies: [
            .product(name: "Hummingbird", package: "hummingbird"),
            .product(name: "HummingbirdAuth", package: "hummingbird-auth"),
            .product(name: "OAuthKit", package: "oauth-kit")
        ]
    )
]
```

### Application Configuration

Set up your Hummingbird application with OAuth support:

```swift
import Hummingbird
import HummingbirdAuth
import OAuthKit

struct User: Authenticatable, Codable, Sendable {
    let id: String
    let name: String
    let email: String
}

typealias AppRequestContext = BasicSessionRequestContext<String, User>

func buildApplication(configuration: ApplicationConfiguration) async throws -> some ApplicationProtocol {
    let router = Router(context: AppRequestContext.self)
    
    // Create OAuthKit factory
    let oauthFactory = OAuthClientFactory()
    
    // Session storage (use appropriate storage for production)
    let sessionStorage = MemorySessionStorage<String, User>(
        expiration: .minutes(30)
    )
    
    // Add middleware
    router.addMiddleware {
        LogRequestsMiddleware(.info)
        CORSMiddleware()
        SessionMiddleware(storage: sessionStorage)
    }
    
    // Configure OAuth routes
    try await configureOAuthRoutes(router, oauthFactory: oauthFactory)
    
    var application = Application(
        router: router,
        server: .http1(),
        configuration: configuration
    )
    return application
}
```

## OAuth Routes Implementation

### Authorization Flow

```swift
import Hummingbird
import HummingbirdAuth
import OAuthKit

func configureOAuthRoutes(
    _ router: Router<AppRequestContext>,
    oauthFactory: OAuthClientFactory
) async throws {
    
    // OAuth initialization routes
    router.get("auth/:provider") { request, context async throws -> Response in
        guard let providerName = context.parameters.get("provider") else {
            throw HTTPError(.badRequest, reason: "Provider parameter required")
        }
        
        let provider = try await createOAuthProvider(providerName, factory: oauthFactory)
        let state = UUID().uuidString
        let (authURL, codeVerifier) = try provider.generateAuthURL(
            state: state,
            scopes: getScopesForProvider(providerName)
        )
        
        // Store OAuth state in session
        context.sessions.setSession("oauth_state", state)
        context.sessions.setSession("code_verifier", codeVerifier ?? "")
        context.sessions.setSession("provider", providerName)
        
        return Response(
            status: .seeOther,
            headers: [.location: authURL.absoluteString]
        )
    }
    
    // OAuth callback handling
    router.get("auth/:provider/callback") { request, context async throws -> Response in
        guard let providerName = context.parameters.get("provider") else {
            throw HTTPError(.badRequest, reason: "Provider parameter required")
        }
        
        let queryParams = request.uri.queryParameters
        
        // Verify state parameter
        guard let receivedState = queryParams.get("state"),
              let storedState: String = context.sessions.getSession("oauth_state"),
              receivedState == storedState else {
            throw HTTPError(.badRequest, reason: "Invalid state parameter")
        }
        
        guard let code = queryParams.get("code") else {
            throw HTTPError(.badRequest, reason: "Authorization code required")
        }
        
        let codeVerifier: String? = context.sessions.getSession("code_verifier")
        let provider = try await createOAuthProvider(providerName, factory: oauthFactory)
        
        do {
            let (tokenResponse, claims) = try await provider.exchangeCode(
                code: code,
                codeVerifier: codeVerifier?.isEmpty == false ? codeVerifier : nil
            )
            
            // Create user from OAuth response
            let user = User(
                id: claims?.sub?.value ?? UUID().uuidString,
                name: claims?.name ?? "Unknown User",
                email: claims?.email ?? ""
            )
            
            // Set authenticated user session
            context.sessions.setSession(user)
            
            // Store tokens for API access
            context.sessions.setSession("access_token", tokenResponse.accessToken)
            if let refreshToken = tokenResponse.refreshToken {
                context.sessions.setSession("refresh_token", refreshToken)
            }
            
            // Clear OAuth temporary data
            context.sessions.clearSession("oauth_state")
            context.sessions.clearSession("code_verifier")
            context.sessions.clearSession("provider")
            
            return Response(
                status: .seeOther,
                headers: [.location: "/dashboard"]
            )
            
        } catch {
            context.logger.error("OAuth token exchange failed: \(error)")
            throw HTTPError(.unauthorized, reason: "Authentication failed")
        }
    }
    
    // Logout
    router.post("logout") { request, context async throws -> Response in
        context.sessions.clearAll()
        return Response(
            status: .seeOther,
            headers: [.location: "/"]
        )
    }
}
```

### Protected Routes

Create protected routes using session authentication:

```swift
func configureProtectedRoutes(_ router: Router<AppRequestContext>) {
    let protected = router.group()
        .add(middleware: SessionAuthenticator<String, User> { id, context in
            // In a real app, you'd fetch from database
            return context.sessions.getSession(id)
        })
    
    // Dashboard route
    protected.get("dashboard") { request, context async throws -> DashboardResponse in
        let user = try context.requireIdentity()
        return DashboardResponse(
            message: "Welcome, \(user.name)!",
            user: user
        )
    }
    
    // Profile route with API calls
    protected.get("profile") { request, context async throws -> UserProfileResponse in
        let user = try context.requireIdentity()
        
        // Make authenticated API call using stored token
        guard let accessToken: String = context.sessions.getSession("access_token") else {
            throw HTTPError(.unauthorized, reason: "No access token available")
        }
        
        let profile = try await fetchUserProfile(accessToken: accessToken)
        return UserProfileResponse(user: user, profile: profile)
    }
    
    // API endpoint
    protected.get("api/user") { request, context async throws -> User in
        return try context.requireIdentity()
    }
}

struct DashboardResponse: ResponseCodable {
    let message: String
    let user: User
}

struct UserProfileResponse: ResponseCodable {
    let user: User
    let profile: [String: String]
}
```

## Provider Factory

Create OAuth providers for different services:

```swift
func createOAuthProvider(
    _ name: String,
    factory: OAuthClientFactory
) async throws -> any OAuth2Provider {
    switch name.lowercased() {
        
    let env = Environment().merging(with: .dotEnv("../env"))    
    
    case "google":
        return try await factory.googleProvider(
            clientID: env.get("GOOGLE_CLIENT_ID")!,
            clientSecret: env.get("GOOGLE_CLIENT_SECRET")!,
            redirectURI: env.get("GOOGLE_REDIRECT_URI")!
        )
    case "microsoft":
        return try await factory.microsoftProvider(
            clientID: env.get("MICROSOFT_CLIENT_ID")!,
            clientSecret: env.get("MICROSOFT_CLIENT_SECRET")!,
            redirectURI: env.get("MICROSOFT_REDIRECT_URI")!,
            tenantID: .common
        )
    case "github":
        return try await factory.githubProvider(
            clientID: env.get("GITHUB_CLIENT_ID")!,
            clientSecret: env.get("GITHUB_CLIENT_SECRET")!,
            redirectURI: env.get("GITHUB_REDIRECT_URI")!
        )
    case "discord":
        return try await factory.discordProvider(
            clientID: env.get("DISCORD_CLIENT_ID")!,
            clientSecret: env.get("DISCORD_CLIENT_SECRET")!,
            redirectURI: env.get("DISCORD_REDIRECT_URI")!
        )
    default:
        throw HTTPError(.badRequest, reason: "Unsupported provider: \(name)")
    }
}

func getScopesForProvider(_ provider: String) -> [String] {
    switch provider.lowercased() {
    case "google":
        return ["openid", "profile", "email"]
    case "microsoft":
        return ["openid", "profile", "email", "User.Read"]
    case "github":
        return ["user:email", "read:user"]
    case "discord":
        return ["identify", "email"]
    default:
        return ["openid", "profile", "email"]
    }
}
```

## Session Extension Helpers

Create convenient session extensions:

```swift
extension SessionProtocol {
    func setSession<T>(_ key: String, _ value: T) where T: Codable {
        self.setSession(SessionData(key: key, value: value))
    }
    
    func getSession<T>(_ key: String) -> T? where T: Codable {
        guard let data: SessionData<T> = self.getSession(key) else { return nil }
        return data.value
    }
    
    func clearSession(_ key: String) {
        self.clearSession(key)
    }
    
    func clearAll() {
        // Implementation depends on your session storage
    }
}

struct SessionData<T: Codable>: Codable {
    let key: String
    let value: T
}
```

## Token Refresh Implementation

Handle token refresh automatically:

```swift
struct TokenRefreshMiddleware<Context: SessionRequestContext>: RouterMiddleware 
where Context.Identity == User {
    
    func handle(
        _ request: Request,
        context: Context,
        next: (Request, Context) async throws -> Response
    ) async throws -> Response {
        
        // Check if we have tokens that need refreshing
        if let refreshToken: String = context.sessions.getSession("refresh_token"),
           let expiresAt: Double = context.sessions.getSession("token_expires_at"),
           let providerName: String = context.sessions.getSession("provider") {
            
            let now = Date().timeIntervalSince1970
            if now >= expiresAt - 300 { // Refresh 5 minutes before expiry
                do {
                    let factory = OAuthClientFactory()
                    let provider = try await createOAuthProvider(providerName, factory: factory)
                    let (newTokens, _) = try await provider.refreshAccessToken(refreshToken: refreshToken)
                    
                    // Update session with new tokens
                    context.sessions.setSession("access_token", newTokens.accessToken)
                    if let newRefreshToken = newTokens.refreshToken {
                        context.sessions.setSession("refresh_token", newRefreshToken)
                    }
                    let newExpiresAt = now + Double(newTokens.expiresIn ?? 3600)
                    context.sessions.setSession("token_expires_at", newExpiresAt)
                    
                    context.logger.info("Token refreshed successfully")
                } catch {
                    context.logger.error("Token refresh failed: \(error)")
                    // Clear invalid tokens
                    context.sessions.clearAll()
                    throw HTTPError(.unauthorized, reason: "Token refresh failed")
                }
            }
        }
        
        return try await next(request, context)
    }
}
```

## Environment Configuration

Set up your environment variables:

```swift
enum Environment {
    static func get(_ key: String) -> String? {
        ProcessInfo.processInfo.environment[key]
    }
    
    static func require(_ key: String) -> String {
        guard let value = get(key) else {
            fatalError("Missing required environment variable: \(key)")
        }
        return value
    }
}
```

Create a `.env` file or set environment variables:

```bash
# Google OAuth2
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=http://localhost:8080/auth/google/callback

# Microsoft OAuth2
MICROSOFT_CLIENT_ID=your-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-microsoft-client-secret
MICROSOFT_REDIRECT_URI=http://localhost:8080/auth/microsoft/callback

# GitHub OAuth2
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GITHUB_REDIRECT_URI=http://localhost:8080/auth/github/callback

# Discord OAuth2
DISCORD_CLIENT_ID=your-discord-client-id
DISCORD_CLIENT_SECRET=your-discord-client-secret
DISCORD_REDIRECT_URI=http://localhost:8080/auth/discord/callback
```

## Complete Application Example

Here's a complete working application:

```swift
import ArgumentParser
import Hummingbird
import HummingbirdAuth
import OAuthKit

@main
struct OAuthApp: AsyncParsableCommand {
    @Option(name: .shortAndLong)
    var hostname: String = "127.0.0.1"

    @Option(name: .shortAndLong)
    var port: Int = 8080

    func run() async throws {
        let app = try await buildApplication(
            configuration: .init(
                address: .hostname(self.hostname, port: self.port),
                serverName: "OAuthApp"
            )
        )
        try await app.runService()
    }
}

func buildApplication(configuration: ApplicationConfiguration) async throws -> some ApplicationProtocol {
    let router = Router(context: AppRequestContext.self)
    
    let oauthFactory = OAuthClientFactory()
    let sessionStorage = MemorySessionStorage<String, User>(expiration: .minutes(30))
    
    // Middleware
    router.addMiddleware {
        LogRequestsMiddleware(.info)
        CORSMiddleware()
        SessionMiddleware(storage: sessionStorage)
        TokenRefreshMiddleware()
    }
    
    // Routes
    router.get("/") { _, _ in
        """
        <h1>OAuth with Hummingbird</h1>
        <a href="/auth/google">Login with Google</a><br>
        <a href="/auth/microsoft">Login with Microsoft</a><br>
        <a href="/auth/github">Login with GitHub</a><br>
        <a href="/auth/discord">Login with Discord</a>
        """
    }
    
    // Configure OAuth routes
    try await configureOAuthRoutes(router, oauthFactory: oauthFactory)
    configureProtectedRoutes(router)
    
    var application = Application(
        router: router,
        server: .http1(),
        configuration: configuration
    )
    
    application.addServices(oauthFactory, sessionStorage)
    return application
}
```

## API Integration

Make authenticated API calls using stored tokens:

```swift
func fetchUserProfile(accessToken: String) async throws -> [String: String] {
    let httpClient = HTTPClient.shared
    
    var request = HTTPClientRequest(url: "https://api.example.com/user")
    request.headers.add(name: "Authorization", value: "Bearer \(accessToken)")
    
    let response = try await httpClient.execute(request, timeout: .seconds(30))
    
    guard response.status == .ok else {
        throw HTTPError(.badGateway, reason: "API request failed")
    }
    
    let data = try await response.body.collect(upTo: 1024 * 1024)
    return try JSONDecoder().decode([String: String].self, from: data)
}
```

## Security Best Practices

1. **Session Security**: Use secure session storage in production (Redis, database)
2. **HTTPS**: Always use HTTPS in production environments
3. **State Validation**: Always validate the state parameter to prevent CSRF
4. **Token Storage**: Store tokens securely and implement proper expiration
5. **Error Handling**: Don't expose sensitive information in error messages
6. **CORS**: Configure CORS properly for your domain

## Production Considerations

### Session Storage

For production, use persistent session storage:

```swift
// Redis session storage
let redisService = RedisService(url: "redis://localhost:6379")
let sessionStorage = RedisSessionStorage<String, User>(
    redis: redisService,
    expiration: .minutes(30)
)

// Database session storage
let fluentSessionStorage = FluentSessionStorage<String, User>(
    fluent: fluent,
    expiration: .minutes(30)
)
```

### Error Handling

Implement proper OAuth error handling:

```swift
extension OAuth2Error: HTTPResponseError {
    public var status: HTTPResponseStatus {
        switch self {
        case .configurationError:
            return .internalServerError
        case .networkError:
            return .badGateway
        case .responseError, .invalidResponse:
            return .badRequest
        case .tokenValidationError:
            return .unauthorized
        default:
            return .internalServerError
        }
    }
    
    public var headers: HTTPFields {
        return [:]
    }
}
```
