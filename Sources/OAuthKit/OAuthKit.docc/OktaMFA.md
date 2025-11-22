# Okta MFA Challenge Flow

Learn how to handle Okta's multi-factor authentication (MFA) flows with push notifications and number challenges.

## Overview

Okta's MFA challenge flows allow you to programmatically handle multi-factor authentication, including push notifications with number challenges, SMS codes, TOTP tokens, and other factor types. This is essential for enterprise applications that need to authenticate users through Okta's adaptive MFA policies.

## Understanding Okta MFA Flow

The Okta MFA flow typically works as follows:

1. **Primary Authentication**: User provides username/password
2. **MFA Challenge**: Okta returns available MFA factors
3. **Factor Selection**: Application chooses or user selects MFA method
4. **Factor Verification**: Complete the challenge (push approval, code entry, etc.)
5. **Session Token**: Receive session token for OAuth flow completion

## MFA Factor Types

OAuthKit supports these Okta MFA factor types:

| Factor Type | Description | User Interaction |
|-------------|-------------|------------------|
| **Push** | Okta Verify push notifications with number challenge | Approve on device |
| **SMS** | SMS code to registered phone | Enter received code |
| **Call** | Voice call with spoken code | Enter heard code |
| **TOTP** | Time-based one-time password (Google Authenticator, etc.) | Enter app-generated code |
| **Email** | Email with verification code | Enter emailed code |
| **Security Question** | Pre-configured security question | Provide answer |
| **WebAuthn** | FIDO2/WebAuthn authenticator | Browser interaction |

## Basic MFA Flow

### Step 1: Primary Authentication

```swift
import OAuthKit

let provider = try await oauthFactory.oktaProvider(
    clientID: "your-okta-client-id",
    clientSecret: "your-okta-client-secret",
    domain: "your-tenant.okta.com",
    redirectURI: "your-redirect-uri"
)

// Authenticate with username and password
let mfaChallenge = try await provider.authenticateWithPassword(
    username: "user@company.com",
    password: "userPassword123"
)

print("Available MFA factors:")
for factor in mfaChallenge.factors {
    print("- \(factor.factorType.displayName): \(factor.id)")
}
```

### Step 2: Handle Push Notification

```swift
// Find push factor
guard let pushFactor = mfaChallenge.factors.first(where: { $0.factorType == .push }) else {
    throw OktaMFAError.factorNotFound
}

// Initiate push notification
let pushResponse = try await provider.initiateOktaVerifyPush(
    factorId: pushFactor.id,
    stateToken: mfaChallenge.stateToken
)

// Display challenge number to user
if let challengeNumber = pushResponse.challengeContext?.challengeNumber {
    print("🔔 Push notification sent!")
    print("📱 Check your Okta Verify app and verify this number: \(challengeNumber)")
}

// Poll for user approval
let pollResult = try await provider.pollForPushApproval(
    factorId: pushFactor.id,
    stateToken: mfaChallenge.stateToken,
    timeout: 60,  // Wait up to 60 seconds
    interval: 2   // Check every 2 seconds
)

if let sessionToken = pollResult.sessionToken {
    print("✅ MFA completed! Session token: \(sessionToken)")
    // Use session token to complete OAuth flow
}
```

### Step 3: Handle SMS/TOTP Codes

```swift
// Example with SMS factor
guard let smsFactor = mfaChallenge.factors.first(where: { $0.factorType == .sms }) else {
    throw OktaMFAError.factorNotFound
}

print("📱 SMS code sent to: \(smsFactor.profile?.phoneNumber ?? "your phone")")
print("Enter the SMS code: ", terminator: "")
let smsCode = readLine() ?? ""

let verifyRequest = OktaMFAVerifyRequest(
    stateToken: mfaChallenge.stateToken,
    passCode: smsCode
)

let verifyResponse = try await provider.verifyMFAFactor(
    factorId: smsFactor.id,
    stateToken: mfaChallenge.stateToken,
    verifyRequest: verifyRequest
)

if verifyResponse.status == .success {
    print("✅ SMS verification successful!")
}
```

## Complete MFA Authentication

For a streamlined experience, use the convenience method:

```swift
do {
    // Complete MFA and get OAuth URL for flow completion
    let (url, codeVerifier) = try await provider.authenticateWithMFA(
        username: "user@company.com",
        password: "userPassword123",
        preferredFactorType: .push,
        state: "my-app-state-123",
        scopes: ["openid", "profile", "email"]
    )
    
    print("✅ MFA complete! Redirect to: \(url)")
    print("Store code verifier: \(codeVerifier ?? "")")
    
    // Later, after OAuth redirect callback with authorization code:
    let (tokenResponse, claims) = try await provider.exchangeCode(
        code: "received-auth-code",
        codeVerifier: codeVerifier
    )
    
    print("✅ OAuth complete!")
    print("Access token: \(tokenResponse.accessToken)")
    print("User: \(claims.name ?? "Unknown")")
    
} catch OktaMFAError.factorNotFound {
    print("❌ Push notification not available for this user")
} catch OktaMFAError.challengeTimeout {
    print("⏰ MFA challenge timed out")
} catch OktaMFAError.userDenied {
    print("❌ User denied the push notification")
}
```

## Advanced MFA Scenarios

### Multiple Factor Types

Handle users with multiple MFA factors:

```swift
let mfaChallenge = try await provider.authenticateWithPassword(
    username: username,
    password: password
)

print("Choose your authentication method:")
for (index, factor) in mfaChallenge.factors.enumerated() {
    print("\(index + 1). \(factor.factorType.displayName)")
}

print("Enter choice (1-\(mfaChallenge.factors.count)): ", terminator: "")
let choice = Int(readLine() ?? "1") ?? 1
let selectedFactor = mfaChallenge.factors[choice - 1]

switch selectedFactor.factorType {
case .push:
    // Handle push notification
    let pushResponse = try await provider.initiateOktaVerifyPush(
        factorId: selectedFactor.id,
        stateToken: mfaChallenge.stateToken
    )
    // Poll for approval...
    
case .sms, .totp:
    // Handle code-based factors
    print("Enter verification code: ", terminator: "")
    let code = readLine() ?? ""
    
    let verifyRequest = OktaMFAVerifyRequest(
        stateToken: mfaChallenge.stateToken,
        passCode: code
    )
    
    let result = try await provider.verifyMFAFactor(
        factorId: selectedFactor.id,
        stateToken: mfaChallenge.stateToken,
        verifyRequest: verifyRequest
    )
    
default:
    print("Factor type not supported in this example")
}
```

### Enterprise Policies

Handle different MFA requirements based on Okta policies:

```swift
func handleEnterpriseAuthentication(username: String, password: String) async throws {
    do {
        let mfaChallenge = try await provider.authenticateWithPassword(
            username: username,
            password: password
        )
        
        // Check what factors are required by policy
        switch mfaChallenge.status {
        case .mfaRequired:
            print("🔒 MFA required by policy")
            
        case .mfaEnroll:
            print("📝 User must enroll in MFA first")
            throw OktaMFAError.apiError("MFA enrollment required")
            
        case .passwordExpired:
            print("🔑 Password expired - user must reset")
            throw OktaMFAError.apiError("Password expired")
            
        case .lockedOut:
            print("🚫 Account locked out")
            throw OktaMFAError.apiError("Account locked")
            
        default:
            print("Status: \(mfaChallenge.status)")
        }
        
        // Proceed with MFA challenge...
        
    } catch let error as OktaMFAError {
        print("MFA Error: \(error.description)")
        throw error
    }
}
```

## Error Handling

Comprehensive error handling for MFA flows:

```swift
do {
    let result = try await provider.authenticateWithMFA(
        username: username,
        password: password
    )
    // Success
} catch OktaMFAError.mfaRequired(let challenge) {
    // Handle MFA challenge
    print("MFA required. Available factors: \(challenge.factors.count)")
    
} catch OktaMFAError.factorVerificationFailed(let message) {
    // Wrong code entered or verification failed
    print("Verification failed: \(message)")
    
} catch OktaMFAError.factorNotFound {
    // Requested factor type not available
    print("Requested MFA method not available for this user")
    
} catch OktaMFAError.challengeTimeout {
    // User took too long to respond
    print("MFA challenge timed out. Please try again.")
    
} catch OktaMFAError.userDenied {
    // User explicitly denied the challenge
    print("Authentication denied by user")
    
} catch OktaMFAError.invalidFactorType(let type) {
    // Unsupported factor type
    print("Factor type not supported: \(type)")
    
} catch OktaMFAError.apiError(let message) {
    // Okta API error
    print("Okta API error: \(message)")
    
} catch {
    // Other errors
    print("Authentication failed: \(error)")
}
```

## CLI Application Example

Complete command-line application with MFA support:

```swift
@main
struct OktaMFAApp {
    static func main() async {
        do {
            let app = OktaMFAApp()
            try await app.run()
        } catch {
            print("❌ Error: \(error)")
            exit(1)
        }
    }
    
    func run() async throws {
        print("🔐 Okta MFA Authentication")
        print("==========================")
        
        print("Username: ", terminator: "")
        let username = readLine() ?? ""
        
        print("Password: ", terminator: "")
        let password = readLine() ?? ""
        
        let factory = OAuthClientFactory()
        let provider = try await factory.oktaProvider(
            clientID: getEnvVar("OKTA_CLIENT_ID"),
            clientSecret: getEnvVar("OKTA_CLIENT_SECRET"),
            domain: getEnvVar("OKTA_DOMAIN"),
            redirectURI: getEnvVar("OKTA_REDIRECT_URI")
        )
        
        // Step 1: Primary authentication
        print("\n🔍 Authenticating...")
        let mfaChallenge = try await provider.authenticateWithPassword(
            username: username,
            password: password
        )
        
        // Step 2: Handle MFA
        print("\n🔒 MFA Required")
        print("Available factors:")
        for (index, factor) in mfaChallenge.factors.enumerated() {
            print("\(index + 1). \(factor.factorType.displayName)")
        }
        
        print("Choose factor (1-\(mfaChallenge.factors.count)): ", terminator: "")
        let choice = Int(readLine() ?? "1") ?? 1
        let factor = mfaChallenge.factors[choice - 1]
        
        let sessionToken = try await handleMFAFactor(
            factor: factor,
            stateToken: mfaChallenge.stateToken,
            provider: provider
        )
        
        // Generate OAuth URL with session token
        let (url, codeVerifier) = try await provider.generateAuthURLWithSession(
            sessionToken: sessionToken,
            state: "cli-app-\(UUID().uuidString)",
            scopes: ["openid", "profile", "email"]
        )
        
        print("\n✅ MFA completed!")
        print("🔗 Complete OAuth flow by visiting: \(url)")
        print("💾 Store code verifier: \(codeVerifier ?? "")")
```
    }
    
    func handleMFAFactor(
        factor: OktaMFAFactor,
        stateToken: String,
        provider: OktaOAuthProvider
    ) async throws -> String {
        switch factor.factorType {
        case .push:
            let pushResponse = try await provider.initiateOktaVerifyPush(
                factorId: factor.id,
                stateToken: stateToken
            )
            
            if let challengeNumber = pushResponse.challengeContext?.challengeNumber {
                print("\n📱 Push notification sent!")
                print("Please approve and verify number: \(challengeNumber)")
            }
            
            print("⏳ Waiting for approval...")
            let pollResult = try await provider.pollForPushApproval(
                factorId: factor.id,
                stateToken: stateToken,
                timeout: 60
            )
            
            guard let sessionToken = pollResult.sessionToken else {
                throw OktaMFAError.factorVerificationFailed("No session token received")
            }
            
            return sessionToken
            
        case .sms, .totp:
            print("Enter verification code: ", terminator: "")
            let code = readLine() ?? ""
            
            let verifyRequest = OktaMFAVerifyRequest(
                stateToken: stateToken,
                passCode: code
            )
            
            let verifyResponse = try await provider.verifyMFAFactor(
                factorId: factor.id,
                stateToken: stateToken,
                verifyRequest: verifyRequest
            )
            
            guard let sessionToken = verifyResponse.sessionToken else {
                throw OktaMFAError.factorVerificationFailed("Verification failed")
            }
            
            return sessionToken
            
        default:
            throw OktaMFAError.invalidFactorType(factor.factorType.rawValue)
        }
    }
```
    
    func getEnvVar(_ name: String) -> String {
        guard let value = ProcessInfo.processInfo.environment[name] else {
            fatalError("Missing environment variable: \(name)")
        }
        return value
    }
}
```

## Integration with Web Applications

For web applications, you'll typically handle MFA in the OAuth flow:

```swift
// In your OAuth callback handler
func handleOAuthCallback(request: Request) async throws -> Response {
    do {
        // Standard OAuth flow
        let (tokens, claims) = try await provider.exchangeCode(
            code: request.query["code"],
            codeVerifier: storedCodeVerifier
        )
        
        return redirect(to: "/dashboard")
        
    } catch OAuth2Error.responseError(let message) where message.contains("MFA") {
        // OAuth flow hit MFA challenge - redirect to MFA flow
        return redirect(to: "/mfa-challenge")
        
    } catch {
        throw error
    }
}

// Separate MFA challenge handler
func handleMFAChallenge(request: Request) async throws -> Response {
    let username = request.session["username"]
    let password = request.session["temp_password"] // Securely stored
    
    let mfaChallenge = try await provider.authenticateWithPassword(
        username: username,
        password: password
    )
    
    // Render MFA factor selection page
    return render("mfa-factors", [
        "factors": mfaChallenge.factors,
        "stateToken": mfaChallenge.stateToken
    ])
}
```

## Environment Configuration

Set up your environment variables:

```bash
# Okta Configuration
export OKTA_CLIENT_ID="your-okta-client-id"
export OKTA_CLIENT_SECRET="your-okta-client-secret"  
export OKTA_DOMAIN="your-tenant.okta.com"
export OKTA_REDIRECT_URI="https://your-app.com/callback"
```

## Security Best Practices

1. **Secure Credential Storage**: Never hardcode credentials
2. **Session Management**: Securely store state tokens temporarily
3. **Timeout Handling**: Always set reasonable timeouts for MFA challenges
4. **User Experience**: Provide clear instructions for each factor type
5. **Error Messages**: Don't expose sensitive information in error messages
6. **Logging**: Log MFA events for security monitoring

This comprehensive MFA support makes OAuthKit enterprise-ready for organizations using Okta's adaptive authentication policies.