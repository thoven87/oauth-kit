//===----------------------------------------------------------------------===//
//
// This source file is part of the oauth-kit open source project
//
// Copyright (c) 2025 the oauth-kit project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of oauth-kit project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import AsyncHTTPClient
import Logging
import Testing

@testable import OAuthKit

@Suite("OAuth Providers Tests")
struct OAuthProvidersTests {
    var logger = Logger(label: "provider-test")
    var oauthKit = OAuthKit(httpClient: HTTPClient.shared, logger: Logger(label: "provider-test"))

    @Test("Google Provider Creation")
    func testGoogleProviderCreation() async throws {
        let googleProvider = try await oauthKit.googleProvider(
            clientID: "",
            clientSecret: "",
            redirectURI: "app://brebo.io"
        )
        let lp = try googleProvider.signInURL()
        #expect(lp.codeVerifier != nil)
        #expect(lp.url.absoluteString.contains("code_challenge"))
    }

    @Test("Microsoft Provider Creation")
    func testMicrosoftProviderCreation() async throws {
        let microsoftProvider = try await oauthKit.microsoftProvider(
            clientID: "some-client-id",
            clientSecret: "some-client-secret",
            tenantID: "some-tenant-id",
            redirectURI: "https://example.com/callback"
        )
        let signInURL = try microsoftProvider.signInURL(
            state: "some-state-value",
        )

        #expect(signInURL.url.absoluteString.contains("redirect_uri"))
    }

    @Test("GitHub Provider Creation")
    func testGitHubProviderCreation() async throws {
        let githubProvider = oauthKit.githubProvider(
            clientID: "",
            clientSecret: "",
            redirectURI: "app://brebo.io"
        )

        let signInURL = try githubProvider.signInURL()
        #expect(signInURL.url.absoluteString.contains("redirect_uri"))
        #expect(signInURL.url.absoluteString.contains("client_id"))
        #expect(signInURL.codeVerifier != nil)

    }

    //    @Test("Apple Provider Creation")
    //    func testAppleProviderCreation() async throws {
    //        let appleProvider = try await oauthKit.appleProvider(
    //            clientID: "2453fdfdf",
    //            teamID: "dsjsdks",
    //            keyID: "esdsdds",
    //            privateKey: "dsddsds",
    //            clientSecret: "-----",
    //            redirectURI: "localhost:8080/oauth/apple/callback"
    //        )
    //
    //        let signInURL = try appleProvider.signInURL()
    //        #expect(signInURL.url.absoluteString.contains("redirect_uri"))
    //        #expect(signInURL.url.absoluteString.contains("client_id"))
    //        #expect(signInURL.codeVerifier != nil)
    //    }

    @Test("Slack Provider Creation")
    func testSlackProviderCreation() throws {
        let slackProvider = oauthKit.slackProvider(
            clientID: "",
            clientSecret: "",
            redirectURI: "https://localhost:8080/callback"
        )
        let signInURL = try slackProvider.signInURL()
        #expect(signInURL.url.absoluteString.contains("redirect_uri"))
        #expect(signInURL.url.absoluteString.contains("client_id"))
        #expect(signInURL.codeVerifier != nil)
    }

    @Test("Facebook Provider Creation")
    func testFacebookProviderCreation() throws {
        let facebookProvider = oauthKit.facebookProvider(
            appID: "my-id",
            appSecret: "",
            redirectURI: "https://localhost:8080/callback"
        )
        let signInURL = try facebookProvider.signInURL()
        #expect(signInURL.url.absoluteString.contains("redirect_uri"))
        #expect(signInURL.url.absoluteString.contains("client_id"))
        #expect(signInURL.codeVerifier != nil)
    }

    @Test("Okta Provider Creation")
    func testOktaProviderCreation() async throws {
        let oktaProvider = try await oauthKit.oktaProvider(
            domain: "oauthkit.swift",
            clientID: "",
            clientSecret: "",
            redirectURI: "https://brebels.com/callback"
        )
        let signInURL = try await oktaProvider.signInURL()
        #expect(signInURL.url.absoluteString.contains("redirect_uri"))
        #expect(signInURL.url.absoluteString.contains("client_id"))
        #expect(signInURL.codeVerifier != nil)
    }

    @Test("AWS Cognito Provider Creation")
    func testAWSCognitoProviderCreation() async throws {
        let cognitoProvider = try await oauthKit.awsCognitoProvider(
            region: "us-east-1",
            userPoolID: "some-user-pool-id",
            clientID: "some-client-id",
            redirectURI: "https://brebels.com/callback"
        )
        let signInURL = try cognitoProvider.signInURL()
        #expect(signInURL.url.absoluteString.contains("redirect_uri"))
        #expect(signInURL.url.absoluteString.contains("client_id"))
        #expect(signInURL.codeVerifier != nil)
    }

    @Test("Google Provider Sign-In URL")
    func testGoogleProviderSignInURL() async throws {
        let googleProvider = try await oauthKit.googleProvider(
            clientID: "some-client-id",
            clientSecret: "some-client-secret",
            redirectURI: "https://example.com/callback"
        )

        let (url, codeVerifier) = try googleProvider.signInURL(
            state: "test-state",
            prompt: .selectAccount
        )

        #expect(url.absoluteString.contains("accounts.google.com"))
        #expect(url.absoluteString.contains("redirect_uri="))
        #expect(url.absoluteString.contains("state=test-state"))
        #expect(url.absoluteString.contains("prompt=select_account"))
        #expect(codeVerifier != nil)
    }

    @Test("GitHub Provider Sign-In URL")
    func testGitHubProviderSignInURL() throws {
        let githubProvider = oauthKit.githubProvider(
            clientID: "some-client-id",
            clientSecret: "some-client-secret",
            redirectURI: "https://example.com/callback"
        )

        let (url, codeVerifier) = try githubProvider.signInURL(
            state: "test-state"
        )

        #expect(url.absoluteString.contains("github.com"))
        #expect(url.absoluteString.contains("redirect_uri="))
        #expect(url.absoluteString.contains("state=test-state"))
        #expect(codeVerifier != nil)
    }

    @Test("Facebook Provider Sign-In URL")
    func testFacebookProviderSignInURL() throws {
        let facebookProvider = oauthKit.facebookProvider(
            appID: "aome-app-id",
            appSecret: "some-app-secret",
            redirectURI: "https://example.com/callback"
        )

        let (url, codeVerifier) = try facebookProvider.signInURL(
            state: "test-state",
            displayMode: .page
        )

        #expect(url.absoluteString.contains("facebook.com"))
        #expect(url.absoluteString.contains("redirect_uri="))
        #expect(url.absoluteString.contains("state=test-state"))
        #expect(url.absoluteString.contains("display=page"))
        #expect(codeVerifier != nil)
    }

    @Test("Slack Provider Sign-In URL")
    func testSlackProviderSignInURL() throws {
        let slackProvider = oauthKit.slackProvider(
            clientID: "some-client-id",
            clientSecret: "some-client-secret",
            redirectURI: "https://example.com/callback"
        )

        let (url, codeVerifier) = try slackProvider.signInURL(
            state: "test-state"
        )

        #expect(url.absoluteString.contains("slack.com"))
        #expect(url.absoluteString.contains("redirect_uri="))
        #expect(url.absoluteString.contains("state=test-state"))
        #expect(codeVerifier != nil)
    }

    @Test("KeyCloak Provider Creation")
    func testKeyClockProviderCreation() throws {
        let keycloakProvider = oauthKit.keycloakProvider(
            endpoints: .init(baseURL: "localhost:8080", realm: "some-realm"),
            clientID: "some-client-id",
            clientSecret: "some-client-secret",
            redirectURI: "https://example.com/callback"
        )
        let signInURL = try keycloakProvider.signInURL()
        #expect(signInURL.url.absoluteString.contains("realm"))
        #expect(signInURL.url.absoluteString.contains("client_id"))
        #expect(signInURL.url.absoluteString.contains("code"))
        #expect(signInURL.url.absoluteString.contains("redirect_uri"))
    }
}
