# SimpleAuthenticationServices

[![Platforms](https://img.shields.io/badge/Platforms-iOS%20%7C%20macOS-Blue.svg)]()
[![SPM compatible](https://img.shields.io/badge/SPM-compatible-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-MIT-lightgrey.svg)](LICENSE)

`SimpleAuthenticationServices` is a Swift library that simplifies the use of Apple's `AuthenticationServices` framework, particularly for passkey authentication. 
It provides a clean, protocol-based approach for easy integration and testing, offering both a real implementation using `ASAuthorizationController` and a mock implementation for your unit and UI tests.
If you want to autotest your passkey-powered authentication flows this library is the way to go. 
It allows you to simulate all kinds of user interactions and authenticator errors which allows you to test not only the happy path but also your error handling.

## Features

*   🚀 Simplifies passkey authentication flows.
*   🧩 Protocol-oriented design (`AuthorizationControllerProtocol`) for easy dependency injection and testing.
*   ✅ `RealAuthorizationController`: Uses Apple's `AuthenticationServices` for actual passkey operations.
*   🧪 `VirtualAuthorizationController`: A mock implementation for testing, allowing you to simulate various authentication scenarios without relying on the system UI or actual credentials.
*   📦 Test-specific dependencies (`CBORCoding`, `Swifter`) are isolated to the mock implementation, ensuring they are not included in your production app builds.
*   Concurrency-ready with Swift concurrency (`async/await`).

## Requirements

*   iOS 13.0+
*   macOS 10.15+

## Installation

`SimpleAuthenticationServices` is available through the Swift Package Manager. To integrate it into your Xcode project or Swift package:

1.  In Xcode, select **File > Add Packages...**
2.  Enter the repository URL: `YOUR_GITHUB_REPO_URL_HERE` (e.g., `https://github.com/your_username/SimpleAuthenticationServices.git`)
3.  Choose the version rule (e.g., "Up to Next Major Version").
4.  Add the package.

Then, you need to add the library products to your targets:

*   For your main application target, add `SimpleAuthenticationServices` to the "Frameworks, Libraries, and Embedded Content" section.
    ```swift
    import SimpleAuthenticationServices
    ```

*   For your test target (e.g., `YourAppTests`, `YourAppUITests`), add `SimpleAuthenticationServicesMocks` to its "Frameworks, Libraries, and Embedded Content" section. This will give you access to `VirtualAuthorizationController`.
    ```swift
    import SimpleAuthenticationServicesMocks // For VirtualAuthorizationController
    import SimpleAuthenticationServices // For AuthorizationControllerProtocol, AuthorizationResult, etc.
    // @testable import YourApp // If testing internal components of your app
    ```

Alternatively, if you're managing your dependencies in a `Package.swift` file, add it to your `dependencies` array:

```swift
dependencies: [
    .package(url: "YOUR_GITHUB_REPO_URL_HERE", from: "1.0.0") // Replace with your repo URL and desired version
]
```

And then add the appropriate products to your target's dependencies:

```swift
// In your target definition
dependencies: [
    .product(name: "SimpleAuthenticationServices", package: "SimpleAuthenticationServices"),
    // ... other dependencies
]

// For a test target
dependencies: [
    .product(name: "SimpleAuthenticationServicesMocks", package: "SimpleAuthenticationServices"),
    // ... other dependencies
]
```

## Usage

### Using the Real Implementation (`RealAuthorizationController`)

Use `RealAuthorizationController` in your production code to interact with the actual `AuthenticationServices` framework. Typically, you would wrap this in a service or plugin that handles communication with your Relying Party (RP) server, including decoding requests from your server and encoding responses back to it.

Here's a conceptual example inspired by how a `PasskeysPlugin` might work:

```swift
import Foundation
import SimpleAuthenticationServices
import AuthenticationServices // For ASAuthorizationRequest and related types

// --- Data structures for communication with your Relying Party server ---
// (These would typically be Codable structs matching your server's API)

// Example: Request structure for passkey registration options from your RP
struct RPAttestationRequestOptions: Codable {
    struct PublicKey: Codable {
        struct RP: Codable { let id: String; let name: String? }
        struct User: Codable { let id: String; let name: String; let displayName: String? }
        struct AuthenticatorSelection: Codable { letauthenticatorAttachment: String?; let requireResidentKey: Bool?; let residentKey: String?; let userVerification: String? }
        
        let challenge: String // Base64URL encoded
        let rp: RP
        let user: User
        let pubKeyCredParams: [PubKeyCredParam]
        let authenticatorSelection: AuthenticatorSelection?
        let attestation: String?
        let excludeCredentials: [CredentialDescriptor]?
    }
    struct PubKeyCredParam: Codable { let type: String; let alg: Int }
    struct CredentialDescriptor: Codable { let type: String; let id: String /* Base64URL */ ; let transports: [String]? }
    
    let publicKey: PublicKey
}

// Example: Response structure for sending registration credential to your RP
struct RPAttestationResponse: Codable {
    struct Response: Codable {
        let clientDataJSON: String // Base64URL encoded
        let attestationObject: String // Base64URL encoded
        let transports: [String]?
    }
    let id: String // Base64URL encoded
    let rawId: String // Base64URL encoded
    let type: String = "public-key"
    let response: Response
}

// Similar structures would exist for Assertion (Login)
// struct RPAssertionRequestOptions: Codable { /* ... */ }
// struct RPAssertionResponse: Codable { /* ... */ }

// --- Your Passkey Service/Plugin ---

@MainActor
class YourPasskeyService {
    private let authController: AuthorizationControllerProtocol

    // In a real app, you might inject this or use a shared instance.
    // For UI testing, you could inject VirtualAuthorizationController here.
    init(authController: AuthorizationControllerProtocol = RealAuthorizationController()) {
        self.authController = authController
    }

    @available(iOS 16.0, macOS 13.0, *) // Ensure appropriate availability
    func registerNewPasskey(optionsJSON: String) async throws -> String /* JSON response for your RP */ {
        guard let jsonData = optionsJSON.data(using: .utf8) else {
            throw AuthorizationError(type: .decoding, message: "Invalid optionsJSON string")
        }

        let decoder = JSONDecoder()
        let rpOptions = try decoder.decode(RPAttestationRequestOptions.self, from: jsonData)
        let pkOptions = rpOptions.publicKey

        guard let challenge = Data.fromBase64Url(pkOptions.challenge),
              let userID = Data.fromBase64Url(pkOptions.user.id) else {
            throw AuthorizationError(type: .decoding, message: "Failed to decode challenge or userID from RP options")
        }

        let provider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: pkOptions.rp.id)
        let registrationRequest = provider.createCredentialRegistrationRequest(
            challenge: challenge,
            name: pkOptions.user.name, // User's name for the passkey
            userID: userID
        )
        
        // You might want to set up authenticatorSelection, excludeCredentials, etc., on the registrationRequest
        // based on pkOptions.authenticatorSelection and pkOptions.excludeCredentials
        // For example:
        // if let authSelection = pkOptions.authenticatorSelection {
        //    registrationRequest.authenticatorSelection = ... 
        // }
        // if #available(iOS 17.4, *), let excluded = pkOptions.excludeCredentials { 
        //    registrationRequest.excludedCredentials = parseRPExcludedCredentials(excluded)
        // }

        do {
            let result = try await authController.create(requests: [registrationRequest])
            
            guard let credential = result.credential as? PasskeyRegistrationCredential else {
                throw AuthorizationError(type: .unhandled, message: "Unexpected credential type after creation.")
            }

            // Convert to your RP's expected response format
            let rpResponse = RPAttestationResponse(
                id: credential.credentialID.toBase64URL(),
                rawId: credential.credentialID.toBase64URL(),
                response: .init(
                    clientDataJSON: credential.rawClientDataJSON.toBase64URL(),
                    attestationObject: credential.rawAttestationObject.toBase64URL(),
                    transports: credential.transports.map { $0.base64EncodedString() } // Example, adjust as needed
                )
            )
            
            let encoder = JSONEncoder()
            let responseData = try encoder.encode(rpResponse)
            guard let responseJSON = String(data: responseData, encoding: .utf8) else {
                throw AuthorizationError(type: .encoding, message: "Failed to encode RP response to JSON string")
            }
            return responseJSON

        } catch let error as AuthorizationError {
            // Log or handle specific AuthorizationError from SimpleAuthenticationServices
            print("Passkey registration failed: \(error.type) - \(error.message ?? error.localizedDescription)")
            throw error
        } catch {
            // Handle other unexpected errors
            print("An unexpected error occurred during passkey registration: \(error)")
            throw AuthorizationError(type: .unknown, originalError: error)
        }
    }

    @available(iOS 16.0, macOS 13.0, *) // Ensure appropriate availability
    func signInWithPasskey(optionsJSON: String, conditionalUI: Bool = false, preferImmediatelyAvailableCredentials: Bool = true) async throws -> String /* JSON response for your RP */ {
        // Similar structure to registerNewPasskey:
        // 1. Decode optionsJSON into your RPAssertionRequestOptions struct.
        // 2. Create ASAuthorizationPlatformPublicKeyCredentialAssertionRequest from decoded options.
        //    - Set challenge, relyingPartyIdentifier, allowedCredentials.
        // 3. Call authController.authorize(...) or authController.authorizeWithAutoFill(...).
        // 4. Process the result.credential (expecting PasskeyAssertionCredential).
        // 5. Encode into your RPAssertionResponse struct and return as JSON string.
        // Remember to handle errors appropriately.
        
        // This is a placeholder - implement fully based on registerNewPasskey structure
        print("signInWithPasskey called with options: \(optionsJSON)")
        // ... (Implementation would be similar to registerNewPasskey but for assertion)
        throw AuthorizationError(type: .unknown, message: "signInWithPasskey not fully implemented in example.") 
    }
}

// Helper for Base64URL decoding (assuming Data.fromBase64Url and toBase64URL exist as extensions)
// You would need to include these Data extensions, like the ones in your VirtualAuthorization.swift test file.
/*
extension Data {
    static func fromBase64Url(_ encoded: String) -> Data? { ... }
    func toBase64URL() -> String { ... }
}
*/
```

This example demonstrates a more complete flow where `SimpleAuthenticationServices` plays its part within a larger service that deals with server communication and data transformation. Your application code would interact with `YourPasskeyService`.

### Using the Mock Implementation (`VirtualAuthorizationController`) for Testing

In your tests, especially UI tests, you can use `VirtualAuthorizationController` (from the `SimpleAuthenticationServicesMocks` library) to simulate different passkey authentication outcomes without any UI interaction or reliance on the actual Passkey infrastructure.

**How Mocking Works for UI Testing:**

1.  **Start `ControlServer`**: Before your UI test launches the application, you start the `ControlServer`. This server runs locally on the test runner and acts as a simple HTTP endpoint that `VirtualAuthorizationController` will query for instructions.
2.  **Launch App with Configuration**: Launch your application (`XCUIApplication`) for testing. Crucially, you pass launch arguments to your app to:
    *   Indicate it's running in a UI test mode (e.g., using a flag like `"-UITestMode"`).
    *   Provide the base URL of the `ControlServer` (e.g., `"-ControlServerURL=<your_control_server_url>"`).
3.  **App Uses `VirtualAuthorizationController`**: Inside your application's startup code (e.g., in your `App` struct's `init` or an `.onAppear` block), detect the UI test mode flag and the `ControlServer` URL. If detected, your app should instantiate `VirtualAuthorizationController` with this URL and use it instead of `RealAuthorizationController` for all passkey operations.
4.  **Control Behavior from UI Test**: During your UI test, you interact with your app's UI (tapping buttons, entering text). To simulate different passkey outcomes (success, cancellation, specific errors), you make changes to the state of the `ControlServer` directly from your test method *before* the app action that would trigger a passkey operation. For example, you can set a property on `ControlServer` to make the next `create` operation return a "cancelled" error.

This setup allows you to deterministically test various flows without actual system-level passkey prompts appearing.

**Example UI Test Setup:**

Here's how you might set up your `XCTestCase` for UI testing:

```swift
import XCTest
// Import SimpleAuthenticationServicesMocks for ControlServer and VirtualAuthorizationController
// You typically don't import SimpleAuthenticationServices directly into UI tests, 
// as the app itself uses the protocol.
import SimpleAuthenticationServicesMocks 

@MainActor // If your test interactions or assertions require it
@available(iOS 16.0, macOS 13.0, *) // Or your app's minimum passkey versions
class YourAppUITests: XCTestCase {

    var controlServer: ControlServer!
    var app: XCUIApplication!

    override func setUpWithError() throws {
        try super.setUpWithError()
        continueAfterFailure = false

        // 1. Initialize and start the ControlServer
        controlServer = ControlServer()
        try controlServer.start() // Starts the local HTTP server

        // 2. Prepare and launch the application
        app = XCUIApplication()
        app.launchArguments += ["-UITestMode"] // Flag for your app
        app.launchArguments += ["-ControlServerURL=\(controlServer.baseURL.absoluteString)"]
        
        // Optional: Add other necessary launch arguments for your app
        // if filteredByGradualRollout {
        //     app.launchArguments += ["-FilteredByGradualRollout"]
        // }
        
        app.launch()
    }

    override func tearDownWithError() throws {
        controlServer.stop()
        controlServer = nil
        app = nil // Optional: clear app instance
        try super.tearDownWithError()
    }

    // --- Test Examples ---
    // The following examples show how to configure the ControlServer and then interact
    // with your app's UI to trigger the mocked passkey operations.

    // 1. Testing the Happy Path (Successful Registration)
    @Test func testSuccessfulRegistration_UITest() async throws {
        // The ControlServer defaults to successful operations if no error is set.
        // No specific configuration needed on controlServer for success for this flow.

        // Example UI Interaction:
        // let initialScreen = LoginScreen(app: app) // Using your Page Object Model
        // let signUpScreen = initialScreen.navigateToSignUp()
        // await signUpScreen.fillRegistrationForm(email: "test@example.com", name: "Test User")
        // signUpScreen.tapRegisterButton() 
        // Replace above with actual UI interactions for your app
        
        app.buttons["navigateToSignUpButton"].tap()
        app.textFields["emailField"].tap()
        app.textFields["emailField"].typeText("ui-test-user@example.com\n")
        app.textFields["nameField"].tap()
        app.textFields["nameField"].typeText("UI Test User\n")
        app.secureTextFields["passwordField"].tap()
        app.secureTextFields["passwordField"].typeText("SecurePassword123\n")
        app.buttons["registerButton"].tap() // This action should trigger passkey creation in the app

        // After the UI interaction that triggers passkey creation:
        // Assert that the app's UI reflects a successful registration.
        // For example, a new screen appears, a success message is shown, etc.
        XCTAssertTrue(app.staticTexts["RegistrationSuccessfulMessage"].waitForExistence(timeout: 5))
        // Or, XCTAssertTrue(ProfileScreen(app: app).isPasskeyRegisteredIndicatorVisible())
    }

    // 2. Testing an Error Path (User Cancels Registration)
    @Test func testRegistrationCancelled_UITest() async throws {
        // Configure the ControlServer to simulate user cancellation for the next 'create' operation
        controlServer.createError = .cancelled 

        // Example UI Interaction:
        app.buttons["navigateToSignUpButton"].tap()
        app.textFields["emailField"].tap()
        app.textFields["emailField"].typeText("ui-test-cancel@example.com\n")
        // ... fill other fields ...
        app.buttons["registerButton"].tap() // This triggers the passkey creation in the app

        // Assert that the app's UI shows an appropriate error message or state
        XCTAssertTrue(app.staticTexts["RegistrationCancelledErrorMessage"].waitForExistence(timeout: 5))
    }

    // 3. Testing an Error Path (No Credentials Available for Assertion/Login)
    @Test func testLoginNoCredentials_UITest() async throws {
        // Ensure the ControlServer/VirtualAuthorizationController knows no credentials exist for the user/RP.
        // This might be the default state, or you might need to interact with ControlServer 
        // or VirtualAuthorizationController (if it exposes methods) to clear/remove credentials.
        // For instance, if your ControlServer can clear credentials:
        // await controlServer.clearAllCredentials()
        // Or, if your VirtualAuthorizationController (accessible via ControlServer perhaps) can:
        // await controlServer.sendCommandToVirtualAuthenticator("removeCredential", params: ["relyingPartyID": "yourRPID"]) 
        // This part depends on how your SimpleAuthenticationServicesMocks is designed.
        
        // For this example, let's assume the test user has no passkeys and is trying to log in.

        // Example UI Interaction for login:
        app.buttons["navigateToLoginButton"].tap()
        app.textFields["emailFieldForLogin"].tap()
        app.textFields["emailFieldForLogin"].typeText("no-passkey-user@example.com\n")
        app.buttons["loginWithPasskeyButton"].tap() // Triggers passkey assertion

        // Assert that the app shows an error indicating no passkeys were found
        XCTAssertTrue(app.staticTexts["NoPasskeysAvailableErrorMessage"].waitForExistence(timeout: 5))
    }
    
    // ... (other test examples like testLoginAuthenticatorError_UITest can follow similar pattern)
}

```

**Your Application Setup (`YourApp.swift` or similar):**

Your main application (`ConnectExampleApp.swift` in your case) needs to check for these launch arguments and configure the `VirtualAuthorizationController` accordingly.

```swift
// In your ConnectExampleApp.swift (simplified from your example)
import SwiftUI
import SimpleAuthenticationServicesMocks // Needed for VirtualAuthorizationController
// ... other imports (Corbado, Factory, etc.)

@main
struct ConnectExampleApp: App {
    // @Injected(\.corbadoService) private var corbado: Corbado 
    // Assuming `corbado` is the service that will use the AuthorizationControllerProtocol

    init() {
        // ... your other initializations ...

        let arguments = ProcessInfo.processInfo.arguments
        if arguments.contains("-UITestMode") {
            // Disable animations for more stable UI tests
            UIView.setAnimationsEnabled(false)

            if let controlServerURLString = arguments.first(where: { $0.hasPrefix("-ControlServerURL=") })?.replacingOccurrences(of: "-ControlServerURL=", with: ""),
               let controlServerURL = URL(string: controlServerURLString) {
                
                // Instantiate VirtualAuthorizationController
                let virtualController = VirtualAuthorizationController(controlServerURL: controlServerURL)
                
                // Configure your service (e.g., Corbado) to use this virtual controller
                // This is a conceptual example; adapt to how your `corbado` service is designed.
                // Example: YourCorbadoService.shared.setAuthorizationController(virtualController)
                // Or, if using a DI framework like Factory, you might override the registration:
                // Container.shared.authorizationController.register { virtualController }
                // In your case: await corbado.setVirtualAuthorizationController(virtualController)
                Task { // If your setter is async
                    // await corbado.setVirtualAuthorizationController(virtualController)
                    print("App configured to use VirtualAuthorizationController with URL: \(controlServerURL)")
                }
            } else {
                print("UI Test Mode: ControlServerURL not provided or invalid.")
            }
        }
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                // .onAppear { /* your existing onAppear logic for corbado setup if still needed outside of init */ }
        }
    }
}
```

## API Overview

<!-- ... (Existing API Overview section) ... -->

## Contributing

<!-- ... (Existing Contributing section) ... -->

## License

<!-- ... (Existing License section) ... -->