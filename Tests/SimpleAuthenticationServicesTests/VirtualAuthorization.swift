import Testing
import AuthenticationServices
import Foundation
import SimpleAuthenticationServices

@testable import SimpleAuthenticationServicesMocks

@MainActor
@available(iOS 16.0, *)
final class GoServerManager {
    static let shared = GoServerManager()
    private var goServerProcess: Process?
    private var isServerReady = false
    
    private init() {}
    
    func startServerIfNeeded() async throws {
        guard goServerProcess == nil else { return }
        
        print("Starting relying party server...")
        let process = Process()
        guard let executableURL = Bundle.module.url(forResource: "relying-pary-server-arm64-darwin", withExtension: nil, subdirectory: "TestBinaries") else {
            fatalError("Binary 'relying-pary-server-arm64-darwin' not found in test bundle.")
        }
        process.executableURL = executableURL
        try process.run()
        goServerProcess = process
        
        // server takes a bit of time to start
        try await Task.sleep(for: .milliseconds(250))
        print("Started relying party server.")
    }
    
    
    func stopServer() {
        guard let process = goServerProcess, process.isRunning else { return }
        print("Stopping relying party server...")
        process.terminate()
        goServerProcess = nil
        print("Stopped relying party server.")
    }
}

let rpID = "test.corbado.io"

@MainActor
@available(iOS 16.0, *)
@Test func attestationAndAssertion() async throws {
    try await GoServerManager.shared.startServerIfNeeded()
    let controlServer = ControlServer()
    try controlServer.start()
    
    let rps = try RelyingPartyServer(baseURLString: "http://localhost:8080")
    let virtualAuthenticator = VirtualAuthorizationController(controlServerURL: controlServer.baseURL)
    let username = "testuser-\(UUID().uuidString)"
    
    _ = try await create(rps: rps, authenticator: virtualAuthenticator, username: username)
    let authenticatorResponse = try await startLogin(rps: rps, authenticator: virtualAuthenticator, username: username)
    try await finishLogin(rps: rps, authenticatorResponse: authenticatorResponse, username: username)
}

@MainActor
@available(iOS 16.0, *)
@Test func attestationCancelledSimulated() async throws {
    try await GoServerManager.shared.startServerIfNeeded()
    let controlServer = ControlServer()
    try controlServer.start()
    
    controlServer.createError = .cancelled
    
    let rps = try RelyingPartyServer(baseURLString: "http://localhost:8080")
    let virtualAuthenticator = VirtualAuthorizationController(controlServerURL: controlServer.baseURL)
    let username = "testuser-\(UUID().uuidString)"
    
    let error = await assertThrows(throws: AuthorizationError.self) {
        _ = try await create(rps: rps, authenticator: virtualAuthenticator, username: username)
    }
    
    #expect(error!.type == .cancelled)
}

@MainActor
@available(iOS 16.0, *)
@Test
func assertionNoCredential() async throws {
    try await GoServerManager.shared.startServerIfNeeded()
    let controlServer = ControlServer()
    try controlServer.start()
    
    let rps = try RelyingPartyServer(baseURLString: "http://localhost:8080")
    let virtualAuthenticator = VirtualAuthorizationController(controlServerURL: controlServer.baseURL)
    let username = "testuser-\(UUID().uuidString)"
    
    let credentialID = try await create(rps: rps, authenticator: virtualAuthenticator, username: username)
    _ = virtualAuthenticator.removeCredential(relyingPartyID: rpID, credentialID: credentialID!)
    
    let error = await assertThrows(throws: AuthorizationError.self) {
        try await startLogin(rps: rps, authenticator: virtualAuthenticator, username: username)
    }
    
    #expect(error!.type == .noCredentialsAvailable)
}

@MainActor
@available(iOS 16.0, *)
@Test
func assertionCancelledSimulated() async throws {
    try await GoServerManager.shared.startServerIfNeeded()
    let controlServer = ControlServer()
    try controlServer.start()
    
    controlServer.authorizeError = .cancelled
    
    let rps = try RelyingPartyServer(baseURLString: "http://localhost:8080")
    let virtualAuthenticator = VirtualAuthorizationController(controlServerURL: controlServer.baseURL)
    let username = "testuser-\(UUID().uuidString)"
    
    _ = try await create(rps: rps, authenticator: virtualAuthenticator, username: username)
    
    let error = await assertThrows(throws: AuthorizationError.self) {
        try await startLogin(rps: rps, authenticator: virtualAuthenticator, username: username)
    }
    
    #expect(error!.type == .cancelled)
}

@MainActor
@available(iOS 16.0, *)
private func create(rps: RelyingPartyServer, authenticator: VirtualAuthorizationController, username: String) async throws -> Data? {
    let registrationOptions = try await rps.registerStart(username: username)
    let decodedChallenge = Data.fromBase64Url(registrationOptions.publicKey.challenge)!
    let decodedUserId = Data.fromBase64Url(registrationOptions.publicKey.user.id)!
    let attestationPlatformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: registrationOptions.publicKey.rp.id)
    let platformRequest = attestationPlatformProvider.createCredentialRegistrationRequest(
        challenge: decodedChallenge,
        name: registrationOptions.publicKey.user.name,
        userID: decodedUserId
    )
    
    let authorizationResult = try await authenticator.create(requests: [platformRequest])
    let typedCredential = try #require(
        authorizationResult.credential as? PasskeyRegistrationCredential,
        "Credential must be of type PasskeyRegistrationCredential. Actual type: \(type(of: authorizationResult.credential))"
    )
    
    let registrationData = RPPlatformPublicKeyCredentialRegistration(
        id: typedCredential.credentialID.toBase64URL(),
        rawId: typedCredential.credentialID.toBase64URL(),
        type: "public-key",
        response: RPPlatformPublicKeyCredentialRegistration.Response(
            clientDataJSON: typedCredential.rawClientDataJSON.toBase64URL(),
            attestationObject: typedCredential.rawAttestationObject.toBase64URL(),
            transports: []
        )
    )
    
    _ = try await rps.registerFinish(username: username, registrationData: registrationData)
    
    return typedCredential.credentialID
}

@MainActor
@available(iOS 16.0, *)
private func startLogin(rps: RelyingPartyServer, authenticator: VirtualAuthorizationController, username: String) async throws -> AuthorizationResult {
    let assertionOptions = try await rps.loginStart(username: username)
    let assertionPlatformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: assertionOptions.publicKey.rpId!)
    let assertionRequest = assertionPlatformProvider.createCredentialAssertionRequest(
        challenge: Data.fromBase64Url(assertionOptions.publicKey.challenge)!
    )
    assertionRequest.allowedCredentials = parseCredentials(credentials: assertionOptions.publicKey.allowCredentials)
    
    return try await authenticator.authorize(requests: [assertionRequest], preferImmediatelyAvailableCredentials: false)
}

private func finishLogin(rps: RelyingPartyServer, authenticatorResponse: AuthorizationResult, username: String) async throws {
    let assertionTyped = try #require(
        authenticatorResponse.credential as? PasskeyAssertionCredential,
        "Credential must be of type PasskeyAssertionCredential. Actual type: \(type(of: authenticatorResponse.credential))"
    )
    
    let loginFinishData = RPPlatformPublicKeyCredentialAssertion(
        id: assertionTyped.credentialID.toBase64URL(),
        rawId: assertionTyped.credentialID.toBase64URL(),
        type: "public-key",
        response: RPPlatformPublicKeyCredentialAssertion.Response(
            clientDataJSON: assertionTyped.rawClientDataJSON.toBase64URL(),
            authenticatorData: assertionTyped.rawAuthenticatorData.toBase64URL(),
            signature: assertionTyped.signature.toBase64URL(),
            userHandle: assertionTyped.userID.toBase64URL()
        )
    )
    
    _ = try await rps.loginFinish(username: username, assertionData: loginFinishData)
}

@available(iOS 16.0, *)
private func parseCredentials(credentials: [RPPublicKeyCredentialRequestOptions.AllowCredentialDescriptor]?) -> [ASAuthorizationPlatformPublicKeyCredentialDescriptor] {
    guard let credentials = credentials else {
        return []
    }
    
    return credentials.compactMap { credential in
        guard let credentialData = Data.fromBase64Url(credential.id) else {
            return nil
        }
        return ASAuthorizationPlatformPublicKeyCredentialDescriptor(credentialID: credentialData)
    }
}

extension Data {
    static func fromBase64(_ encoded: String) -> Data? {
        var encoded = encoded
        let remainder = encoded.count % 4
        if remainder > 0 {
            encoded = encoded.padding(
                toLength: encoded.count + 4 - remainder,
                withPad: "=",
                startingAt: 0
            )
        }
        return Data(base64Encoded: encoded)
    }
    
    static func fromBase64Url(_ encoded: String) -> Data? {
        let base64String = base64UrlToBase64(base64Url: encoded)
        return fromBase64(base64String)
    }
    
    private static func base64UrlToBase64(base64Url: String) -> String {
        return base64Url.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
    }
    
    func toBase64URL() -> String {
        var result = self.base64EncodedString()
        result = result.replacingOccurrences(of: "+", with: "-")
        result = result.replacingOccurrences(of: "/", with: "_")
        result = result.replacingOccurrences(of: "=", with: "")
        return result
    }
}

func assertThrows<T>(throws: T.Type, _ block: @Sendable @escaping () async throws -> Any) async -> T? {
    do {
        _ = try await block()
        #expect(Bool(false), "Expected an error to be thrown, but none was")
    } catch {
        return error as? T
    }
    
    return nil
}

