import AuthenticationServices

public protocol AuthorizationControllerProtocol: Sendable { // Protocol itself should be Sendable
    @available(iOS 16.0, *)
    @available(macOS 13.0, *)
    @MainActor // This method will present UI
    func authorize(requests: [ASAuthorizationRequest], preferImmediatelyAvailableCredentials: Bool) async throws -> AuthorizationResult

    @available(iOS 16.0, *)
    @available(macOS 13.0, *)
    @MainActor // This method will present UI
    func authorizeWithAutoFill(requests: [ASAuthorizationRequest]) async throws -> AuthorizationResult

    @available(iOS 16.0, *)
    @available(macOS 13.0, *)
    @MainActor // This method will present UI
    func create(requests: [ASAuthorizationRequest]) async throws -> AuthorizationResult

    @MainActor // This method might interact with an ongoing UI operation
    func cancel() async
}

public protocol AuthorizationProvider: Sendable {}
public protocol AuthorizationCredential: Sendable {}

public struct AuthorizationResult: Sendable {
    public let provider: AuthorizationProvider
    public let credential: AuthorizationCredential
    
    public init(credential: AuthorizationCredential) {
        self.provider = DummyProvider()
        self.credential = credential
    }
}

public protocol PublicKeyCredential: AuthorizationCredential {
    var rawClientDataJSON: Data { get }
    var credentialID: Data { get }
}

public protocol PublicKeyCredentialRegistration: PublicKeyCredential {
    var rawAttestationObject: Data { get }
}

public protocol PublicKeyCredentialAssertion: PublicKeyCredential {
    var rawAuthenticatorData: Data { get }
    var signature: Data { get }
    var userID: Data {get}
}

public struct DummyProvider: AuthorizationProvider {}

public struct PasskeyRegistrationCredential: PublicKeyCredentialRegistration {
    public let credentialID: Data
    public let rawClientDataJSON: Data
    public let rawAttestationObject: Data
    public let transports: [Data]
    
    public init(
        credentialID: Data,
        rawClientDataJSON: Data,
        rawAttestationObject: Data,
        transports: [Data]
    ) {
        self.credentialID = credentialID
        self.rawClientDataJSON = rawClientDataJSON
        self.rawAttestationObject = rawAttestationObject
        self.transports = transports
    }
}

public struct PasskeyAssertionCredential: PublicKeyCredentialAssertion {
    public let credentialID: Data
    public let rawClientDataJSON: Data
    public let rawAuthenticatorData: Data
    public let signature: Data
    public let userID: Data
    
    public init(
        credentialID: Data,
        rawClientDataJSON: Data,
        rawAuthenticatorData: Data,
        signature: Data,
        userID: Data
    ) {
        self.credentialID = credentialID
        self.rawClientDataJSON = rawClientDataJSON
        self.rawAuthenticatorData = rawAuthenticatorData
        self.signature = signature
        self.userID = userID
    }
}

public struct PublicKeyCredentialDescriptor: Hashable, Sendable {
    public let credentialID: Data
    public var transports: [String]? = nil
    
    public init(credentialID: Data) {
        self.credentialID = credentialID
    }
}

public enum AuthorizationErrorType: Equatable, Sendable, Codable {
    case cancelled
    case unknown
    case decoding
    case encoding
    case domainNotAssociated
    case excludeCredentialsMatch
    case noCredentialsAvailable
    case functionNotSupported
    case unhandled // this indicates an issue in the SimpleAuthenticationServices library => create a GitHub issue
}

public struct AuthorizationError: Error, LocalizedError, Sendable {
    public let type: AuthorizationErrorType
    public let originalError: Error?
    
    public init(type: AuthorizationErrorType, originalError: Error? = nil) {
        self.type = type
        self.originalError = originalError
    }
}
