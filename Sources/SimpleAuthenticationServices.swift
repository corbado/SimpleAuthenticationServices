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
    
    @MainActor // This method will present UI
    func signalAllAcceptedCredentials(rpID: String, userHandle: Data, acceptedCredentialIDs: [Data]) async throws(AuthorizationError)

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

/// The WebAuthn `authenticatorAttachment` of a credential (https://w3c.github.io/webauthn/#enumdef-authenticatorattachment).
public enum PasskeyAuthenticatorAttachment: String, Sendable, Equatable {
    /// The authenticator is part of this device (e.g. iCloud Keychain on this iPhone).
    case platform
    /// A roaming authenticator, e.g. a security key or a phone used via hybrid (QR code).
    case crossPlatform = "cross-platform"
}

/// Client extension outputs reported by AuthenticationServices.
/// Fields are nil when the extension was not requested or the OS does not report it.
public struct PasskeyClientExtensionResults: Sendable, Equatable {
    /// Output of the `largeBlob` extension (iOS 17+ / macOS 14+).
    public struct LargeBlob: Sendable, Equatable {
        /// Registration: whether the authenticator supports large blobs.
        public let supported: Bool?
        /// Assertion (read): the blob that was read.
        public let blob: Data?
        /// Assertion (write): whether the blob was written.
        public let written: Bool?

        public init(supported: Bool? = nil, blob: Data? = nil, written: Bool? = nil) {
            self.supported = supported
            self.blob = blob
            self.written = written
        }
    }

    /// Output of the `prf` extension (iOS 18+ / macOS 15+).
    public struct PRF: Sendable, Equatable {
        /// Registration: whether the credential supports PRF.
        public let enabled: Bool?
        /// The first PRF result, if evaluated.
        public let first: Data?
        /// The second PRF result, if evaluated with a second salt.
        public let second: Data?

        public init(enabled: Bool? = nil, first: Data? = nil, second: Data? = nil) {
            self.enabled = enabled
            self.first = first
            self.second = second
        }
    }

    public let largeBlob: LargeBlob?
    public let prf: PRF?

    public init(largeBlob: LargeBlob? = nil, prf: PRF? = nil) {
        self.largeBlob = largeBlob
        self.prf = prf
    }

    public var isEmpty: Bool { largeBlob == nil && prf == nil }
}

public struct PasskeyRegistrationCredential: PublicKeyCredentialRegistration {
    public let credentialID: Data
    public let rawClientDataJSON: Data
    public let rawAttestationObject: Data
    /// WebAuthn transport names (e.g. "usb", "nfc", "ble", "hybrid", "internal") as UTF-8 bytes.
    public let transports: [Data]
    /// nil when the OS does not report it (below iOS 16.6 / macOS 13.5).
    public let attachment: PasskeyAuthenticatorAttachment?
    public let clientExtensionResults: PasskeyClientExtensionResults

    public init(
        credentialID: Data,
        rawClientDataJSON: Data,
        rawAttestationObject: Data,
        transports: [Data],
        attachment: PasskeyAuthenticatorAttachment? = nil,
        clientExtensionResults: PasskeyClientExtensionResults = PasskeyClientExtensionResults()
    ) {
        self.credentialID = credentialID
        self.rawClientDataJSON = rawClientDataJSON
        self.rawAttestationObject = rawAttestationObject
        self.transports = transports
        self.attachment = attachment
        self.clientExtensionResults = clientExtensionResults
    }

    /// The reported transports as WebAuthn transport strings.
    public var transportNames: [String] {
        transports.compactMap { String(data: $0, encoding: .utf8) }
    }
}

public struct PasskeyAssertionCredential: PublicKeyCredentialAssertion {
    public let credentialID: Data
    public let rawClientDataJSON: Data
    public let rawAuthenticatorData: Data
    public let signature: Data
    public let userID: Data
    /// nil when the OS does not report it (below iOS 16.6 / macOS 13.5).
    public let attachment: PasskeyAuthenticatorAttachment?
    public let clientExtensionResults: PasskeyClientExtensionResults

    public init(
        credentialID: Data,
        rawClientDataJSON: Data,
        rawAuthenticatorData: Data,
        signature: Data,
        userID: Data,
        attachment: PasskeyAuthenticatorAttachment? = nil,
        clientExtensionResults: PasskeyClientExtensionResults = PasskeyClientExtensionResults()
    ) {
        self.credentialID = credentialID
        self.rawClientDataJSON = rawClientDataJSON
        self.rawAuthenticatorData = rawAuthenticatorData
        self.signature = signature
        self.userID = userID
        self.attachment = attachment
        self.clientExtensionResults = clientExtensionResults
    }
}

public struct PublicKeyCredentialDescriptor: Hashable, Sendable {
    public let credentialID: Data
    public var transports: [String]? = nil
    
    public init(credentialID: Data) {
        self.credentialID = credentialID
    }
}

public enum AuthorizationErrorType: String, Equatable, Sendable, Codable {
    case cancelled
    case unknown
    case decoding
    case encoding
    case domainNotAssociated
    case excludeCredentialsMatch
    case noCredentialsAvailable
    case functionNotSupported
    case unhandled // this indicates an issue in the SimpleAuthenticationServices library => create a GitHub issue
    case noPresentationAnchor
}

public struct AuthorizationError: Error, LocalizedError, Sendable {
    public let type: AuthorizationErrorType
    public let originalError: Error?

    public init(type: AuthorizationErrorType, originalError: Error? = nil) {
        self.type = type
        self.originalError = originalError
    }

    public var errorDescription: String? {
        guard let originalError else {
            return "AuthorizationError(type: \(type.rawValue))"
        }

        return "AuthorizationError(type: \(type.rawValue), originalError: \(String(describing: originalError)))"
    }
}
