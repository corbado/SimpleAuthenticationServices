import AuthenticationServices

@MainActor
protocol Cancelable {
    func cancel()
}

final public class RealAuthorizationController: AuthorizationControllerProtocol, Sendable {
    public init() {}
    
    @MainActor
    private var inFlightController: Cancelable?
    
    @MainActor
    @available(iOS 16.0, *)
    @available(macOS 13.0, *)
    public func authorize(requests: [ASAuthorizationRequest], preferImmediatelyAvailableCredentials: Bool) async throws -> AuthorizationResult {
        cancel()
        
        return try await withCheckedThrowingContinuation{ (continuation: CheckedContinuation<AuthorizationResult, Error>) in
            let controller = AssertionController { result in
                switch result {
                case .success(let resp):   continuation.resume(returning: resp)
                case .failure(let err):    continuation.resume(throwing: err)
                }
            }
            
            self.inFlightController = controller
            
            controller.performRequests(requests: requests, preferImmediatelyAvailableCredentials: preferImmediatelyAvailableCredentials)
        }
    }
    
    @MainActor
    @available(iOS 16.0, *)
    @available(macOS 13.0, *)
    public func authorizeWithAutoFill(requests: [ASAuthorizationRequest]) async throws -> AuthorizationResult {
        cancel()
        
        return try await withCheckedThrowingContinuation{ (continuation: CheckedContinuation<AuthorizationResult, Error>) in
            let controller = AssertionController { result in
                switch result {
                case .success(let resp):   continuation.resume(returning: resp)
                case .failure(let err):    continuation.resume(throwing: err)
                }
            }
            
            self.inFlightController = controller
            
            controller.performAutoFillAssistedRequests(requests: requests)
        }
    }
    
    @MainActor
    @available(iOS 16.0, *)
    @available(macOS 13.0, *)
    public func create(requests: [ASAuthorizationRequest]) async throws -> AuthorizationResult {
        cancel()
        
        return try await withCheckedThrowingContinuation{ (continuation: CheckedContinuation<AuthorizationResult, Error>) in
            let controller = RegistrationController { result in
                switch result {
                case .success(let resp):   continuation.resume(returning: resp)
                case .failure(let err):    continuation.resume(throwing: err)
                }
            }
            
            self.inFlightController = controller
            
            DispatchQueue.main.async {
                controller.performRequests(requests: requests)
            }
        }
    }
    
    @MainActor
    public func signalAllAcceptedCredentials(rpID: String, userHandle: Data, acceptedCredentialIDs: [Data]) async throws(AuthorizationError) {
        if #available(iOS 26.0, *) {
            let credentialUpdater = ASCredentialUpdater()
            do {
                try await credentialUpdater.reportAllAcceptedPublicKeyCredentials(
                    relyingPartyIdentifier: rpID,
                    userHandle: userHandle,
                    acceptedCredentialIDs: acceptedCredentialIDs
                )
            } catch {
                throw AuthorizationError(type: .unknown, originalError: error)
            }
        }
    }
    
    @MainActor
    public func cancel() {
        self.inFlightController?.cancel()
        self.inFlightController = nil
    }
}


