import AuthenticationServices


@available(iOS 16.0, *)
@available(macOS 13.0, *)
@MainActor
public class AssertionController: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding, Cancelable {
    private var completion: ((Result<AuthorizationResult, AuthorizationError>) -> Void)
    private var authorizationController: ASAuthorizationController?
    private var hasCompleted = false
    
    init(completion: @escaping ((Result<AuthorizationResult, AuthorizationError>) -> Void)) {
        self.completion = completion;
    }
    
    private func completeOnce(_ result: Result<AuthorizationResult, AuthorizationError>) {
        guard !hasCompleted else { return }
        hasCompleted = true
        completion(result)
    }
    
    func performRequests(requests: [ASAuthorizationRequest], preferImmediatelyAvailableCredentials: Bool) {
        let options: ASAuthorizationController.RequestOptions = preferImmediatelyAvailableCredentials ? .preferImmediatelyAvailableCredentials : []
        
        let authorizationController = ASAuthorizationController(authorizationRequests: requests)
        authorizationController.delegate = self
        authorizationController.presentationContextProvider = self
        authorizationController.performRequests(options: options)
        
        self.authorizationController = authorizationController
    }
    
    func performAutoFillAssistedRequests(requests: [ASAuthorizationRequest]) {
#if os(iOS)
        let authorizationController = ASAuthorizationController(authorizationRequests: requests)
        authorizationController.delegate = self
        authorizationController.presentationContextProvider = self
        authorizationController.performAutoFillAssistedRequests()
        
        self.authorizationController = authorizationController
#else
        print("performAutoFillAssistedRequests is not supported on this platform.")
#endif
    }
    
    public func authorizationController(controller: ASAuthorizationController, didCompleteWithAuthorization authorization: ASAuthorization) {
        switch authorization.credential {
        case let r as ASAuthorizationPlatformPublicKeyCredentialAssertion:
            let response = AuthorizationResult(
                credential: PasskeyAssertionCredential(
                    credentialID: r.credentialID,
                    rawClientDataJSON: r.rawClientDataJSON,
                    rawAuthenticatorData: r.rawAuthenticatorData,
                    signature: r.signature,
                    userID: r.userID
                )
            )
            
            completeOnce(.success(response))
            break
        default:
            completeOnce(.failure(AuthorizationError.init(type: .unhandled)))
            break
        }
    }
    
    public func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        guard let authorizationError = error as? ASAuthorizationError else {
            completeOnce(.failure(AuthorizationError(type: .unknown, originalError: error)))
            return
        }
        
        switch (authorizationError.code) {
        case ASAuthorizationError.canceled:
            if (error.localizedDescription.contains("No credentials available for login.")) {
                completeOnce(.failure(AuthorizationError(type: .noCredentialsAvailable, originalError: error)))
            } else {
                completeOnce(.failure(AuthorizationError(type: .cancelled, originalError: error)))
            }
            break
        case ASAuthorizationError.failed:
            if (error.localizedDescription.contains("is not associated with domain")) {
                completeOnce(.failure(AuthorizationError(type: .domainNotAssociated, originalError: error)))
            } else {
                completeOnce(.failure(AuthorizationError(type: .unknown, originalError: error)))
            }
            break
        case ASAuthorizationError.invalidResponse, ASAuthorizationError.notHandled, ASAuthorizationError.unknown:
            completeOnce(.failure(AuthorizationError(type: .unknown, originalError: error)))
            break
        default:
            completeOnce(.failure(AuthorizationError(type: .cancelled, originalError: error)))
            break
        }
        
        return
    }
    
    public func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
#if os(iOS)
        if let scene = UIApplication.shared.connectedScenes.first(where: { $0.activationState == .foregroundActive }) as? UIWindowScene {
            if let keyWindow = scene.windows.first(where: { $0.isKeyWindow }) {
                return keyWindow
            }
            if let firstWindow = scene.windows.first {
                return firstWindow
            }
        }
        if let legacyWindow = UIApplication.shared.delegate?.window ?? nil {
            return legacyWindow
        }
        
        // No valid window found - create a dummy window to return, then cancel the operation
        let dummyWindow = UIWindow(frame: CGRect.zero)
        
        // Cancel the authorization and report the error
        DispatchQueue.main.async {
            self.completeOnce(.failure(AuthorizationError(type: .noPresentationAnchor)))
            self.authorizationController?.cancel()
        }
        
        return dummyWindow

#elseif os(macOS)
        if let keyWindow = NSApplication.shared.keyWindow {
            return keyWindow
        }
        if let mainWindow = NSApplication.shared.mainWindow {
            return mainWindow
        }
        // Fallback to any visible window if main/key are not found (less ideal but better than crashing)
        if let anyWindow = NSApplication.shared.windows.first(where: { $0.isVisible }) {
            return anyWindow
        }
        
        // No valid window found - create a dummy window to return, then cancel the operation
        let dummyWindow = NSWindow(contentRect: NSRect.zero, styleMask: [], backing: .buffered, defer: false)
        
        // Cancel the authorization and report the error
        DispatchQueue.main.async {
            self.completeOnce(.failure(AuthorizationError(type: .noPresentationAnchor)))
            self.authorizationController?.cancel()
        }
        
        return dummyWindow
#else
        // Unsupported platform - create a dummy window and cancel
        let dummyWindow = UIWindow(frame: CGRect.zero)
        
        DispatchQueue.main.async {
            self.completeOnce(.failure(AuthorizationError(type: .noPresentationAnchor)))
            self.authorizationController?.cancel()
        }
        
        return dummyWindow
#endif
    }
    
    func cancel() {
        self.authorizationController?.cancel()
    }
}

