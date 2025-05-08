import AuthenticationServices


@available(iOS 16.0, *)
@available(macOS 13.0, *)
@MainActor
public class AssertionController: NSObject, ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding, Cancelable {
    private var completion: ((Result<AuthorizationResult, AuthorizationError>) -> Void)
    private var authorizationController: ASAuthorizationController?
    
    init(completion: @escaping ((Result<AuthorizationResult, AuthorizationError>) -> Void)) {
        self.completion = completion;
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
            
            completion(.success(response))
            break
        default:
            completion(.failure(AuthorizationError.init(type: .unhandled)))
            break
        }
    }
    
    public func authorizationController(controller: ASAuthorizationController, didCompleteWithError error: Error) {
        guard let authorizationError = error as? ASAuthorizationError else {
            completion(.failure(AuthorizationError(type: .unknown, originalError: error)))
            return
        }
        
        switch (authorizationError.code) {
        case ASAuthorizationError.canceled:
            if (error.localizedDescription.contains("No credentials available for login.")) {
                completion(.failure(AuthorizationError(type: .noCredentialsAvailable, originalError: error)))
            } else {
                completion(.failure(AuthorizationError(type: .cancelled, originalError: error)))
            }
            break
        case ASAuthorizationError.failed:
            if (error.localizedDescription.contains("is not associated with domain")) {
                completion(.failure(AuthorizationError(type: .domainNotAssociated, originalError: error)))
            } else {
                completion(.failure(AuthorizationError(type: .unknown, originalError: error)))
            }
            break
        case ASAuthorizationError.invalidResponse, ASAuthorizationError.notHandled, ASAuthorizationError.unknown:
            completion(.failure(AuthorizationError(type: .unknown, originalError: error)))
            break
        default:
            completion(.failure(AuthorizationError(type: .cancelled, originalError: error)))
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
        fatalError("No window available for ASAuthorizationController on iOS. Ensure a UIWindowScene is active or a delegate window is set.")
        
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
        fatalError("No window available for ASAuthorizationController on macOS. Ensure a window is key or main.")
#else
        fatalError("Unsupported platform for presentationAnchor")
#endif
    }
    
    func cancel() {
        self.authorizationController?.cancel()
    }
}

