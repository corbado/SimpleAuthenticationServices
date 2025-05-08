import AuthenticationServices
import SimpleAuthenticationServices

@available(iOS 15.0, *)
@available(macOS 12.0, *)
public final class VirtualAuthorizationController: AuthorizationControllerProtocol {
    let controlServerURL: URL?
    
    @MainActor
    private var credentialsByRPID: [String: [Credential]] = [:]
    
    public init(controlServerURL: URL? = nil) {
        self.controlServerURL = controlServerURL
    }
    
    @MainActor
    // TODO: user behaviour (userVerification)
    public func authorize(requests: [ASAuthorizationRequest], preferImmediatelyAvailableCredentials: Bool) async throws -> AuthorizationResult {
        // if more than one request is provided, we will always process only the first one
        guard let firstRequest = requests.first else {
            throw AuthorizationError(type: .unhandled)
        }
        
        switch firstRequest {
        case let typed as ASAuthorizationPlatformPublicKeyCredentialAssertionRequest:
            // maybe simulate an authenticator error
            let (delay, maybeSimulateError) = await fetchControlCommand(path: "/authorize")
            try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            
            if let simulatedErrorType = maybeSimulateError {
                throw AuthorizationError(type: simulatedErrorType)
            }
            
            let relyingPartyID = typed.relyingPartyIdentifier
            guard let existingCredentials = self.credentialsByRPID[relyingPartyID] else {
                throw AuthorizationError(type: .noCredentialsAvailable)
            }
                        
            let userVerificationWasRequired = true
            let assertionOpts = AssertionOptions(
                challenge: typed.challenge,
                rpId: typed.relyingPartyIdentifier,
                allowCredentials: typed.allowedCredentials.map { CredentialDescriptor(id: $0.credentialID) },
                userVerificationRequired: userVerificationWasRequired
            )
            
            let assertionResponse = try createAssertionResponse(
                rp: RelyingParty(id: typed.relyingPartyIdentifier, origin: "https://" + typed.relyingPartyIdentifier),
                credentials: existingCredentials,
                options: assertionOpts
            )
            
            return AuthorizationResult(credential: assertionResponse)
            
        default:
            throw AuthorizationError(type: .unhandled)
        }
    }
    
    @MainActor
    public func authorizeWithAutoFill(requests: [ASAuthorizationRequest]) async throws -> AuthorizationResult {
        // if more than one request is provided, we will always process only the first one
        guard let firstRequest = requests.first else {
            throw AuthorizationError(type: .unhandled)
        }
        
        switch firstRequest {
        case let typed as ASAuthorizationPlatformPublicKeyCredentialAssertionRequest:
            // maybe simulate an authenticator error
            let (delay, maybeSimulateError) = await fetchControlCommand(path: "/authorizeWithAutoFill")
            try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            
            if let simulatedErrorType = maybeSimulateError {
                throw AuthorizationError(type: simulatedErrorType)
            }
            
            let relyingPartyID = typed.relyingPartyIdentifier
            guard let existingCredentials = self.credentialsByRPID[relyingPartyID] else {
                throw AuthorizationError(type: .noCredentialsAvailable)
            }
            
            let userVerificationWasRequired = true
            let assertionOpts = AssertionOptions(
                challenge: typed.challenge,
                rpId: typed.relyingPartyIdentifier,
                allowCredentials: typed.allowedCredentials.map { CredentialDescriptor(id: $0.credentialID) },
                userVerificationRequired: userVerificationWasRequired
            )
            
            let assertionResponse = try createAssertionResponse(
                rp: RelyingParty(id: typed.relyingPartyIdentifier, origin: "https://" + typed.relyingPartyIdentifier),
                credentials: existingCredentials,
                options: assertionOpts
            )
            
            return AuthorizationResult(credential: assertionResponse)
            
        default:
            throw AuthorizationError(type: .unhandled)
        }
    }
    
    @MainActor
    // TODO: system behaviour (excludeCredentials)
    public func create(requests: [ASAuthorizationRequest]) async throws -> AuthorizationResult {
        // if more than one request is provided, we will always process only the first one
        guard let firstRequest = requests.first else {
            throw AuthorizationError(type: .unhandled)
        }
        
        switch firstRequest {
        case let typed as ASAuthorizationPlatformPublicKeyCredentialRegistrationRequest:
            // maybe simulate an authenticator error
            let (delay, maybeSimulateError) = await fetchControlCommand(path: "/create")
            try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            if let simulatedErrorType = maybeSimulateError {
                throw AuthorizationError(type: simulatedErrorType)
            }
            
            let key = try Key(newWithType: .ec2)
            let credential = Credential(key: key, userID: typed.userID)
            
            // check if excludeCredentials hits, if it has been set in request
            if #available(iOS 17.4, *, macOS 13.5, *) {
                if let excludedCredentials = typed.excludedCredentials {
                    let excludeCredentialsHit = excludedCredentials.contains { excludedCredential in
                        self.credentialsByRPID[typed.relyingPartyIdentifier]?.contains { credential in
                            excludedCredential.credentialID == credential.id
                        } ?? false
                    }
                    
                    if excludeCredentialsHit {
                        throw AuthorizationError(type: .excludeCredentialsMatch)
                    }
                }
            }
            
            self.credentialsByRPID[typed.relyingPartyIdentifier, default: []].append(credential)
            
            let attestationResponse = try createAttestationResponse(
                rp: RelyingParty(id: typed.relyingPartyIdentifier, origin: "https://" + typed.relyingPartyIdentifier),
                cred: credential,
                options: AttestationOptions(challenge: typed.challenge)
            )
            
            return AuthorizationResult(credential: attestationResponse)
            
        default:
            throw AuthorizationError(type: .unhandled)
        }
    }
        
    @MainActor
    public func removeCredential(relyingPartyID: String, credentialID: Data) -> Credential? {
        if let toDeleteIndex = self.credentialsByRPID[relyingPartyID]?.firstIndex(where: { $0.id == credentialID }) {
            return self.credentialsByRPID[relyingPartyID]?.remove(at: toDeleteIndex)
        }
        
        return nil
    }
    
    public func cancel() async {
        return
    }
    
    private func fetchControlCommand(path: String) async -> (TimeInterval, AuthorizationErrorType?) {
        guard let baseURL = controlServerURL else {
            print("Info: controlServerURL is nil.")
            return (0, nil)
        }
        
        guard let fullURL = URL(string: path, relativeTo: baseURL) ?? URL(string: baseURL.absoluteString + path) else {
            print("Error: Could not construct full URL from \(baseURL) and \(path)")
            return (0, nil)
        }
        
        var request = URLRequest(url: fullURL)
        request.httpMethod = "GET"
        do {
            let (data, response) = try await URLSession.shared.data(for: request)
            
            guard let httpResponse = response as? HTTPURLResponse else {
                print("Error: Response is not an HTTPURLResponse.")
                return (0, nil)
            }
            
            guard (200...299).contains(httpResponse.statusCode) else {
                print("Error: HTTP request failed with status code \(httpResponse.statusCode).")
                return (0, nil)
            }
            
            let decoder = JSONDecoder()
            let apiResponse = try decoder.decode(ControlServerAPIResponse.self, from: data)
            return (apiResponse.delay, apiResponse.error)
            
        } catch {
            print("Error: Network request failed: \(error.localizedDescription)")
            return (0, nil)
        }
    }
}


