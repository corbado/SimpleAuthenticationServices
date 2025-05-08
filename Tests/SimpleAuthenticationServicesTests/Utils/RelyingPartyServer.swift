import Foundation

enum RPServerError: Error {
    case invalidURL
    case networkError(Error)
    case httpError(statusCode: Int, message: String?)
    case decodingError(Error)
    case encodingError(Error)
    case serverMessage(String)
    case missingChallenge
}

struct RPRegistrationStartResponse: Codable {
    let publicKey: RPPublicKeyCredentialCreationOptions
}

struct RPPublicKeyCredentialCreationOptions: Codable {
    struct RP: Codable {
        let id: String
        let name: String
        let icon: String?
    }
    struct User: Codable {
        let id: String // Base64URL encoded
        let name: String
        let displayName: String
        let icon: String?
    }
    struct PubKeyCredParam: Codable {
        let alg: Int // COSEAlgorithmIdentifier
        let type: String // e.g., "public-key"
    }
    struct AuthenticatorSelection: Codable {
        let authenticatorAttachment: String? // e.g., "platform", "cross-platform"
        let requireResidentKey: Bool?
        let residentKey: String? // e.g., "preferred", "required", "discouraged"
        let userVerification: String? // e.g., "required", "preferred", "discouraged"
    }
    struct ExcludeCredentialDescriptor: Codable {
        let id: String // Base64URL encoded
        let type: String // e.g., "public-key"
        let transports: [String]? // e.g., ["internal", "usb", "nfc", "ble"]
    }
    
    let rp: RP
    let user: User
    let challenge: String // Base64URL encoded
    let pubKeyCredParams: [PubKeyCredParam]
    let timeout: Int?
    let excludeCredentials: [ExcludeCredentialDescriptor]?
    let authenticatorSelection: AuthenticatorSelection?
    let attestation: String? // e.g., "none", "indirect", "direct"
    // let extensions: [String: Any]? // More complex to make Codable, use [String: String] or a library like AnyCodable if needed
}

struct RPPlatformPublicKeyCredentialRegistration: Codable {
    struct Response: Codable {
        let clientDataJSON: String // Base64URL encoded
        let attestationObject: String // Base64URL encoded
        let transports: [String]? // Optional: "internal", "hybrid", "nfc", "usb", "ble"
    }
    let id: String // Base64URL encoded credential ID
    let rawId: String // Base64URL encoded credential ID (often same as id)
    let type: String // Usually "public-key"
    let response: Response
    // let clientExtensionResults: [String: Any]? // Similar to extensions above
}

struct RPAssertionStartResponse: Codable {
    let publicKey: RPPublicKeyCredentialRequestOptions
}


struct RPPublicKeyCredentialRequestOptions: Codable {
    struct AllowCredentialDescriptor: Codable {
        let id: String // Base64URL encoded
        let type: String // e.g., "public-key"
        let transports: [String]? // e.g., ["internal", "usb", "nfc", "ble"]
    }
    
    let challenge: String // Base64URL encoded
    let timeout: Int?
    let rpId: String? // Relying Party ID
    let allowCredentials: [AllowCredentialDescriptor]? // Optional, for non-discoverable credentials
    let userVerification: String? // e.g., "required", "preferred", "discouraged"
    // let extensions: [String: Any]? // More complex
}

struct RPPlatformPublicKeyCredentialAssertion: Codable {
    struct Response: Codable {
        let clientDataJSON: String // Base64URL encoded
        let authenticatorData: String // Base64URL encoded
        let signature: String // Base64URL encoded
        let userHandle: String? // Base64URL encoded, present if resident key was used
    }
    let id: String // Base64URL encoded credential ID that was used
    let rawId: String // Base64URL encoded credential ID (often same as id)
    let type: String // Usually "public-key"
    let response: Response
    // let clientExtensionResults: [String: Any]?
}

@MainActor
class RelyingPartyServer {
    private let baseURL: URL
    private let session: URLSession
    
    init(baseURLString: String, session: URLSession = .shared) throws {
        guard let url = URL(string: baseURLString) else {
            throw RPServerError.invalidURL
        }
        self.baseURL = url
        self.session = session
    }
    
    /// Sends the client's attestation response to the server to finalize registration.
    func registerStart(username: String) async throws -> RPRegistrationStartResponse {
        var components = URLComponents(url: baseURL.appendingPathComponent("register/start"), resolvingAgainstBaseURL: false)
        components?.queryItems = [URLQueryItem(name: "username", value: username)]
        
        guard let url = components?.url else {
            throw RPServerError.invalidURL
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        return try await performDataTask(with: request)
    }
    
    func registerFinish(username: String, registrationData: RPPlatformPublicKeyCredentialRegistration) async throws {
        var components = URLComponents(url: baseURL.appendingPathComponent("register/finish"), resolvingAgainstBaseURL: false)
        components?.queryItems = [URLQueryItem(name: "username", value: username)]
        
        guard let url = components?.url else {
            throw RPServerError.invalidURL
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        do {
            request.httpBody = try JSONEncoder().encode(registrationData)
        } catch {
            throw RPServerError.encodingError(error)
        }
        
        // Perform the task, but we don't need to decode a specific body for success
        _ = try await performDataTaskReturningData(with: request)
    }
    
    func loginStart(username: String? = nil) async throws -> RPAssertionStartResponse {
        var components = URLComponents(url: baseURL.appendingPathComponent("login/start"), resolvingAgainstBaseURL: false)
        if let username = username, !username.isEmpty {
            components?.queryItems = [URLQueryItem(name: "username", value: username)]
        }
        
        guard let url = components?.url else {
            throw RPServerError.invalidURL
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        return try await performDataTask(with: request)
    }
    
    func loginFinish(username: String? = nil, assertionData: RPPlatformPublicKeyCredentialAssertion) async throws {
        var components = URLComponents(url: baseURL.appendingPathComponent("login/finish"), resolvingAgainstBaseURL: false)
        if let username = username, !username.isEmpty {
            components?.queryItems = [URLQueryItem(name: "username", value: username)]
        }
        
        guard let url = components?.url else {
            throw RPServerError.invalidURL
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        
        do {
            request.httpBody = try JSONEncoder().encode(assertionData)
        } catch {
            throw RPServerError.encodingError(error)
        }
        
        _ = try await performDataTaskReturningData(with: request)
    }
    
    /// Generic helper to perform data tasks and decode JSON
    private func performDataTask<T: Decodable>(with request: URLRequest) async throws -> T {
        let (data, response) = try await session.data(for: request) // Modern URLSession async API
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw RPServerError.networkError(URLError(.badServerResponse))
        }
        
        guard (200...299).contains(httpResponse.statusCode) else {
            var errorMessage: String?
            if let msg = String(data: data, encoding: .utf8) {
                errorMessage = msg.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            throw RPServerError.httpError(statusCode: httpResponse.statusCode, message: errorMessage)
        }
        
        do {
            let decodedObject = try JSONDecoder().decode(T.self, from: data)
            return decodedObject
        } catch {
            throw RPServerError.decodingError(error)
        }
    }
    
    /// Generic helper for tasks that don't expect a decodable JSON body on success (e.g., just a 200 OK)
    private func performDataTaskReturningData(with request: URLRequest) async throws -> Data? {
        let (data, response) = try await session.data(for: request)
        guard let httpResponse = response as? HTTPURLResponse else {
            throw RPServerError.networkError(URLError(.badServerResponse))
        }
        
        guard (200...299).contains(httpResponse.statusCode) else {
            var errorMessage: String?
            if let msg = String(data: data, encoding: .utf8) {
                errorMessage = msg.trimmingCharacters(in: .whitespacesAndNewlines)
            }
            
            throw RPServerError.httpError(statusCode: httpResponse.statusCode, message: errorMessage)
        }
        
        return data.isEmpty ? nil : data
    }
    
    func checkHealth() async -> Bool {
        let url = baseURL.appendingPathComponent("health")
        var request = URLRequest(url: url)
        request.httpMethod = "GET"
        
        do {
            let (data, response) = try await session.data(for: request)
            guard let httpResponse = response as? HTTPURLResponse,
                  httpResponse.statusCode == 200,
                  let body = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
                  body == "OK" else {
                return false
            }
            return true
        } catch {
            return false
        }
    }
}
