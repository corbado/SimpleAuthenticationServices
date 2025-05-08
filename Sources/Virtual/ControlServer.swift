import Foundation
import Swifter
import SimpleAuthenticationServices

struct ControlServerAPIResponse: Codable {
    let delay: TimeInterval
    let error: AuthorizationErrorType?
}

public class ControlServer {
    private let server = HttpServer()
    var port: Int?
    
    public var createError: AuthorizationErrorType?
    public var createDelay: TimeInterval = 0
    public var authorizeError: AuthorizationErrorType?
    public var authorizeDelay: TimeInterval = 0
    public var authorizeWithAutoFillError: AuthorizationErrorType?
    public var authorizeWithAutoFillErrorDelay: TimeInterval = 3600

    public init() {
        setupRoutes()
    }

    private func setupRoutes() {
        server["/create"] = { _ in
            let response = ControlServerAPIResponse(delay: self.createDelay, error: self.createError)
            do {
                let jsonData = try JSONEncoder().encode(response)
                return .ok(.data(jsonData, contentType: "application/json"))
            } catch {
                print("Control Server: Error encoding JSON: \(error)")
                return .internalServerError
            }
        }
        
        server["/authorize"] = { _ in
            let response = ControlServerAPIResponse(delay: self.authorizeDelay, error: self.authorizeError)
            do {
                let jsonData = try JSONEncoder().encode(response)
                return .ok(.data(jsonData, contentType: "application/json"))
            } catch {
                print("Control Server: Error encoding JSON: \(error)")
                return .internalServerError
            }
        }
        
        server["/authorizeWithAutoFill"] = { _ in
            let response = ControlServerAPIResponse(delay: self.authorizeWithAutoFillErrorDelay, error: self.authorizeWithAutoFillError)
            do {
                let jsonData = try JSONEncoder().encode(response)
                return .ok(.data(jsonData, contentType: "application/json"))
            } catch {
                print("Control Server: Error encoding JSON: \(error)")
                return .internalServerError
            }
        }
    }

    public func start() throws {
        // Start on port 0 to let the system pick an available port
        // This is crucial for avoiding conflicts in CI or when running multiple test suites
        try server.start(0, forceIPv4: true) // forceIPv4 can help with localhost resolution
        self.port = try server.port() // Get the actual port it's running on
        print("Control server started on: http://localhost:\(self.port!)")
    }

    public func stop() {
        server.stop()
        self.port = nil
        print("Control server stopped.")
    }

    public var baseURL: URL {
        guard let port = port else {
            fatalError("Control server does not have a valid URL")
        }
        
        return URL(string: "http://localhost:\(port)")!
    }
}
