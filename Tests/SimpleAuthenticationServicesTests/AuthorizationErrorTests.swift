import AuthenticationServices
import Foundation
import SimpleAuthenticationServices
import Testing

@Test func authorizationErrorDescribesTypeWithoutUnderlyingError() {
    let error: any Error = AuthorizationError(type: .noPresentationAnchor)

    #expect(error.localizedDescription == "AuthorizationError(type: noPresentationAnchor)")
}

@Test func authorizationErrorPreservesNativeDiagnostics() {
    let native = ASAuthorizationError(.failed, userInfo: [
        NSLocalizedDescriptionKey: "Authorization failed",
        NSDebugDescriptionErrorKey: "Diagnostic detail for the failed operation"
    ])
    let error: any Error = AuthorizationError(type: .unknown, originalError: native)
    let description = error.localizedDescription

    #expect(description.contains("type: unknown"))
    #expect(description.contains(ASAuthorizationError.errorDomain))
    #expect(description.contains("\(ASAuthorizationError.Code.failed.rawValue)"))
    #expect(description.contains("Authorization failed"))
    #expect(description.contains("Diagnostic detail for the failed operation"))
}

@Test func authorizationErrorPreservesNestedError() {
    let underlying = NSError(domain: "TestCredentialProvider", code: 42, userInfo: [
        NSLocalizedDescriptionKey: "Credential provider rejected the update"
    ])
    let native = ASAuthorizationError(.failed, userInfo: [
        NSUnderlyingErrorKey: underlying
    ])
    let error: any Error = AuthorizationError(type: .unknown, originalError: native)
    let description = error.localizedDescription

    #expect(description.contains("TestCredentialProvider"))
    #expect(description.contains("42"))
    #expect(description.contains("Credential provider rejected the update"))
}
