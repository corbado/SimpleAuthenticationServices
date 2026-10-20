import AuthenticationServices
import Foundation
import Testing

@testable import SimpleAuthenticationServices

@Test func attachmentUsesWebAuthnValues() {
    #expect(PasskeyAuthenticatorAttachment.platform.rawValue == "platform")
    #expect(PasskeyAuthenticatorAttachment.crossPlatform.rawValue == "cross-platform")
}

@available(iOS 16.6, macOS 13.5, *)
@Test func mapsNativeAttachment() {
    #expect(passkeyAttachment(.platform) == .platform)
    #expect(passkeyAttachment(.crossPlatform) == .crossPlatform)
}

@available(iOS 17.5, macOS 14.5, *)
@Test func mapsSecurityKeyTransportsToWebAuthnNames() {
    #expect(webAuthnTransportName(.usb) == "usb")
    #expect(webAuthnTransportName(.nfc) == "nfc")
    #expect(webAuthnTransportName(.bluetooth) == "ble")
    #expect(webAuthnTransportName(.init(rawValue: "something-new")) == nil)
}

@Test func newCredentialFieldsDefaultToUnreported() {
    let registration = PasskeyRegistrationCredential(
        credentialID: Data([1]),
        rawClientDataJSON: Data(),
        rawAttestationObject: Data(),
        transports: ["usb", "ble"].map { Data($0.utf8) }
    )
    #expect(registration.attachment == nil)
    #expect(registration.clientExtensionResults.isEmpty)
    #expect(registration.transportNames == ["usb", "ble"])

    let assertion = PasskeyAssertionCredential(
        credentialID: Data([1]),
        rawClientDataJSON: Data(),
        rawAuthenticatorData: Data(),
        signature: Data(),
        userID: Data()
    )
    #expect(assertion.attachment == nil)
    #expect(assertion.clientExtensionResults.isEmpty)
}
