import AuthenticationServices
import CryptoKit

// Maps the authenticator attachment and client extension outputs reported by
// AuthenticationServices to the library's Sendable value types.

@available(iOS 16.6, macOS 13.5, *)
func passkeyAttachment(_ attachment: ASAuthorizationPublicKeyCredentialAttachment) -> PasskeyAuthenticatorAttachment? {
    switch attachment {
    case .platform:
        return .platform
    case .crossPlatform:
        return .crossPlatform
    @unknown default:
        return nil
    }
}

@available(iOS 16.0, macOS 13.0, *)
func passkeyAttachment(of assertion: ASAuthorizationPlatformPublicKeyCredentialAssertion) -> PasskeyAuthenticatorAttachment? {
    if #available(iOS 16.6, macOS 13.5, *) {
        return passkeyAttachment(assertion.attachment)
    }
    return nil
}

@available(iOS 16.0, macOS 13.0, *)
func passkeyAttachment(of registration: ASAuthorizationPlatformPublicKeyCredentialRegistration) -> PasskeyAuthenticatorAttachment? {
    if #available(iOS 16.6, macOS 13.5, *) {
        return passkeyAttachment(registration.attachment)
    }
    return nil
}

@available(iOS 16.0, macOS 13.0, *)
func clientExtensionResults(of assertion: ASAuthorizationPlatformPublicKeyCredentialAssertion) -> PasskeyClientExtensionResults {
    var largeBlob: PasskeyClientExtensionResults.LargeBlob?
    var prf: PasskeyClientExtensionResults.PRF?

    if #available(iOS 17.0, macOS 14.0, *), let output = assertion.largeBlob {
        switch output.result {
        case .read(let data):
            largeBlob = .init(blob: data)
        case .write(let success):
            largeBlob = .init(written: success)
        @unknown default:
            break
        }
    }

    if #available(iOS 18.0, macOS 15.0, *), let output = assertion.prf {
        prf = .init(first: output.first.rawData, second: output.second?.rawData)
    }

    return PasskeyClientExtensionResults(largeBlob: largeBlob, prf: prf)
}

@available(iOS 16.0, macOS 13.0, *)
func clientExtensionResults(of registration: ASAuthorizationPlatformPublicKeyCredentialRegistration) -> PasskeyClientExtensionResults {
    var largeBlob: PasskeyClientExtensionResults.LargeBlob?
    var prf: PasskeyClientExtensionResults.PRF?

    if #available(iOS 17.0, macOS 14.0, *), let output = registration.largeBlob {
        largeBlob = .init(supported: output.isSupported)
    }

    if #available(iOS 18.0, macOS 15.0, *), let output = registration.prf {
        prf = .init(enabled: output.isSupported, first: output.first?.rawData, second: output.second?.rawData)
    }

    return PasskeyClientExtensionResults(largeBlob: largeBlob, prf: prf)
}

/// Maps security-key transports to WebAuthn transport names; unknown values are dropped.
@available(iOS 17.5, macOS 14.5, *)
func webAuthnTransportName(_ transport: ASAuthorizationSecurityKeyPublicKeyCredentialDescriptor.Transport) -> String? {
    switch transport {
    case .usb:
        return "usb"
    case .nfc:
        return "nfc"
    case .bluetooth:
        return "ble"
    default:
        return nil
    }
}

private extension SymmetricKey {
    var rawData: Data {
        withUnsafeBytes { Data($0) }
    }
}
