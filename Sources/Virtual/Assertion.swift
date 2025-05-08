import Foundation
import CryptoKit
import CBORCoding
import SimpleAuthenticationServices

public struct AssertionOptions {
    let challenge: Data
    let rpId: String
    let allowCredentials: [CredentialDescriptor]?
    let userVerificationRequired: Bool
}

public struct CredentialDescriptor {
    let id: Data
}

fileprivate struct AssertionClientDataPayload: Codable {
    let type: String
    let challenge: String
    let origin: String
}

struct AssertionResponsePayload: Codable {
    let authenticatorData: String // Base64URL encoded
    let clientDataJSON: String    // Base64URL encoded
    let signature: String         // Base64URL encoded
    let userHandle: String?       // Base64URL encoded (optional, for discoverable credentials)
}

struct AssertionResultPayload: Codable {
    let type: String
    let id: String        // Base64URL encoded credential ID
    let rawId: String     // Base64URL encoded credential ID (matches `rawId` from Go JSON tag)
    let response: AssertionResponsePayload
}
func createAssertionResponse(rp: RelyingParty, credentials: [Credential], options: AssertionOptions) throws -> PasskeyAssertionCredential {
    let clientData = AssertionClientDataPayload(
        type: "webauthn.get",
        challenge: options.challenge.base64UrlEncodedString(),
        origin: rp.origin
    )
    let clientDataJSON = try JSONEncoder().encode(clientData)

    let rpIDHash = Data(SHA256.hash(data: Data(rp.id.utf8)))

    let filteredCredentials = credentials.filter { c in
        let allowCredentials = options.allowCredentials ?? []
        if allowCredentials.isEmpty {
            return true
        }
        
        return allowCredentials.contains(where: { $0.id == c.id })
    }
    
    // for now, we always take the first credential
    guard let cred = filteredCredentials.first else {
        throw AuthorizationError(type: .noCredentialsAvailable)
    }
    
    // Bit 0 (UP) = 1
    // Bit 2 (UV) = 1
    // Bit 3 (BE) = 1
    // Bit 4 (BS) = 1
    // Bit 6 (AT) = 0 (assertion)
    // Value = 29 (0x1D)
    let flags: UInt8 = 0x1D
    var authenticatorData = Data()
    authenticatorData.append(rpIDHash)
    authenticatorData.append(flags)
    authenticatorData.append(uint32ToBigEndianData(cred.counter + 1))

    let clientDataJSONHash = Data(SHA256.hash(data: clientDataJSON))
    var dataToSign = Data()
    dataToSign.append(authenticatorData)
    dataToSign.append(clientDataJSONHash)

    let digestToSign = SHA256.hash(data: dataToSign)
    let signature = try cred.key.sign(digest: digestToSign)

    return PasskeyAssertionCredential(
        credentialID: cred.id,
        rawClientDataJSON: clientDataJSON,
        rawAuthenticatorData: authenticatorData,
        signature: signature,
        userID: cred.userID
    )
}
