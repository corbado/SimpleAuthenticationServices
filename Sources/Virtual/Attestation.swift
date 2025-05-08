import Foundation
import CryptoKit
import CBORCoding
import SimpleAuthenticationServices

public struct RelyingParty {
    let id: String
    let origin: String
}

public struct AttestationOptions {
    let challenge: Data
}

fileprivate struct ClientDataPayload: Codable {
    let type: String
    let challenge: String
    let origin: String
}

fileprivate struct AttestationStatement: Codable {
    let alg: Int
    let sig: Data
}

fileprivate struct AttestationObjectPayload: Codable {
    let fmt: String
    let attStmt: AttestationStatement
    let authData: Data
}

struct AttestationResponsePayload: Codable {
    let attestationObject: String
    let clientDataJSON: String
}

struct AttestationResultPayload: Codable {
    let type: String
    let id: String
    let rawId: String
    let response: AttestationResponsePayload
}

fileprivate let ec2SHA256Algo: Int = -7
fileprivate let rsaSHA256Algo: Int = -257
fileprivate let defaultAAGUID: Data = dataFromHexString("fbfc3007154e4ecc8c0b6e020557d7bd")!

extension Data {
    func base64UrlEncodedString() -> String {
        var base64 = self.base64EncodedString()
        base64 = base64.replacingOccurrences(of: "+", with: "-")
        base64 = base64.replacingOccurrences(of: "/", with: "_")
        base64 = base64.replacingOccurrences(of: "=", with: "")
        return base64
    }
}


fileprivate func uint16ToBigEndianData(_ value: UInt16) -> Data {
    var bigEndian = value.bigEndian
    return Data(bytes: &bigEndian, count: MemoryLayout<UInt16>.size)
}

func uint32ToBigEndianData(_ value: UInt32) -> Data {
    var bigEndian = value.bigEndian
    return Data(bytes: &bigEndian, count: MemoryLayout<UInt32>.size)
}

func createAttestationResponse(rp: RelyingParty, cred: Credential, options: AttestationOptions) throws -> PasskeyRegistrationCredential {
    let clientData = ClientDataPayload(
        type: "webauthn.create",
        challenge: options.challenge.base64UrlEncodedString(),
        origin: rp.origin
    )
    let clientDataJSON = try JSONEncoder().encode(clientData)
    let publicKeyData = try cred.key.attestationData()

    var attestedCredentialData = Data()
    attestedCredentialData.append(defaultAAGUID) // AAGUID
    attestedCredentialData.append(uint16ToBigEndianData(UInt16(cred.id.count))) // Credential ID Length
    attestedCredentialData.append(cred.id) // Credential ID
    attestedCredentialData.append(publicKeyData) // Credential Public Key (COSE_Key)

    let rpIDHash = Data(SHA256.hash(data: Data(rp.id.utf8)))

    // Bit 0 (UP) = 1
    // Bit 2 (UV) = 1
    // Bit 3 (BE) = 1
    // Bit 4 (BS) = 1
    // Bit 6 (AT) = 1
    // Value = 93 (0x5D)
    let flags: UInt8 = 0x5D
    
    var authData = Data()
    authData.append(rpIDHash)
    authData.append(flags)
    authData.append(uint32ToBigEndianData(cred.counter)) // Sign Count
    authData.append(attestedCredentialData) // Attested Credential Data

    let clientDataJSONHashed = Data(SHA256.hash(data: clientDataJSON))
    var dataToSign = Data()
    dataToSign.append(authData)
    dataToSign.append(clientDataJSONHashed)

    let digestToSign = SHA256.hash(data: dataToSign)
    let signature = try cred.key.sign(digest: digestToSign)
    
    var algo: Int
    switch cred.key.type {
    case .ec2:
        algo = ec2SHA256Algo
    }

    let attestationStatement = AttestationStatement(
        alg: algo,
        sig: signature
    )

    let attestationObject = AttestationObjectPayload(
        fmt: "packed",
        attStmt: attestationStatement,
        authData: authData
    )

    let encoder = CBOREncoder()
    let attestationObjectBytes = try! encoder.encode(attestationObject)

    return PasskeyRegistrationCredential(
        credentialID: cred.id,
        rawClientDataJSON: clientDataJSON,
        rawAttestationObject: attestationObjectBytes,
        transports: []
    )
}

func dataFromHexString(_ hex: String) -> Data? {
    var data = Data(capacity: hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
        let nextIndex = hex.index(index, offsetBy: 2)
        if nextIndex > hex.endIndex { // Ensure we have a full byte pair
            return nil // Or handle partial byte differently
        }
        let byteString = hex[index..<nextIndex]
        if let byte = UInt8(byteString, radix: 16) {
            data.append(byte)
        } else {
            return nil // Invalid hex character
        }
        index = nextIndex
    }
    return data
}

