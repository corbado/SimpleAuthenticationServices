import Foundation
import CryptoKit
import CBORCoding

enum WebAuthnError: Error {
    case invalidKeyType(String)
    case keyGenerationFailed(String)
    case keyImportFailed(String)
    case signingFailed(String)
    case internalError(String)
}

enum KeyType: String, Codable, CaseIterable {
    case ec2 = "ec2"
}

protocol SigningKey {
    func attestationData() throws -> Data
    func sign<D: Digest>(digest: D) throws -> Data
    var rawPrivateKeyData: Data { get }
}

class EC2SigningKey: SigningKey {
    let rawPrivateKeyData: Data
    private let privateKey: P256.Signing.PrivateKey
    
    convenience init() throws {
        let newPrivateKey = P256.Signing.PrivateKey()
        try self.init(privateKeyData: newPrivateKey.x963Representation)
    }
    
    init(privateKeyData: Data) throws {
        self.rawPrivateKeyData = privateKeyData
        do {
            self.privateKey = try P256.Signing.PrivateKey(x963Representation: privateKeyData)
        } catch {
            throw WebAuthnError.keyImportFailed("Failed to import EC2 private key: \(error.localizedDescription)")
        }
    }
    
    func attestationData() throws -> Data {
        let cborEncoder = CBOREncoder()
        let cryptoKitPublicKey = privateKey.publicKey
        let x963Representation = cryptoKitPublicKey.x963Representation
        guard x963Representation.count == 65 && x963Representation[0] == 0x04 else {
            throw NSError(domain: "COSE", code: 0, userInfo: [NSLocalizedDescriptionKey: "Invalid P256 public key format"])
        }
        let xCoord = x963Representation[1...32]
        let yCoord = x963Representation[33...64]
        
        let cosePublicKey = COSEEC2PublicKey(
            kty: 2,
            alg: -7,
            crv: 1,
            x: xCoord,
            y: yCoord
        )
        
        return try cborEncoder.encode(cosePublicKey)
    }
    
    func sign<D: Digest>(digest: D) throws -> Data {
        do {
            let signature = try privateKey.signature(for: digest)
            print("EC2SigningKey: sign() called. Produced signature of size \(signature.rawRepresentation.count)")
            return signature.derRepresentation // Or DER representation if required
        } catch {
            throw WebAuthnError.signingFailed("EC2 signing failed: \(error.localizedDescription)")
        }
    }
}

public final class Key: Codable {
    let type: KeyType
    let data: Data
    private var _signingKey: SigningKey?
    
    init(newWithType type: KeyType) throws {
        self.type = type
        let concreteSigningKey: SigningKey
        switch type {
        case .ec2:
            concreteSigningKey = try EC2SigningKey()
        }
        self.data = concreteSigningKey.rawPrivateKeyData
        self._signingKey = concreteSigningKey
        print("Key: Initialized new \(type) key. Data size: \(self.data.count)")
    }
    
    init(type: KeyType, data: Data) {
        self.type = type
        self.data = data
        self._signingKey = nil // Will be lazy-loaded
        print("Key: Imported \(type) key. Data size: \(self.data.count). Signing key will be loaded on demand.")
    }
    
    enum CodingKeys: String, CodingKey {
        case type
        case data
    }
    
    public required init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.type = try container.decode(KeyType.self, forKey: .type)
        self.data = try container.decode(Data.self, forKey: .data)
        self._signingKey = nil // Lazy load on demand
        print("Key: Decoded \(type) key. Data size: \(self.data.count). Signing key will be loaded on demand.")
    }
    
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(type, forKey: .type)
        try container.encode(data, forKey: .data)
    }
    
    private func ensureSigningKey() throws {
        // If already initialized, do nothing
        if _signingKey != nil {
            return
        }
        
        switch type {
        case .ec2:
            self._signingKey = try EC2SigningKey(privateKeyData: data)
        }
        if _signingKey == nil {
            throw WebAuthnError.internalError("Failed to initialize signing key instance for type \(type)")
        }
    }
    
    func attestationData() throws -> Data {
        try ensureSigningKey()
        guard let sk = _signingKey else {
            throw WebAuthnError.internalError("Signing key not initialized after ensure for attestation.")
        }
        return try sk.attestationData()
    }
    
    func sign<D: Digest>(digest: D) throws -> Data {
        try ensureSigningKey()
        guard let sk = _signingKey else {
            throw WebAuthnError.internalError("Signing key not initialized after ensure for signing.")
        }
        return try sk.sign(digest: digest)
    }
}

struct COSEEC2PublicKey: Codable {
    let kty: Int
    let alg: Int
    let crv: Int
    let x: Data
    let y: Data
    
    enum CodingKeys: Int, CodingKey {
        case kty = 1
        case alg = 3
        case crv = -1
        case x   = -2
        case y   = -3
    }
}
