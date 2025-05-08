import Foundation
import Security

public struct Credential {
    public let key: Key
    public var counter: UInt32
    public let id: Data
    public let userID: Data
    
    public init(key: Key, userID: Data) {
        self.key = key
        self.counter = 0
        self.userID = userID
        
        var randomBytes = [UInt8](repeating: 0, count: 32)
        let status = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)

        if status == errSecSuccess {
            self.id = Data(randomBytes)
        } else {
            self.id = UUID().uuidString.data(using: .utf8) ?? Data()
        }
    }
}
