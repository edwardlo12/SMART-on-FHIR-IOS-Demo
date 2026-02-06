import Foundation
import KeychainAccess

class KeychainHelper {
    static let shared = KeychainHelper()
    let keychain = Keychain(service: "com.yourcompany.smartfhirdemo")
    
    func saveToken(_ token: String, forKey key: String) {
        keychain[key] = token
    }
    
    func getToken(forKey key: String) -> String? {
        return keychain[key]
    }
    
    func deleteToken(forKey key: String) {
        try? keychain.remove(key)
    }
}
