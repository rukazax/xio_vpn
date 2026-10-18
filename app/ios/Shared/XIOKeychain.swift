import Foundation
import Security

enum XIOKeychain {
  static let sharedSuite = "group.app.xio.client"
  static func sharedGroup() throws -> String {
    guard let value = Bundle.main.object(forInfoDictionaryKey: "XIOKeychainGroup") as? String,
          !value.isEmpty, !value.contains("$(") else {
      throw NSError(domain: "XIO", code: 1, userInfo: [NSLocalizedDescriptionKey: "Apple signing and shared keychain entitlement are required."])
    }
    return value
  }
  static func query(_ account: String, profile: Bool) throws -> [String: Any] {
    guard account.range(of: "^[a-zA-Z0-9]{1,100}$", options: .regularExpression) != nil else {
      throw NSError(domain: "XIO", code: 2)
    }
    var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
      kSecAttrService as String: profile ? "app.xio.profiles" : "app.xio.credentials",
      kSecAttrAccount as String: account]
    // SSH credentials stay in the host application's private keychain group.
    // Only VPN client configurations are shared with NetworkExtension.
    if profile { q[kSecAttrAccessGroup as String] = try sharedGroup() }
    return q
  }
  static func read(_ account: String, profile: Bool) throws -> String? {
    var q = try query(account, profile: profile)
    q[kSecReturnData as String] = true; q[kSecMatchLimit as String] = kSecMatchLimitOne
    var value: CFTypeRef?; let code = SecItemCopyMatching(q as CFDictionary, &value)
    if code == errSecItemNotFound { return nil }
    guard code == errSecSuccess, let data = value as? Data, let text = String(data: data, encoding: .utf8) else {
      throw NSError(domain: NSOSStatusErrorDomain, code: Int(code))
    }
    return text
  }
  static func write(_ account: String, value: String, profile: Bool) throws {
    let q = try query(account, profile: profile)
    let attrs: [String: Any] = [kSecValueData as String: Data(value.utf8),
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
    var code = SecItemUpdate(q as CFDictionary, attrs as CFDictionary)
    if code == errSecItemNotFound { var add = q; add.merge(attrs) { _, new in new }; code = SecItemAdd(add as CFDictionary, nil) }
    guard code == errSecSuccess else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(code)) }
  }
  static func delete(_ account: String, profile: Bool) throws {
    let code = SecItemDelete(try query(account, profile: profile) as CFDictionary)
    guard code == errSecSuccess || code == errSecItemNotFound else { throw NSError(domain: NSOSStatusErrorDomain, code: Int(code)) }
  }
}
