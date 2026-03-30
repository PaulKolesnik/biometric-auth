import Foundation
import Capacitor
import LocalAuthentication
import Security

@objc(BiometricCredentialPlugin)
public class BiometricCredentialPlugin: CAPPlugin, CAPBridgedPlugin {
    private struct Record: Codable {
        let credentialId: String
        let userId: String
        let keyTag: String
        let algorithm: String
        let securityLevel: String
        var invalidated: Bool
    }

    private struct ResolveResult {
        var record: Record?
        var errorCode: String?
        var reason: String?
    }

    private struct KeyCreationResult {
        let key: SecKey
        let securityLevel: String
    }

    private let storageKey = "biometric_credential_plugin_records_v1"
    private let algorithm = "ES256"

    public let identifier = "BiometricCredentialPlugin"
    public let jsName = "BiometricCredential"
    public let pluginMethods: [CAPPluginMethod] = [
        CAPPluginMethod(name: "checkBiometry", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "checkRegistration", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "registerCredential", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "authenticate", returnType: CAPPluginReturnPromise),
        CAPPluginMethod(name: "removeCredential", returnType: CAPPluginReturnPromise)
    ]

    /// Reports biometric availability and device readiness using LocalAuthentication.
    /// Resolves with capability flags and a normalized error code when unavailable.
    /// LAContext docs: https://developer.apple.com/documentation/localauthentication/lacontext
    @objc func checkBiometry(_ call: CAPPluginCall) {
        let context = LAContext()
        var error: NSError?
        // canEvaluatePolicy docs:
        // https://developer.apple.com/documentation/localauthentication/lacontext/canevaluatepolicy(_:error:)
        let available = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)

        let biometryType: String
        if #available(iOS 11.0, *) {
            // biometryType docs:
            // https://developer.apple.com/documentation/localauthentication/lacontext/biometrytype
            switch context.biometryType {
            case .faceID:
                biometryType = "faceId"
            case .touchID:
                biometryType = "touchId"
            case .none:
                biometryType = "none"
            @unknown default:
                biometryType = "none"
            }
        } else {
            biometryType = available ? "touchId" : "none"
        }

        call.resolve([
            "isAvailable": available,
            "strongBiometryIsAvailable": available,
            "biometryType": biometryType,
            "biometryTypes": available ? [biometryType] : ["none"],
            "deviceIsSecure": available,
            "meetsSecurityRequirements": available,
            "reason": available ? "Biometric authentication is available." : reasonForLAError(error),
            "code": available ? "" : mapLAErrorCode(error)
        ])
    }

    /// Checks whether a credential exists for the provided explicit selector.
    /// Selector may be by `credentialId`, `userId`, or both when they are consistent.
    @objc func checkRegistration(_ call: CAPPluginCall) {
        let userId = normalize(call.getString("userId"))
        let credentialId = normalize(call.getString("credentialId"))
        let resolved = resolveRecord(userId: userId, credentialId: credentialId)

        if let code = resolved.errorCode {
            call.resolve([
                "isRegistered": false,
                "reason": resolved.reason ?? "Invalid selector.",
                "code": code,
            ])
            return
        }

        guard let record = resolved.record else {
            call.resolve([
                "isRegistered": false,
                "reason": "No credential found for supplied selector.",
                "code": "credentialNotFound",
            ])
            return
        }

        call.resolve([
            "isRegistered": true,
            "credentialId": record.credentialId,
            "userId": record.userId,
            "securityLevel": record.securityLevel,
            "invalidated": record.invalidated,
            "code": record.invalidated ? "credentialInvalidated" : "",
            "reason": record.invalidated ? "Credential was invalidated in local store." : NSNull(),
        ])
    }

    /// Registers a new biometric credential and generates a secure key pair.
    /// Enforces duplicate protections and optionally requires hardware-backed key storage.
    @objc func registerCredential(_ call: CAPPluginCall) {
        guard let userId = normalize(call.getString("userId")),
              let credentialId = normalize(call.getString("credentialId")) else {
            call.reject("userId and credentialId are required.", "configurationError")
            return
        }

        guard let challenge = normalize(call.getString("challenge")) else {
            call.reject("Challenge is required.", "challengeMissing")
            return
        }

        guard validateBase64Url(challenge) else {
            call.reject("Challenge must be a base64url non-empty string.", "challengeInvalid")
            return
        }

        let records = loadRecords()
        if records.contains(where: { $0.credentialId == credentialId }) {
            call.reject("Credential already exists for this credentialId.", "credentialAlreadyExists")
            return
        }

        if records.contains(where: { $0.userId == userId }) {
            call.reject("A credential already exists for this user on this device.", "credentialAlreadyExists")
            return
        }

        let reason = normalize(call.getString("iosPromptReason")) ?? "Verify your identity"
        let requireHardwareBacked = call.getBool("requireHardwareBackedKey", false)
        let detectCompromised = call.getBool("detectCompromisedDevice", false)
        let compromisedSignal = detectCompromised ? isCompromisedDevice() : false

        authenticateBiometric(reason: reason) { [weak self] success, error, _ in
            guard let self = self else { return }

            guard success else {
                call.reject(self.reasonForLAError(error), self.mapLAErrorCode(error))
                return
            }

            let tag = self.keyTag(for: credentialId)
            guard let keyResult = self.createPrivateKey(
                tag: tag,
                invalidateOnEnrollmentChange: call.getBool("invalidateOnBiometricEnrollmentChange", true),
                requireHardwareBacked: requireHardwareBacked
            ) else {
                call.reject("Failed to generate secure key.", "keyGenerationFailed")
                return
            }

            if requireHardwareBacked && keyResult.securityLevel != "secureEnclave" {
                _ = self.deletePrivateKey(tag: tag)
                call.reject("Hardware-backed key is required by policy.", "securityLevelInsufficient")
                return
            }

            // SecKeyCopyPublicKey docs:
            // https://developer.apple.com/documentation/security/1394661-seckeycopypublickey
            // SecKeyCopyExternalRepresentation docs:
            // https://developer.apple.com/documentation/security/1643698-seckeycopyexternalrepresentation
            guard let publicKey = SecKeyCopyPublicKey(keyResult.key),
                  let publicData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
                call.reject("Failed to extract public key.", "keyGenerationFailed")
                return
            }

            let payload = self.buildCanonicalPayload(type: "registration", challenge: challenge, credentialId: credentialId, userId: userId)
            guard let payloadData = payload.data(using: .utf8) else {
                call.reject("Failed to encode payload.", "signatureFailed")
                return
            }

            var signError: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(keyResult.key, .ecdsaSignatureMessageX962SHA256, payloadData as CFData, &signError) as Data? else {
                call.reject("Failed to sign registration payload.", "signatureFailed")
                return
            }

            var updated = records
            updated.append(Record(
                credentialId: credentialId,
                userId: userId,
                keyTag: tag,
                algorithm: self.algorithm,
                securityLevel: keyResult.securityLevel,
                invalidated: false
            ))
            self.saveRecords(updated)

            var result: [String: Any] = [
                "credentialId": credentialId,
                "userId": userId,
                "publicKey": self.toBase64Url(publicData),
                "algorithm": self.algorithm,
                "securityLevel": keyResult.securityLevel,
                "signature": self.toBase64Url(signature),
                "signedPayload": self.toBase64Url(payloadData),
            ]
            if detectCompromised {
                result["compromisedDeviceSignal"] = compromisedSignal
            }

            call.resolve(result)
        }
    }

    /// Authenticates the user and signs a canonical payload with the stored private key.
    /// Rejects when selector resolution fails, key is invalidated, or signing cannot complete.
    @objc func authenticate(_ call: CAPPluginCall) {
        let userId = normalize(call.getString("userId"))
        let credentialId = normalize(call.getString("credentialId"))

        guard let challenge = normalize(call.getString("challenge")) else {
            call.reject("Challenge is required.", "challengeMissing")
            return
        }

        guard validateBase64Url(challenge) else {
            call.reject("Challenge must be a base64url non-empty string.", "challengeInvalid")
            return
        }

        let resolved = resolveRecord(userId: userId, credentialId: credentialId)
        if let code = resolved.errorCode {
            call.reject(resolved.reason ?? "Invalid selector.", code)
            return
        }

        guard let record = resolved.record else {
            call.reject("No credential found for supplied selector.", "credentialNotFound")
            return
        }

        if record.invalidated {
            call.reject("Credential is invalidated and cannot be used.", "credentialInvalidated")
            return
        }

        let reason = normalize(call.getString("iosPromptReason")) ?? "Verify your identity"
        let detectCompromised = call.getBool("detectCompromisedDevice", false)
        let compromisedSignal = detectCompromised ? isCompromisedDevice() : false

        authenticateBiometric(reason: reason) { [weak self] success, error, authContext in
            guard let self = self else { return }

            guard success else {
                call.reject(self.reasonForLAError(error), self.mapLAErrorCode(error))
                return
            }

            let payload = self.buildCanonicalPayload(type: "authentication", challenge: challenge, credentialId: record.credentialId, userId: record.userId)
            guard let payloadData = payload.data(using: .utf8) else {
                call.reject("Failed to encode payload.", "signatureFailed")
                return
            }

            guard let privateKey = self.loadPrivateKey(tag: record.keyTag, context: authContext) else {
                self.markInvalidated(credentialId: record.credentialId)
                call.reject("Credential key is unavailable or invalidated.", "credentialInvalidated")
                return
            }

            var signError: Unmanaged<CFError>?
            // SecKeyCreateSignature docs:
            // https://developer.apple.com/documentation/security/1643698-seckeycreatesignature
            guard let signature = SecKeyCreateSignature(privateKey, .ecdsaSignatureMessageX962SHA256, payloadData as CFData, &signError) as Data? else {
                call.reject("Failed to sign authentication payload.", "signatureFailed")
                return
            }

            var result: [String: Any] = [
                "credentialId": record.credentialId,
                "userId": record.userId,
                "signature": self.toBase64Url(signature),
                "signedPayload": self.toBase64Url(payloadData),
                "algorithm": record.algorithm,
                "securityLevel": record.securityLevel,
                "usedBiometry": true,
            ]
            if detectCompromised {
                result["compromisedDeviceSignal"] = compromisedSignal
            }

            call.resolve(result)
        }
    }

    /// Removes a credential from secure key storage and local metadata storage.
    /// Returns `removed: false` when no matching record exists.
    @objc func removeCredential(_ call: CAPPluginCall) {
        let userId = normalize(call.getString("userId"))
        let credentialId = normalize(call.getString("credentialId"))
        let resolved = resolveRecord(userId: userId, credentialId: credentialId)

        if let code = resolved.errorCode {
            call.reject(resolved.reason ?? "Invalid selector.", code)
            return
        }

        guard let record = resolved.record else {
            call.resolve(["removed": false])
            return
        }

        _ = deletePrivateKey(tag: record.keyTag)
        var records = loadRecords()
        records.removeAll { $0.credentialId == record.credentialId }
        saveRecords(records)
        call.resolve(["removed": true])
    }

    /// Resolves exactly one credential record from explicit selectors.
    /// Returns a structured result that can represent ambiguity or selector mismatch.
    private func resolveRecord(userId: String?, credentialId: String?) -> ResolveResult {
        let hasUser = userId?.isEmpty == false
        let hasCredential = credentialId?.isEmpty == false

        if !hasUser && !hasCredential {
            return ResolveResult(record: nil, errorCode: "configurationError", reason: "Explicit selector is required. Implicit credential selection is forbidden.")
        }

        let records = loadRecords()

        if let credentialId, let userId {
            guard let record = records.first(where: { $0.credentialId == credentialId }) else {
                return ResolveResult(record: nil, errorCode: nil, reason: nil)
            }
            if record.userId != userId {
                return ResolveResult(record: nil, errorCode: "configurationError", reason: "credentialId and userId refer to different credentials.")
            }
            return ResolveResult(record: record, errorCode: nil, reason: nil)
        }

        if let credentialId {
            return ResolveResult(record: records.first(where: { $0.credentialId == credentialId }), errorCode: nil, reason: nil)
        }

        if let userId {
            let matches = records.filter { $0.userId == userId }
            if matches.count > 1 {
                return ResolveResult(record: nil, errorCode: "configurationError", reason: "Selector is ambiguous for this userId.")
            }
            return ResolveResult(record: matches.first, errorCode: nil, reason: nil)
        }

        return ResolveResult(record: nil, errorCode: "configurationError", reason: "Invalid selector.")
    }

    /// Builds a deterministic JSON payload string for backend signature verification.
    /// Field order is intentionally fixed to keep canonical serialization stable.
    private func buildCanonicalPayload(type: String, challenge: String, credentialId: String, userId: String?) -> String {
        var dict: [(String, Any)] = [
            ("v", 1),
            ("type", type),
            ("challenge", challenge),
            ("credentialId", credentialId),
        ]

        if let userId {
            dict.append(("userId", userId))
        }

        dict.append(("algorithm", "ES256"))

        let parts = dict.map { key, value -> String in
            let valueString: String
            if let stringValue = value as? String {
                valueString = "\"\(escapeJson(stringValue))\""
            } else {
                valueString = "\(value)"
            }
            return "\"\(key)\":\(valueString)"
        }

        return "{\(parts.joined(separator: ","))}"
    }

    /// Prompts biometric authentication through `LAContext` and marshals completion on main queue.
    /// evaluatePolicy docs: https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:)
    private func authenticateBiometric(reason: String, completion: @escaping (Bool, NSError?, LAContext?) -> Void) {
        let context = LAContext()
        context.localizedFallbackTitle = ""
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
            DispatchQueue.main.async {
                completion(success, error as NSError?, success ? context : nil)
            }
        }
    }

    /// Creates a private EC key in Secure Enclave when possible, with policy-bound access control.
    /// Falls back to non-Secure-Enclave key generation only when hardware-backed is not required.
    /// Security framework docs:
    /// - SecAccessControlCreateWithFlags: https://developer.apple.com/documentation/security/1396916-secaccesscontrolcreatewithflags
    /// - SecKeyCreateRandomKey: https://developer.apple.com/documentation/security/1643691-seckeycreaterandomkey
    private func createPrivateKey(tag: String, invalidateOnEnrollmentChange: Bool, requireHardwareBacked: Bool) -> KeyCreationResult? {
        let tagData = Data(tag.utf8)
        let accessFlags: SecAccessControlCreateFlags = invalidateOnEnrollmentChange
            ? [.privateKeyUsage, .biometryCurrentSet]
            : [.privateKeyUsage, .biometryAny]

        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            accessFlags,
            nil
        ) else {
            return nil
        }

        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tagData,
                kSecAttrAccessControl as String: access,
            ],
        ]

        var error: Unmanaged<CFError>?
        if let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) {
            return KeyCreationResult(key: key, securityLevel: "secureEnclave")
        }

        if requireHardwareBacked {
            return nil
        }

        attributes.removeValue(forKey: kSecAttrTokenID as String)
        error = nil
        guard let fallbackKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            return nil
        }

        return KeyCreationResult(key: fallbackKey, securityLevel: "hardware")
    }

    /// Loads a previously created private key reference by application tag.
    /// Returns nil when key is missing or inaccessible.
    /// SecItemCopyMatching docs: https://developer.apple.com/documentation/security/1398306-secitemcopymatching
    private func loadPrivateKey(tag: String, context: LAContext? = nil) -> SecKey? {
        let tagData = Data(tag.utf8)
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        if let context = context {
            query[kSecUseAuthenticationContext as String] = context
        }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return nil
        }

        return (item as! SecKey)
    }

    /// Deletes a private key by tag from the Keychain key class.
    /// Treats "item not found" as success to keep deletion idempotent.
    /// SecItemDelete docs: https://developer.apple.com/documentation/security/1395547-secitemdelete
    private func deletePrivateKey(tag: String) -> Bool {
        let tagData = Data(tag.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]

        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    /// Loads persisted credential records from `UserDefaults` JSON blob storage.
    /// Returns an empty list when data is missing or decoding fails.
    private func loadRecords() -> [Record] {
        guard let data = UserDefaults.standard.data(forKey: storageKey) else {
            return []
        }

        do {
            return try JSONDecoder().decode([Record].self, from: data)
        } catch {
            return []
        }
    }

    /// Persists credential records to `UserDefaults` using JSON encoding.
    /// Persistence failures are intentionally swallowed in this implementation.
    private func saveRecords(_ records: [Record]) {
        do {
            let data = try JSONEncoder().encode(records)
            UserDefaults.standard.set(data, forKey: storageKey)
        } catch {
            // Intentionally ignore persistence errors in MVP scaffold.
        }
    }

    /// Marks an existing credential as invalidated in local metadata storage.
    private func markInvalidated(credentialId: String) {
        var records = loadRecords()
        guard let index = records.firstIndex(where: { $0.credentialId == credentialId }) else {
            return
        }

        records[index].invalidated = true
        saveRecords(records)
    }

    /// Derives a deterministic key tag used to locate secure keys in Keychain.
    private func keyTag(for credentialId: String) -> String {
        return "biometric_credential_\(credentialId)"
    }

    /// Trims whitespace/newlines and normalizes empty strings to nil.
    private func normalize(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    /// Validates that a string is non-empty Base64URL-compatible input.
    private func validateBase64Url(_ value: String) -> Bool {
        let pattern = "^[A-Za-z0-9_-]+$"
        return value.range(of: pattern, options: .regularExpression) != nil
    }

    /// Encodes data to Base64URL without padding.
    private func toBase64Url(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Escapes control characters for safe inline JSON string construction.
    private func escapeJson(_ value: String) -> String {
        var escaped = value
        escaped = escaped.replacingOccurrences(of: "\\", with: "\\\\")
        escaped = escaped.replacingOccurrences(of: "\"", with: "\\\"")
        escaped = escaped.replacingOccurrences(of: "\n", with: "\\n")
        escaped = escaped.replacingOccurrences(of: "\r", with: "\\r")
        escaped = escaped.replacingOccurrences(of: "\t", with: "\\t")
        return escaped
    }

    /// Maps `LAError` values to normalized plugin-level error codes.
    private func mapLAErrorCode(_ error: NSError?) -> String {
        guard let error else { return "unknown" }
        guard error.domain == LAError.errorDomain else { return "unknown" }

        switch LAError.Code(rawValue: error.code) {
        case .userCancel, .userFallback:
            return "userCancel"
        case .systemCancel, .appCancel:
            return "systemCancel"
        case .biometryLockout:
            return "lockout"
        case .biometryNotEnrolled:
            return "notEnrolled"
        case .biometryNotAvailable:
            return "notAvailable"
        case .invalidContext, .notInteractive:
            return "invalidContext"
        case .none:
            return "unknown"
        @unknown default:
            return "unknown"
        }
    }

    /// Returns user-facing reason text for LocalAuthentication failures.
    private func reasonForLAError(_ error: NSError?) -> String {
        guard let error else {
            return "Biometric authentication is unavailable."
        }
        return error.localizedDescription
    }

    /// Performs lightweight jailbreak/tamper heuristics for risk signaling.
    private func isCompromisedDevice() -> Bool {
        let suspiciousPaths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
        ]

        if suspiciousPaths.contains(where: { FileManager.default.fileExists(atPath: $0) }) {
            return true
        }

        if let path = getenv("DYLD_INSERT_LIBRARIES"), String(cString: path).isEmpty == false {
            return true
        }

        let tempProbe = "/private/biometric_plugin_jb_probe.txt"
        do {
            try "probe".write(toFile: tempProbe, atomically: true, encoding: .utf8)
            try? FileManager.default.removeItem(atPath: tempProbe)
            return true
        } catch {
            return false
        }
    }
}
