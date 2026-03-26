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

    @objc func checkBiometry(_ call: CAPPluginCall) {
        let context = LAContext()
        var error: NSError?
        let available = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)

        let biometryType: String
        if #available(iOS 11.0, *) {
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

        authenticateBiometric(reason: reason) { [weak self] success, error in
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

            guard let publicKey = SecKeyCopyPublicKey(keyResult.key),
                  let publicData = SecKeyCopyExternalRepresentation(publicKey, nil) as Data? else {
                call.reject("Failed to extract public key.", "keyGenerationFailed")
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
            ]
            if detectCompromised {
                result["compromisedDeviceSignal"] = compromisedSignal
            }

            call.resolve(result)
        }
    }

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

        authenticateBiometric(reason: reason) { [weak self] success, error in
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

            guard let privateKey = self.loadPrivateKey(tag: record.keyTag) else {
                self.markInvalidated(credentialId: record.credentialId)
                call.reject("Credential key is unavailable or invalidated.", "credentialInvalidated")
                return
            }

            var signError: Unmanaged<CFError>?
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

    private func authenticateBiometric(reason: String, completion: @escaping (Bool, NSError?) -> Void) {
        let context = LAContext()
        context.localizedFallbackTitle = ""
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason) { success, error in
            DispatchQueue.main.async {
                completion(success, error as NSError?)
            }
        }
    }

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

    private func loadPrivateKey(tag: String) -> SecKey? {
        let tagData = Data(tag.utf8)
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tagData,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return nil
        }

        return (item as! SecKey)
    }

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

    private func saveRecords(_ records: [Record]) {
        do {
            let data = try JSONEncoder().encode(records)
            UserDefaults.standard.set(data, forKey: storageKey)
        } catch {
            // Intentionally ignore persistence errors in MVP scaffold.
        }
    }

    private func markInvalidated(credentialId: String) {
        var records = loadRecords()
        guard let index = records.firstIndex(where: { $0.credentialId == credentialId }) else {
            return
        }

        records[index].invalidated = true
        saveRecords(records)
    }

    private func keyTag(for credentialId: String) -> String {
        return "biometric_credential_\(credentialId)"
    }

    private func normalize(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private func validateBase64Url(_ value: String) -> Bool {
        let pattern = "^[A-Za-z0-9_-]+$"
        return value.range(of: pattern, options: .regularExpression) != nil
    }

    private func toBase64Url(_ data: Data) -> String {
        return data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private func escapeJson(_ value: String) -> String {
        var escaped = value
        escaped = escaped.replacingOccurrences(of: "\\", with: "\\\\")
        escaped = escaped.replacingOccurrences(of: "\"", with: "\\\"")
        escaped = escaped.replacingOccurrences(of: "\n", with: "\\n")
        escaped = escaped.replacingOccurrences(of: "\r", with: "\\r")
        escaped = escaped.replacingOccurrences(of: "\t", with: "\\t")
        return escaped
    }

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

    private func reasonForLAError(_ error: NSError?) -> String {
        guard let error else {
            return "Biometric authentication is unavailable."
        }
        return error.localizedDescription
    }

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
