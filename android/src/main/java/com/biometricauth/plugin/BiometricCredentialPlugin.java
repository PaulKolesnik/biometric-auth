package com.biometricauth.plugin;

import android.app.KeyguardManager;
import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import androidx.annotation.NonNull;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricPrompt;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.FragmentActivity;

import com.getcapacitor.JSObject;
import com.getcapacitor.Plugin;
import com.getcapacitor.PluginCall;
import com.getcapacitor.PluginMethod;
import com.getcapacitor.annotation.CapacitorPlugin;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executor;
import java.util.regex.Pattern;

@CapacitorPlugin(name = "BiometricCredential")
public class BiometricCredentialPlugin extends Plugin {

    private static final String PREFS = "biometric_credential_plugin_records_v1";
    private static final String PREFS_KEY = "records";
    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String ALGORITHM = "ES256";
    private static final Pattern BASE64URL = Pattern.compile("^[A-Za-z0-9_-]+$");

    private static final String CODE_NOT_SUPPORTED = "notSupported";
    private static final String CODE_NOT_AVAILABLE = "notAvailable";
    private static final String CODE_CHALLENGE_MISSING = "challengeMissing";
    private static final String CODE_CHALLENGE_INVALID = "challengeInvalid";
    private static final String CODE_CONFIGURATION_ERROR = "configurationError";
    private static final String CODE_CREDENTIAL_NOT_FOUND = "credentialNotFound";
    private static final String CODE_CREDENTIAL_EXISTS = "credentialAlreadyExists";
    private static final String CODE_CREDENTIAL_INVALIDATED = "credentialInvalidated";
    private static final String CODE_SECURITY_LEVEL_INSUFFICIENT = "securityLevelInsufficient";
    private static final String CODE_KEY_GENERATION_FAILED = "keyGenerationFailed";
    private static final String CODE_SIGNATURE_FAILED = "signatureFailed";
    private static final String CODE_COMPROMISED_DEVICE = "compromisedDevice";

    private static class OperationException extends Exception {
        final String code;

        /** Carries a typed plugin error code through async biometric callbacks. */
        OperationException(String code, String message) {
            super(message);
            this.code = code;
        }
    }

    private interface AuthSuccessHandler {
        /** Handles a successful biometric callback and may throw operation errors. */
        void onSuccess(@NonNull BiometricPrompt.AuthenticationResult result) throws Exception;
    }

    private static class ResolveResult {
        Record record;
        String errorCode;
        String reason;
    }

    private static class Record {
        String credentialId;
        String userId;
        String keyAlias;
        String algorithm;
        String securityLevel;
        boolean invalidated;

        /** Serializes a local credential record to JSON for SharedPreferences persistence. */
        JSONObject toJson() throws JSONException {
            JSONObject json = new JSONObject();
            json.put("credentialId", credentialId);
            json.put("userId", userId);
            json.put("keyAlias", keyAlias);
            json.put("algorithm", algorithm);
            json.put("securityLevel", securityLevel);
            json.put("invalidated", invalidated);
            return json;
        }

        /** Deserializes a local credential record from JSON with safe defaults. */
        static Record fromJson(JSONObject json) {
            Record out = new Record();
            out.credentialId = json.optString("credentialId");
            out.userId = json.optString("userId");
            out.keyAlias = json.optString("keyAlias");
            out.algorithm = json.optString("algorithm", ALGORITHM);
            out.securityLevel = json.optString("securityLevel", "hardware");
            out.invalidated = json.optBoolean("invalidated", false);
            return out;
        }
    }

    @Override
    /** Plugin lifecycle hook. Reserved for future initialization logic. */
    public void load() {
        super.load();
    }

    @PluginMethod
    /** Reports biometric capability and security posture for the current Android device. */
    public void checkBiometry(PluginCall call) {
        Context context = getContext();
        // AndroidX BiometricManager docs:
        // https://developer.android.com/reference/androidx/biometric/BiometricManager
        BiometricManager manager = BiometricManager.from(context);
        // canAuthenticate docs:
        // https://developer.android.com/reference/androidx/biometric/BiometricManager#canAuthenticate(int)
        int strongResult = manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG);
        boolean strongAvailable = strongResult == BiometricManager.BIOMETRIC_SUCCESS;

        KeyguardManager keyguard = (KeyguardManager) context.getSystemService(Context.KEYGUARD_SERVICE);
        boolean secure = keyguard != null && keyguard.isDeviceSecure();

        // PackageManager feature flag reports whether fingerprint hardware is present.
        // Android Keystore CryptoObject flows require Class 3 (BIOMETRIC_STRONG); on the
        // vast majority of Android devices fingerprint is the only Class 3 modality, so
        // this plugin intentionally restricts eligibility to fingerprint.
        PackageManager pm = context.getPackageManager();
        boolean hasFingerprint = pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT);

        // `available` requires BOTH fingerprint hardware AND a successful strong-biometric
        // enrollment check, so we never advertise availability when only face/iris (Class 2)
        // is enrolled even though BiometricManager might otherwise report WEAK as usable.
        boolean available = hasFingerprint && strongAvailable;

        JSONArray types = new JSONArray();
        if (available) {
            types.put("fingerprint");
        } else {
            types.put("none");
        }

        String primaryType = available ? "fingerprint" : "none";

        String reason;
        String code;
        if (available) {
            reason = "Fingerprint is available.";
            code = "";
        } else if (!hasFingerprint) {
            reason = "Fingerprint hardware is not available on this device.";
            code = CODE_NOT_AVAILABLE;
        } else {
            reason = reasonForBiometricResult(strongResult);
            code = mapBiometricErrorToCode(strongResult);
        }

        JSObject result = new JSObject();
        result.put("isAvailable", available);
        result.put("strongBiometryIsAvailable", strongAvailable);
        result.put("biometryType", primaryType);
        result.put("biometryTypes", types);
        result.put("deviceIsSecure", secure);
        result.put("meetsSecurityRequirements", available && secure);
        result.put("reason", reason);
        result.put("code", code);
        call.resolve(result);
    }

    @PluginMethod
    /** Checks whether a credential exists for the explicit selector (userId/credentialId). */
    public void checkRegistration(PluginCall call) {
        String userId = trim(call.getString("userId"));
        String credentialId = trim(call.getString("credentialId"));
        ResolveResult resolved = resolveRecord(userId, credentialId);

        if (resolved.errorCode != null) {
            JSObject result = new JSObject();
            result.put("isRegistered", false);
            result.put("reason", resolved.reason);
            result.put("code", resolved.errorCode);
            call.resolve(result);
            return;
        }

        if (resolved.record == null) {
            JSObject result = new JSObject();
            result.put("isRegistered", false);
            result.put("reason", "No credential found for supplied selector.");
            result.put("code", CODE_CREDENTIAL_NOT_FOUND);
            call.resolve(result);
            return;
        }

        JSObject result = new JSObject();
        result.put("isRegistered", true);
        result.put("credentialId", resolved.record.credentialId);
        result.put("userId", resolved.record.userId);
        result.put("securityLevel", resolved.record.securityLevel);
        result.put("invalidated", resolved.record.invalidated);
        result.put("code", resolved.record.invalidated ? CODE_CREDENTIAL_INVALIDATED : "");
        if (resolved.record.invalidated) {
            result.put("reason", "Credential was invalidated in local store.");
        }
        call.resolve(result);
    }

    @PluginMethod
    /** Registers a new credential after strong biometric verification and key generation. */
    public void registerCredential(PluginCall call) {
        String userId = trim(call.getString("userId"));
        String credentialId = trim(call.getString("credentialId"));
        String challenge = trim(call.getString("challenge"));

        if (isEmpty(userId) || isEmpty(credentialId)) {
            reject(call, CODE_CONFIGURATION_ERROR, "userId and credentialId are required.");
            return;
        }

        String challengeError = validateChallenge(challenge);
        if (challengeError != null) {
            reject(call, challengeError, challengeError.equals(CODE_CHALLENGE_MISSING)
                ? "Challenge is required."
                : "Challenge must be a base64url non-empty string.");
            return;
        }

        if (!meetsStrongBiometryRequirements()) {
            reject(call, CODE_SECURITY_LEVEL_INSUFFICIENT, "Strong biometric is required on Android.");
            return;
        }

        try {
            if (findByCredentialId(credentialId) != null) {
                reject(call, CODE_CREDENTIAL_EXISTS, "Credential already exists for this credentialId.");
                return;
            }

            if (countByUserId(userId) > 0) {
                reject(call, CODE_CREDENTIAL_EXISTS, "A credential already exists for this user on this device.");
                return;
            }
        } catch (Exception error) {
            reject(call, CODE_NOT_SUPPORTED, "Failed to inspect local credential storage: " + error.getMessage());
            return;
        }

        // Always evaluate device integrity and embed the result in the signed payload.
        // Running unconditionally prevents Frida from simply flipping a boolean gate.
        boolean deviceIntegrity = !isCompromisedDevice();

        String alias = keyAliasFor(credentialId);
        byte[] challengeBytes = Base64.decode(challenge, Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
        KeyPair keyPair;
        try {
            keyPair = generateKeyPair(alias, challengeBytes);
        } catch (Exception error) {
            reject(call, CODE_KEY_GENERATION_FAILED, "Failed to generate key pair.");
            return;
        }

        // PublicKey#getEncoded docs:
        // https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/Key.html#getEncoded()
        PublicKey publicKey = keyPair.getPublic();

        String securityLevel = resolveSecurityLevel(alias);
        if (!("hardware".equals(securityLevel) || "strongBox".equals(securityLevel))) {
            deleteKeyQuietly(alias);
            reject(call, CODE_SECURITY_LEVEL_INSUFFICIENT, "Hardware-backed key is required.");
            return;
        }

        Signature signatureObj;
        try {
            signatureObj = Signature.getInstance("SHA256withECDSA");
            signatureObj.initSign(keyPair.getPrivate());
        } catch (Exception error) {
            deleteKeyQuietly(alias);
            reject(call, CODE_SIGNATURE_FAILED, "Failed to initialize signature for registration.");
            return;
        }

        BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signatureObj);

        performBiometricPrompt(call, buildPromptTitle(call, "Register credential"), call.getString("androidSubtitle"), cryptoObject, result -> {
            BiometricPrompt.CryptoObject resultCrypto = result.getCryptoObject();
            if (resultCrypto == null || resultCrypto.getSignature() == null) {
                deleteKeyQuietly(alias);
                throw new OperationException(CODE_SIGNATURE_FAILED, "Biometric crypto object is unavailable.");
            }

            String canonical = buildCanonicalPayload("registration", challenge, credentialId, userId, securityLevel, deviceIntegrity);
            byte[] payloadBytes = canonical.getBytes(StandardCharsets.UTF_8);
            String signedPayload = toBase64Url(payloadBytes);

            byte[] signatureBytes;
            try {
                Signature signer = resultCrypto.getSignature();
                signer.update(payloadBytes);
                signatureBytes = signer.sign();
            } catch (Exception signEx) {
                deleteKeyQuietly(alias);
                throw new OperationException(CODE_SIGNATURE_FAILED, "Failed to sign registration payload.");
            }

            Record record = new Record();
            record.credentialId = credentialId;
            record.userId = userId;
            record.keyAlias = alias;
            record.algorithm = ALGORITHM;
            record.securityLevel = securityLevel;
            record.invalidated = false;

            upsertRecord(record);

            List<String> attestationChain = getAttestationCertificateChain(alias);

            JSObject out = new JSObject();
            out.put("credentialId", credentialId);
            out.put("userId", userId);
            out.put("publicKey", toBase64Url(publicKey.getEncoded()));
            out.put("publicKeyFormat", "spki");
            out.put("algorithm", ALGORITHM);
            out.put("securityLevel", securityLevel);
            out.put("signature", toBase64Url(signatureBytes));
            out.put("signatureFormat", "der");
            out.put("signedPayload", signedPayload);
            out.put("deviceIntegrity", deviceIntegrity);
            if (!attestationChain.isEmpty()) {
                out.put("attestationCertificateChain", new JSONArray(attestationChain));
            }

            call.resolve(out);
        });
    }

    @PluginMethod
    /** Authenticates the user and signs a canonical payload with a biometric-protected private key. */
    public void authenticate(PluginCall call) {
        String userId = trim(call.getString("userId"));
        String credentialId = trim(call.getString("credentialId"));
        String challenge = trim(call.getString("challenge"));

        String challengeError = validateChallenge(challenge);
        if (challengeError != null) {
            reject(call, challengeError, challengeError.equals(CODE_CHALLENGE_MISSING)
                ? "Challenge is required."
                : "Challenge must be a base64url non-empty string.");
            return;
        }

        ResolveResult resolved = resolveRecord(userId, credentialId);
        if (resolved.errorCode != null) {
            reject(call, resolved.errorCode, resolved.reason);
            return;
        }

        if (resolved.record == null) {
            reject(call, CODE_CREDENTIAL_NOT_FOUND, "No credential found for supplied selector.");
            return;
        }

        if (resolved.record.invalidated) {
            reject(call, CODE_CREDENTIAL_INVALIDATED, "Credential is invalidated and cannot be used.");
            return;
        }

        // Strong biometric is always required — enforced both here and by the
        // BiometricPrompt BIOMETRIC_STRONG authenticator flag.
        if (!meetsStrongBiometryRequirements()) {
            reject(call, CODE_SECURITY_LEVEL_INSUFFICIENT, "Strong biometric is required on Android.");
            return;
        }

        boolean deviceIntegrity = !isCompromisedDevice();

        try {
            PrivateKey privateKey = loadPrivateKey(resolved.record.keyAlias);
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey);

            BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signature);
            performBiometricPrompt(call, buildPromptTitle(call, "Authenticate"), call.getString("androidSubtitle"), cryptoObject, result -> {
                BiometricPrompt.CryptoObject resultCrypto = result.getCryptoObject();
                if (resultCrypto == null || resultCrypto.getSignature() == null) {
                    throw new IllegalStateException("Biometric crypto object is unavailable.");
                }

                String canonical = buildCanonicalPayload("authentication", challenge, resolved.record.credentialId, resolved.record.userId, resolved.record.securityLevel, deviceIntegrity);
                byte[] payloadBytes = canonical.getBytes(StandardCharsets.UTF_8);
                String signedPayload = toBase64Url(payloadBytes);

                Signature signer = resultCrypto.getSignature();
                signer.update(payloadBytes);
                byte[] signatureBytes = signer.sign();

                JSObject out = new JSObject();
                out.put("credentialId", resolved.record.credentialId);
                out.put("userId", resolved.record.userId);
                out.put("signature", toBase64Url(signatureBytes));
                out.put("signatureFormat", "der");
                out.put("signedPayload", signedPayload);
                out.put("algorithm", resolved.record.algorithm);
                out.put("securityLevel", resolved.record.securityLevel);
                out.put("usedBiometry", true);
                out.put("deviceIntegrity", deviceIntegrity);

                call.resolve(out);
            });
        } catch (UnrecoverableEntryException ex) {
            markInvalidated(resolved.record.credentialId);
            reject(call, CODE_CREDENTIAL_INVALIDATED, "Credential key is unavailable or invalidated.");
        } catch (InvalidKeyException ex) {
            markInvalidated(resolved.record.credentialId);
            reject(call, CODE_CREDENTIAL_INVALIDATED, "Credential key is invalidated and must be re-registered.");
        } catch (Exception ex) {
            reject(call, CODE_SIGNATURE_FAILED, "Failed to sign authentication payload: " + ex.getMessage());
        }
    }

    @PluginMethod
    /** Deletes a credential from Android Keystore and local storage if it exists. */
    public void removeCredential(PluginCall call) {
        String userId = trim(call.getString("userId"));
        String credentialId = trim(call.getString("credentialId"));

        ResolveResult resolved = resolveRecord(userId, credentialId);
        if (resolved.errorCode != null) {
            reject(call, resolved.errorCode, resolved.reason);
            return;
        }

        if (resolved.record == null) {
            JSObject out = new JSObject();
            out.put("removed", false);
            call.resolve(out);
            return;
        }

        try {
            deleteKey(resolved.record.keyAlias);
            removeRecord(resolved.record.credentialId);

            JSObject out = new JSObject();
            out.put("removed", true);
            call.resolve(out);
        } catch (Exception ex) {
            reject(call, CODE_NOT_SUPPORTED, "Failed to remove credential: " + ex.getMessage());
        }
    }

    /**
     * Displays the AndroidX biometric prompt and forwards success to the provided handler.
     * BiometricPrompt docs: https://developer.android.com/reference/androidx/biometric/BiometricPrompt
     */
    private void performBiometricPrompt(
        PluginCall call,
        String title,
        String subtitle,
        BiometricPrompt.CryptoObject cryptoObject,
        AuthSuccessHandler onSuccess
    ) {
        FragmentActivity activity;
        try {
            activity = (FragmentActivity) getActivity();
        } catch (ClassCastException error) {
            reject(call, CODE_NOT_SUPPORTED, "Activity context is not compatible with BiometricPrompt.");
            return;
        }

        if (activity == null) {
            reject(call, CODE_NOT_AVAILABLE, "No active Android activity is available.");
            return;
        }

        activity.runOnUiThread(() -> {
            if (activity.isFinishing() || activity.isDestroyed()) {
                reject(call, CODE_NOT_AVAILABLE, "Android activity is not in a valid state for biometric prompt.");
                return;
            }

            // ContextCompat#getMainExecutor docs:
            // https://developer.android.com/reference/androidx/core/content/ContextCompat#getMainExecutor(android.content.Context)
            Executor executor = ContextCompat.getMainExecutor(activity);
            BiometricPrompt prompt = new BiometricPrompt(activity, executor, new BiometricPrompt.AuthenticationCallback() {
                @Override
                public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                    super.onAuthenticationError(errorCode, errString);
                    reject(call, mapPromptErrorToCode(errorCode), errString.toString());
                }

                @Override
                public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                    super.onAuthenticationSucceeded(result);
                    try {
                        onSuccess.onSuccess(result);
                    } catch (OperationException error) {
                        reject(call, error.code, error.getMessage() == null ? "Native operation failed." : error.getMessage());
                    } catch (Exception error) {
                        reject(call, CODE_NOT_SUPPORTED, error.getMessage() == null ? "Native operation failed." : error.getMessage());
                    }
                }
            });

            BiometricPrompt.PromptInfo.Builder builder = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setNegativeButtonText("Cancel")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG);

            if (!isEmpty(subtitle)) {
                builder.setSubtitle(subtitle);
            }

            BiometricPrompt.PromptInfo info = builder.build();
            // authenticate overload docs:
            // https://developer.android.com/reference/androidx/biometric/BiometricPrompt#authenticate(androidx.biometric.BiometricPrompt.PromptInfo,androidx.biometric.BiometricPrompt.CryptoObject)
            if (cryptoObject != null) {
                prompt.authenticate(info, cryptoObject);
            } else {
                // https://developer.android.com/reference/androidx/biometric/BiometricPrompt#authenticate(androidx.biometric.BiometricPrompt.PromptInfo)
                prompt.authenticate(info);
            }
        });
    }

    /**
     * Returns true only when fingerprint hardware is present AND a Class 3 (STRONG)
     * biometric is enrolled. Restricting to fingerprint ensures the Keystore-backed
     * CryptoObject flow cannot be satisfied by face/iris unlock, which on most Android
     * devices is classified as Class 2 (WEAK) and therefore cannot release Keystore keys.
     */
    private boolean meetsStrongBiometryRequirements() {
        PackageManager pm = getContext().getPackageManager();
        if (!pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
            return false;
        }
        BiometricManager manager = BiometricManager.from(getContext());
        return manager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS;
    }

    /**
     * Creates an EC P-256 key pair in Android Keystore with biometric user authentication
     * and Key Attestation. The attestation challenge binds the certificate chain to a
     * server-generated nonce so the server can verify hardware origin.
     * KeyGenParameterSpec docs: https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec
     */
    private KeyPair generateKeyPair(String alias, byte[] attestationChallenge) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE);
        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            // Always invalidate when biometric enrollment changes to prevent an attacker
            // from adding their fingerprint and reusing an existing credential.
            .setInvalidatedByBiometricEnrollment(true)
            // Bind a server-generated challenge into the attestation certificate so the
            // server can verify the key was created in TEE/StrongBox hardware.
            .setAttestationChallenge(attestationChallenge);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG);
        } else {
            builder.setUserAuthenticationValidityDurationSeconds(-1);
        }

        generator.initialize(builder.build());
        return generator.generateKeyPair();
    }

    /**
     * Extracts the Key Attestation certificate chain from Android Keystore.
     * Each certificate is DER-encoded and returned as a base64 string.
     * The server must validate this chain against Google's hardware attestation root CA
     * and parse the attestation extension (OID 1.3.6.1.4.1.11129.2.1.17).
     */
    private List<String> getAttestationCertificateChain(String alias) {
        List<String> chain = new ArrayList<>();
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null);
            Certificate[] certs = keyStore.getCertificateChain(alias);
            if (certs != null) {
                for (Certificate cert : certs) {
                    chain.add(Base64.encodeToString(cert.getEncoded(), Base64.NO_WRAP));
                }
            }
        } catch (Exception ignored) {
        }
        return chain;
    }

    /** Loads a private key entry from Android Keystore for the given alias. */
    private PrivateKey loadPrivateKey(String alias) throws Exception {
        // KeyStore docs:
        // https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/security/KeyStore.html
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
        keyStore.load(null);

        KeyStore.Entry entry = keyStore.getEntry(alias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            throw new UnrecoverableEntryException("Private key entry not found for alias.");
        }

        return ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
    }

    /** Determines whether a key is StrongBox, hardware-backed, software-backed, or unknown. */
    private String resolveSecurityLevel(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
            keyStore.load(null);
            KeyStore.Entry entry = keyStore.getEntry(alias, null);
            if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
                return "unknown";
            }

            PrivateKey key = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
            KeyFactory factory = KeyFactory.getInstance(key.getAlgorithm(), KEYSTORE);
            KeyInfo info = (KeyInfo) factory.getKeySpec(key, KeyInfo.class);

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && isStrongBoxBacked(info)) {
                return "strongBox";
            }

            if (info.isInsideSecureHardware()) {
                return "hardware";
            }

            return "software";
        } catch (InvalidKeySpecException | ClassCastException ignored) {
            return "unknown";
        } catch (Exception ignored) {
            return "unknown";
        }
    }

    /** Deletes an entry from Android Keystore when the alias exists. */
    private void deleteKey(String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE);
        keyStore.load(null);
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias);
        }
    }

    /** Resolves a single credential by explicit selector and detects ambiguous selection. */
    private ResolveResult resolveRecord(String userId, String credentialId) {
        ResolveResult out = new ResolveResult();
        boolean hasUser = !isEmpty(userId);
        boolean hasCredential = !isEmpty(credentialId);

        if (!hasUser && !hasCredential) {
            out.errorCode = CODE_CONFIGURATION_ERROR;
            out.reason = "Explicit selector is required. Implicit credential selection is forbidden.";
            return out;
        }

        try {
            if (hasCredential && hasUser) {
                Record record = findByCredentialId(credentialId);
                if (record == null) {
                    return out;
                }

                if (!record.userId.equals(userId)) {
                    out.errorCode = CODE_CONFIGURATION_ERROR;
                    out.reason = "credentialId and userId refer to different credentials.";
                    return out;
                }

                out.record = record;
                return out;
            }

            if (hasCredential) {
                out.record = findByCredentialId(credentialId);
                return out;
            }

            JSONArray records = loadRecords();
            Record match = null;
            int count = 0;
            // Scan all records to guarantee userId-only selection is unambiguous.
            for (int i = 0; i < records.length(); i += 1) {
                JSONObject item = records.getJSONObject(i);
                Record record = Record.fromJson(item);
                if (userId.equals(record.userId)) {
                    count += 1;
                    match = record;
                }
            }

            if (count > 1) {
                out.errorCode = CODE_CONFIGURATION_ERROR;
                out.reason = "Selector is ambiguous for this userId.";
                return out;
            }

            out.record = match;
            return out;
        } catch (JSONException error) {
            out.errorCode = CODE_NOT_SUPPORTED;
            out.reason = "Local credential storage is corrupted.";
            return out;
        }
    }

    /** Finds a credential record by credentialId, or null when absent. */
    private Record findByCredentialId(String credentialId) throws JSONException {
        JSONArray records = loadRecords();
        for (int i = 0; i < records.length(); i += 1) {
            JSONObject item = records.getJSONObject(i);
            Record record = Record.fromJson(item);
            if (credentialId.equals(record.credentialId)) {
                return record;
            }
        }

        return null;
    }

    /** Counts credentials tied to a userId in local storage. */
    private int countByUserId(String userId) throws JSONException {
        JSONArray records = loadRecords();
        int count = 0;
        for (int i = 0; i < records.length(); i += 1) {
            JSONObject item = records.getJSONObject(i);
            Record record = Record.fromJson(item);
            if (userId.equals(record.userId)) {
                count += 1;
            }
        }

        return count;
    }

    /** Inserts or replaces a credential record in the persisted JSON array. */
    private void upsertRecord(Record target) throws JSONException {
        JSONArray records = loadRecords();
        JSONArray out = new JSONArray();
        boolean replaced = false;

        for (int i = 0; i < records.length(); i += 1) {
            JSONObject item = records.getJSONObject(i);
            Record record = Record.fromJson(item);
            if (record.credentialId.equals(target.credentialId)) {
                out.put(target.toJson());
                replaced = true;
            } else {
                out.put(item);
            }
        }

        if (!replaced) {
            out.put(target.toJson());
        }

        persistRecords(out);
    }

    /** Removes a credential record by credentialId from local storage. */
    private void removeRecord(String credentialId) throws JSONException {
        JSONArray records = loadRecords();
        JSONArray out = new JSONArray();

        for (int i = 0; i < records.length(); i += 1) {
            JSONObject item = records.getJSONObject(i);
            Record record = Record.fromJson(item);
            if (!credentialId.equals(record.credentialId)) {
                out.put(item);
            }
        }

        persistRecords(out);
    }

    /** Marks a credential as invalidated in local storage after key failures. */
    private void markInvalidated(String credentialId) {
        try {
            Record record = findByCredentialId(credentialId);
            if (record == null) {
                return;
            }

            record.invalidated = true;
            upsertRecord(record);
        } catch (Exception ignored) {
        }
    }

    /** Loads persisted credential records from SharedPreferences. */
    private JSONArray loadRecords() throws JSONException {
        // SharedPreferences docs:
        // https://developer.android.com/reference/android/content/SharedPreferences
        SharedPreferences prefs = getContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        String raw = prefs.getString(PREFS_KEY, "[]");
        return new JSONArray(raw == null ? "[]" : raw);
    }

    /** Persists credential records atomically to SharedPreferences. */
    private void persistRecords(JSONArray records) {
        SharedPreferences prefs = getContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE);
        // Editor#apply docs:
        // https://developer.android.com/reference/android/content/SharedPreferences.Editor#apply()
        prefs.edit().putString(PREFS_KEY, records.toString()).apply();
    }

    /** Returns a prompt title from call options or falls back to a default title. */
    private String buildPromptTitle(PluginCall call, String fallback) {
        String title = trim(call.getString("androidTitle"));
        return isEmpty(title) ? fallback : title;
    }

    /** Validates challenge format as a non-empty base64url string. */
    private String validateChallenge(String challenge) {
        if (isEmpty(challenge)) {
            return CODE_CHALLENGE_MISSING;
        }

        if (!BASE64URL.matcher(challenge).matches()) {
            return CODE_CHALLENGE_INVALID;
        }

        return null;
    }

    /**
     * Builds the canonical JSON payload string used for signature verification on backend.
     * Security-critical metadata (securityLevel, deviceIntegrity) is embedded inside the
     * signed payload so the server can trust these claims even if client-side booleans
     * are tampered with via runtime instrumentation (e.g. Frida).
     */
    private String buildCanonicalPayload(String type, String challenge, String credentialId, String userId, String securityLevel, boolean deviceIntegrity) {
        StringBuilder builder = new StringBuilder();
        builder.append("{");
        builder.append("\"v\":2,");
        builder.append("\"type\":").append(JSONObject.quote(type)).append(",");
        builder.append("\"challenge\":").append(JSONObject.quote(challenge)).append(",");
        builder.append("\"credentialId\":").append(JSONObject.quote(credentialId)).append(",");
        if (!isEmpty(userId)) {
            builder.append("\"userId\":").append(JSONObject.quote(userId)).append(",");
        }
        builder.append("\"algorithm\":\"ES256\",");
        builder.append("\"securityLevel\":").append(JSONObject.quote(securityLevel)).append(",");
        builder.append("\"deviceIntegrity\":").append(deviceIntegrity);
        builder.append("}");
        return builder.toString();
    }

    /** Maps BiometricManager capability errors to plugin error codes. */
    private String mapBiometricErrorToCode(int result) {
        switch (result) {
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                return "notEnrolled";
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                return CODE_NOT_AVAILABLE;
            case BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED:
                return CODE_SECURITY_LEVEL_INSUFFICIENT;
            case BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED:
                return CODE_NOT_SUPPORTED;
            default:
                return "unknown";
        }
    }

    /** Converts BiometricManager results into user-readable explanation text. */
    private String reasonForBiometricResult(int result) {
        switch (result) {
            case BiometricManager.BIOMETRIC_SUCCESS:
                return "Strong biometric is available.";
            case BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED:
                return "No strong biometric is enrolled.";
            case BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE:
                return "No biometric hardware is available.";
            case BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE:
                return "Biometric hardware is currently unavailable.";
            case BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED:
                return "System security update is required for strong biometric usage.";
            case BiometricManager.BIOMETRIC_ERROR_UNSUPPORTED:
                return "Biometric authentication is unsupported on this device.";
            default:
                return "Strong biometric is unavailable.";
        }
    }

    /** Maps BiometricPrompt runtime errors to plugin error codes. */
    private String mapPromptErrorToCode(int errorCode) {
        switch (errorCode) {
            case BiometricPrompt.ERROR_USER_CANCELED:
            case BiometricPrompt.ERROR_NEGATIVE_BUTTON:
                return "userCancel";
            case BiometricPrompt.ERROR_CANCELED:
                return "systemCancel";
            case BiometricPrompt.ERROR_NO_BIOMETRICS:
                return "notEnrolled";
            case BiometricPrompt.ERROR_HW_NOT_PRESENT:
            case BiometricPrompt.ERROR_HW_UNAVAILABLE:
                return CODE_NOT_AVAILABLE;
            case BiometricPrompt.ERROR_LOCKOUT:
            case BiometricPrompt.ERROR_LOCKOUT_PERMANENT:
                return "lockout";
            default:
                return "unknown";
        }
    }

    /** Rejects a Capacitor call with a normalized code/message pair. */
    private void reject(PluginCall call, String code, String message) {
        call.reject(message, code);
    }

    /** Derives a deterministic Android Keystore alias from credentialId. */
    private String keyAliasFor(String credentialId) {
        return "biometric_credential_" + credentialId;
    }

    /** Trims a string safely and preserves null input. */
    private String trim(String value) {
        return value == null ? null : value.trim();
    }

    /** Returns true when a string is null or whitespace-only. */
    private boolean isEmpty(String value) {
        return value == null || value.trim().isEmpty();
    }

    /** Encodes bytes as Base64URL without padding for wire-safe payloads. */
    private String toBase64Url(byte[] bytes) {
        // Android Base64 docs:
        // https://developer.android.com/reference/android/util/Base64#encodeToString(byte%5B%5D,int)
        return Base64.encodeToString(bytes, Base64.NO_WRAP | Base64.NO_PADDING | Base64.URL_SAFE);
    }

    /** Detects StrongBox support on API levels where this property exists. */
    private boolean isStrongBoxBacked(KeyInfo info) {
        try {
            // Reflection Method docs:
            // https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/reflect/Method.html#invoke(java.lang.Object,java.lang.Object...)
            Method method = KeyInfo.class.getMethod("isStrongBoxBacked");
            Object value = method.invoke(info);
            return value instanceof Boolean && (Boolean) value;
        } catch (Exception ignored) {
            return false;
        }
    }

    /** Attempts key deletion and intentionally ignores cleanup failures. */
    private void deleteKeyQuietly(String alias) {
        try {
            deleteKey(alias);
        } catch (Exception ignored) {
        }
    }

    /**
     * Comprehensive device integrity check covering root, bootloader,
     * runtime instrumentation (Frida), and known tampering frameworks.
     */
    private boolean isCompromisedDevice() {
        return hasRootIndicators()
            || hasUnverifiedBootloader()
            || hasFridaIndicators()
            || hasTamperingFrameworks()
            || hasDangerousBuildProperties();
    }

    /** Checks common su binary paths and root management artifacts. */
    private boolean hasRootIndicators() {
        String[] suPaths = {
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/vendor/bin/su",
            "/system/app/Superuser.apk",
            "/data/adb/magisk",
            "/sbin/.magisk",
            "/cache/.disable_magisk",
            "/dev/magisk/mirror",
        };

        for (String path : suPaths) {
            if (new File(path).exists()) {
                return true;
            }
        }

        if (Build.TAGS != null && Build.TAGS.contains("test-keys")) {
            return true;
        }

        String[] rootPackages = {
            "com.topjohnwu.magisk",
            "eu.chainfire.supersu",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "com.yellowes.su",
        };
        return hasAnyPackageInstalled(rootPackages);
    }

    /**
     * Reads ro.boot.verifiedbootstate system property to check if the
     * bootloader is in VERIFIED (green) state. Any other state (yellow,
     * orange, red) indicates an unlocked or tampered bootloader.
     */
    private boolean hasUnverifiedBootloader() {
        String bootState = getSystemProperty("ro.boot.verifiedbootstate");
        if (bootState != null && !bootState.isEmpty() && !"green".equalsIgnoreCase(bootState)) {
            return true;
        }

        String verityMode = getSystemProperty("ro.boot.veritymode");
        if (verityMode != null && "disabled".equalsIgnoreCase(verityMode)) {
            return true;
        }

        String flashLocked = getSystemProperty("ro.boot.flash.locked");
        if ("0".equals(flashLocked)) {
            return true;
        }

        return false;
    }

    /** Detects Frida runtime instrumentation via port probing, library scanning, and file checks. */
    private boolean hasFridaIndicators() {
        if (isFridaPortOpen()) {
            return true;
        }

        if (hasFridaLibrariesInMaps()) {
            return true;
        }

        String[] fridaPaths = {
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/data/local/tmp/frida-agent",
            "/data/local/tmp/frida-gadget",
        };
        for (String path : fridaPaths) {
            if (new File(path).exists()) {
                return true;
            }
        }

        return false;
    }

    /** Attempts a TCP connection to the default Frida server port. */
    private boolean isFridaPortOpen() {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress("127.0.0.1", 27042), 100);
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    /** Scans /proc/self/maps for frida or gadget shared libraries loaded into the process. */
    private boolean hasFridaLibrariesInMaps() {
        try (BufferedReader reader = new BufferedReader(new FileReader("/proc/self/maps"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String lower = line.toLowerCase();
                if (lower.contains("frida") || lower.contains("gadget")) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    /** Detects Xposed framework and similar hooking tools. */
    private boolean hasTamperingFrameworks() {
        String[] xposedPaths = {
            "/system/framework/XposedBridge.jar",
            "/system/bin/app_process.orig",
            "/system/xposed.prop",
        };
        for (String path : xposedPaths) {
            if (new File(path).exists()) {
                return true;
            }
        }

        String[] tamperPackages = {
            "de.robv.android.xposed.installer",
            "org.meowcat.edxposed.manager",
            "org.lsposed.manager",
            "com.saurik.substrate",
        };
        return hasAnyPackageInstalled(tamperPackages);
    }

    /** Checks build properties that indicate a debug or insecure system image. */
    private boolean hasDangerousBuildProperties() {
        if ("1".equals(getSystemProperty("ro.debuggable"))) {
            return true;
        }
        if ("0".equals(getSystemProperty("ro.secure"))) {
            return true;
        }

        String selinux = getSystemProperty("ro.build.selinux");
        if ("0".equals(selinux) || "disabled".equalsIgnoreCase(selinux)) {
            return true;
        }

        return false;
    }

    /** Reads an Android system property via reflection on SystemProperties. */
    private String getSystemProperty(String name) {
        try {
            Class<?> clazz = Class.forName("android.os.SystemProperties");
            Method getter = clazz.getMethod("get", String.class);
            Object value = getter.invoke(null, name);
            return value instanceof String ? (String) value : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    /** Checks whether any of the given package names are installed on the device. */
    private boolean hasAnyPackageInstalled(String[] packageNames) {
        try {
            PackageManager pm = getContext().getPackageManager();
            for (String pkg : packageNames) {
                try {
                    pm.getPackageInfo(pkg, 0);
                    return true;
                } catch (PackageManager.NameNotFoundException ignored) {
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }
}
