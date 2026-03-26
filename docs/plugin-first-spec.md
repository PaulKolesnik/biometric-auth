# Capacitor Secure Biometric Credential Plugin - Plugin-First SPEC (MVP)

## Purpose

Define a reusable Capacitor plugin contract for strong biometric authentication based on:
- OS biometric verification
- Cryptographic signing using a local protected private key

This document is plugin-first and backend-agnostic.

## Scope Boundary

### Plugin Responsibility
- Biometric gating
- Key generation and protected key usage
- Deterministic payload signing
- Canonical error model across platforms

### Caller Responsibility
- Challenge creation policy
- Challenge lifecycle and replay protection
- Business verification semantics
- Backend transport and persistence

## Core Product and Security Decisions

- Biometry alone is not sufficient.
- Signature alone is not sufficient.
- Valid authentication requires biometric verification and challenge signing.
- Private key must never be exposed to JavaScript.
- Every authenticate operation requires a caller-provided challenge.
- Registration is blocked when required security level cannot be met.
- No device credential fallback in secure mode.
- Strong biometric is mandatory on Android native.
- Web is simulation-only in MVP and must not claim native hardware security parity.

## API Surface (MVP)

- checkBiometry()
- checkRegistration(options?)
- registerCredential(options)
- authenticate(options)
- removeCredential(options?)

## Finalized MVP Decisions

- credentialId ownership model: caller-supplied
- userId local storage model: raw userId
- registration metadata (minimum): biometryType, securityLevel, keyAlgorithm
- removeCredential selector: credentialId or userId, only when resolution is unique
- implicit credential selection: forbidden in all cases

## Challenge Input Contract

1. challenge is opaque caller input.
2. challenge is required in registerCredential and authenticate.
3. MVP canonical input format is base64url non-empty string.
4. Plugin validates syntax only, not business semantics.
5. Missing challenge -> challengeMissing.
6. Malformed challenge -> challengeInvalid.

## Credential Identifier Contract

1. registerCredential requires caller-supplied credentialId.
2. credentialId must be unique in local plugin storage.
3. Plugin uses credentialId for lookup, signing, and removal.
4. Ambiguous lookup must fail explicitly.
5. Plugin must not auto-select credentials.

## Canonical Signed Payload Contract

### Signing Rule

Plugin signs canonical UTF-8 bytes of a fixed JSON payload and returns:
- signedPayload: base64url(utf8(canonical-json))
- signature: base64url(ecdsa-sign(signedPayload-bytes))

### Payload Schema (v1)

```json
{
  "v": 1,
  "type": "registration | authentication",
  "challenge": "<caller-challenge-base64url>",
  "credentialId": "<caller-supplied-id>",
  "userId": "<optional-bound-user-id>",
  "algorithm": "ES256"
}
```

### Canonicalization Rule

Property insertion order must be fixed as:
1. v
2. type
3. challenge
4. credentialId
5. userId (if present)
6. algorithm

No re-serialization variance is allowed across platforms.

## Registration Contract

1. Requires userId, credentialId, challenge.
2. Requires biometric verification.
3. Fails if security policy cannot be satisfied.
4. Generates key pair and stores private key in protected native storage (or software-only simulation on web).
5. Returns public fields only.
6. Fails with credentialAlreadyExists when uniqueness scope conflicts.
7. If requireHardwareBackedKey is true, registration must fail with securityLevelInsufficient when the platform cannot produce hardware-backed key material.

## Authentication Contract

1. Requires challenge and explicit selector (credentialId and/or userId).
2. Requires biometric verification.
3. Fails when no unique local credential can be resolved.
4. Signs canonical payload with selected credential private key.
5. Returns signature + signedPayload + metadata.

## Selection Rules

1. If credentialId is present, resolve by credentialId first.
2. If only userId is present, resolve by userId.
3. If both are present and conflict, fail with configurationError.
4. If neither selector is provided, fail with configurationError.
5. Implicit selection is forbidden even when only one credential exists.

## Removal Rules

1. removeCredential accepts credentialId or userId.
2. Removal executes only when selector resolves uniquely.
3. Ambiguous selector fails.
4. Missing credential may return removed=false (recommended deterministic MVP behavior).

## Error Model

Canonical business error semantics:
- userCancel and systemCancel are distinct
- credentialNotFound and credentialInvalidated are distinct
- securityLevelInsufficient for policy mismatch
- raw native errors are not public primary contract

## Advisory Integrity Signal

- detectCompromisedDevice is advisory-only in MVP.
- When requested, plugin returns compromisedDeviceSignal based on platform heuristics.
- This signal must not be treated as a standalone authentication decision.

## Platform Notes

### iOS (Native Target)
- LocalAuthentication for biometric verification
- Keychain/Secure Enclave for key material

### Android (Native Target)
- BiometricPrompt for biometric verification
- Android Keystore for key material
- strong biometric required in secure mode

### Web (MVP Simulation)
- Development flow only
- No native security parity claims
- Security level must be presented as simulation/software

## Multi-Account Policy

- Plugin supports multiple accounts on same device.
- Each account stores a separate credential.
- API supports lookup by userId or credentialId.
- Ambiguous resolution always fails.

## Acceptance Criteria Summary

### Functional
- Biometry capability check works
- Registration status check works
- Credential registration works with challenge and biometric gate
- Authentication works with challenge and biometric gate
- Remove credential works deterministically

### Security
- Private key never exposed to JS
- Registration blocked on insufficient security policy
- Authentication fails without challenge
- Prompt success alone is not enough; signing is required
- No device credential fallback path

### DX
- Promise-based typed API
- Canonical typed errors
- Web simulation supports development flow
- Multi-account supported with explicit selectors

## Minimal Integration Example (Illustrative)

1. App obtains or creates challenge according to its own policy.
2. App calls registerCredential/authenticate with explicit selectors.
3. Plugin performs biometric gate and key operation.
4. Plugin returns public output only.
5. App decides whether to send output to backend, verify locally, or use another trust flow.
