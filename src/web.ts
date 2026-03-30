import { WebPlugin } from '@capacitor/core'
import {
  AuthenticateOptions,
  AuthenticateResult,
  BiometricCredentialPlugin,
  BiometryType,
  CheckBiometryResult,
  CheckRegistrationOptions,
  CheckRegistrationResult,
  CredentialSecurityLevel,
  PluginErrorCode,
  RegisterCredentialOptions,
  RegisterCredentialResult,
  RemoveCredentialOptions,
  RemoveCredentialResult,
} from './definitions'
import { fail } from './errors'
import { assertBase64UrlNonEmpty, fromBase64Url, toBase64Url } from './internal/encoding'
import { buildCanonicalPayload, encodeSignedPayload } from './internal/payload'
import { StoredCredentialRecord, WebCredentialStore } from './internal/web-store'

export class BiometricCredentialWeb extends WebPlugin implements BiometricCredentialPlugin {
  private readonly store = new WebCredentialStore()

  async checkBiometry(): Promise<CheckBiometryResult> {
    const cryptoAvailable = typeof crypto !== 'undefined' && !!crypto.subtle

    return {
      isAvailable: cryptoAvailable,
      strongBiometryIsAvailable: false,
      biometryType: BiometryType.none,
      biometryTypes: [BiometryType.none],
      deviceIsSecure: false,
      meetsSecurityRequirements: cryptoAvailable,
      reason: cryptoAvailable
        ? 'Web simulation mode. Native biometric/security guarantees are not available.'
        : 'Web Crypto is unavailable in this environment.',
      code: cryptoAvailable ? '' : PluginErrorCode.notAvailable,
    }
  }

  async checkRegistration(options?: CheckRegistrationOptions): Promise<CheckRegistrationResult> {
    const matches = this.resolveRecords(options)

    if (matches.errorCode) {
      return {
        isRegistered: false,
        reason: matches.reason,
        code: matches.errorCode,
      }
    }

    if (matches.records.length !== 1) {
      return {
        isRegistered: false,
        reason: 'No credential found for supplied selector.',
        code: PluginErrorCode.credentialNotFound,
      }
    }

    const record = matches.records[0]
    return {
      isRegistered: true,
      credentialId: record.credentialId,
      userId: record.userId,
      securityLevel: record.securityLevel,
      invalidated: record.invalidated,
      code: record.invalidated ? PluginErrorCode.credentialInvalidated : '',
      reason: record.invalidated ? 'Credential was invalidated in local store.' : undefined,
    }
  }

  async registerCredential(options: RegisterCredentialOptions): Promise<RegisterCredentialResult> {
    this.ensureWebCryptoAvailable()
    this.validateChallenge(options.challenge)
    this.ensureRequired(options.userId, 'userId')
    this.ensureRequired(options.credentialId, 'credentialId')

    if (options.requireStrongBiometry) {
      fail({
        code: PluginErrorCode.securityLevelInsufficient,
        message: 'Web simulation cannot satisfy strong biometric requirements.',
        platform: 'web',
        isUserActionable: true,
      })
    }

    if (this.store.hasCredentialId(options.credentialId)) {
      fail({
        code: PluginErrorCode.credentialAlreadyExists,
        message: 'Credential already exists for this credentialId.',
        platform: 'web',
        isUserActionable: true,
      })
    }

    const existingByUser = this.store.getByUserId(options.userId)
    if (existingByUser.length > 0) {
      fail({
        code: PluginErrorCode.credentialAlreadyExists,
        message: 'A credential already exists for this user on this device.',
        platform: 'web',
        isUserActionable: true,
      })
    }

    const keyPair = await this.generateKeyPair()
    const exportedPublic = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
    const exportedPrivate = await crypto.subtle.exportKey('jwk', keyPair.privateKey)

    const payload = buildCanonicalPayload({
      type: 'registration',
      challenge: options.challenge,
      credentialId: options.credentialId,
      userId: options.userId,
    })

    const signedPayload = encodeSignedPayload(payload)
    const signature = await this.signPayload(keyPair.privateKey, signedPayload)

    const record: StoredCredentialRecord = {
      credentialId: options.credentialId,
      userId: options.userId,
      publicKeyJwk: exportedPublic,
      privateKeyJwk: exportedPrivate,
      algorithm: 'ES256',
      securityLevel: CredentialSecurityLevel.software,
      invalidated: false,
    }

    this.store.upsert(record)

    return {
      credentialId: record.credentialId,
      userId: record.userId,
      publicKey: JSON.stringify(record.publicKeyJwk),
      algorithm: record.algorithm,
      securityLevel: record.securityLevel,
      signature,
      signedPayload,
      compromisedDeviceSignal: options.detectCompromisedDevice ? false : undefined,
    }
  }

  async authenticate(options: AuthenticateOptions): Promise<AuthenticateResult> {
    this.ensureWebCryptoAvailable()
    this.validateChallenge(options.challenge)

    const resolved = this.resolveSingleRecordOrFail(options)

    if (resolved.invalidated) {
      fail({
        code: PluginErrorCode.credentialInvalidated,
        message: 'Credential is invalidated and cannot be used.',
        platform: 'web',
        isUserActionable: true,
      })
    }

    if (options.requireStrongBiometry) {
      fail({
        code: PluginErrorCode.securityLevelInsufficient,
        message: 'Web simulation cannot satisfy strong biometric requirements.',
        platform: 'web',
        isUserActionable: true,
      })
    }

    const privateKey = await crypto.subtle.importKey(
      'jwk',
      resolved.privateKeyJwk,
      {
        name: 'ECDSA',
        namedCurve: 'P-256',
      },
      false,
      ['sign'],
    )

    const payload = buildCanonicalPayload({
      type: 'authentication',
      challenge: options.challenge,
      credentialId: resolved.credentialId,
      userId: resolved.userId,
    })

    const signedPayload = encodeSignedPayload(payload)
    const signature = await this.signPayload(privateKey, signedPayload)

    return {
      credentialId: resolved.credentialId,
      userId: resolved.userId,
      signature,
      signedPayload,
      algorithm: resolved.algorithm,
      securityLevel: resolved.securityLevel,
      usedBiometry: true,
      compromisedDeviceSignal: options.detectCompromisedDevice ? false : undefined,
    }
  }

  async removeCredential(options?: RemoveCredentialOptions): Promise<RemoveCredentialResult> {
    const matches = this.resolveRecords(options)

    if (matches.errorCode) {
      fail({
        code: matches.errorCode,
        message: matches.reason ?? 'Failed to resolve credential selector.',
        platform: 'web',
        isUserActionable: true,
      })
    }

    if (matches.records.length === 0) {
      return { removed: false }
    }

    const removed = this.store.removeByCredentialId(matches.records[0].credentialId)
    return { removed }
  }

  private ensureRequired(value: string | undefined, field: string): void {
    if (!value || value.trim().length === 0) {
      fail({
        code: PluginErrorCode.configurationError,
        message: `Missing required field: ${field}`,
        platform: 'web',
        isUserActionable: true,
      })
    }
  }

  private ensureWebCryptoAvailable(): void {
    if (typeof crypto === 'undefined' || !crypto.subtle) {
      fail({
        code: PluginErrorCode.notAvailable,
        message: 'Web Crypto is unavailable.',
        platform: 'web',
        isUserActionable: true,
      })
    }
  }

  private validateChallenge(challenge: string): void {
    try {
      assertBase64UrlNonEmpty(challenge)
    } catch (error) {
      const code = error instanceof Error && error.message === 'missing'
        ? PluginErrorCode.challengeMissing
        : PluginErrorCode.challengeInvalid

      fail({
        code,
        message: code === PluginErrorCode.challengeMissing
          ? 'Challenge is required.'
          : 'Challenge must be a base64url non-empty string.',
        platform: 'web',
        isUserActionable: true,
      })
    }
  }

  private resolveSingleRecordOrFail(selector: {
    credentialId?: string
    userId?: string
  }): StoredCredentialRecord {
    const resolved = this.resolveRecords(selector)

    if (resolved.errorCode) {
      fail({
        code: resolved.errorCode,
        message: resolved.reason ?? 'Credential selector is invalid.',
        platform: 'web',
        isUserActionable: true,
      })
    }

    if (resolved.records.length === 0) {
      fail({
        code: PluginErrorCode.credentialNotFound,
        message: 'No credential found for supplied selector.',
        platform: 'web',
        isUserActionable: true,
      })
    }

    return resolved.records[0]
  }

  private resolveRecords(selector?: {
    credentialId?: string
    userId?: string
  }): {
    records: StoredCredentialRecord[]
    errorCode?: PluginErrorCode
    reason?: string
  } {
    const hasCredentialId = !!selector?.credentialId
    const hasUserId = !!selector?.userId

    if (!hasCredentialId && !hasUserId) {
      return {
        records: [],
        errorCode: PluginErrorCode.configurationError,
        reason: 'Explicit selector is required. Implicit credential selection is forbidden.',
      }
    }

    if (hasCredentialId && hasUserId) {
      const byCredentialId = this.store.getByCredentialId(selector!.credentialId!)
      if (!byCredentialId) {
        return { records: [] }
      }

      if (byCredentialId.userId !== selector!.userId) {
        return {
          records: [],
          errorCode: PluginErrorCode.configurationError,
          reason: 'credentialId and userId refer to different credentials.',
        }
      }

      return {
        records: [byCredentialId],
      }
    }

    if (hasCredentialId) {
      const record = this.store.getByCredentialId(selector!.credentialId!)
      return { records: record ? [record] : [] }
    }

    const byUserId = this.store.getByUserId(selector!.userId!)
    if (byUserId.length > 1) {
      return {
        records: [],
        errorCode: PluginErrorCode.configurationError,
        reason: 'Selector is ambiguous for this userId.',
      }
    }

    return { records: byUserId }
  }

  private async generateKeyPair(): Promise<CryptoKeyPair> {
    try {
      return await crypto.subtle.generateKey(
        {
          name: 'ECDSA',
          namedCurve: 'P-256',
        },
        true,
        ['sign', 'verify'],
      )
    } catch {
      fail({
        code: PluginErrorCode.keyGenerationFailed,
        message: 'Failed to generate key pair.',
        platform: 'web',
        isUserActionable: false,
      })
    }
  }

  private async signPayload(privateKey: CryptoKey, signedPayload: string): Promise<string> {
    try {
      const payloadBytes = fromBase64Url(signedPayload)
      const payloadBuffer = Uint8Array.from(payloadBytes).buffer
      const signature = await crypto.subtle.sign(
        {
          name: 'ECDSA',
          hash: 'SHA-256',
        },
        privateKey,
        payloadBuffer,
      )

      return toBase64Url(new Uint8Array(signature))
    } catch {
      fail({
        code: PluginErrorCode.signatureFailed,
        message: 'Failed to sign payload.',
        platform: 'web',
        isUserActionable: false,
      })
    }
  }
}
