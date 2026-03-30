export enum BiometryType {
  none = 'none',
  touchId = 'touchId',
  faceId = 'faceId',
  fingerprint = 'fingerprint',
  face = 'face',
  iris = 'iris',
}

export enum CredentialSecurityLevel {
  unknown = 'unknown',
  software = 'software',
  hardware = 'hardware',
  secureEnclave = 'secureEnclave',
  strongBox = 'strongBox',
}

export enum PluginErrorCode {
  unknown = 'unknown',
  notSupported = 'notSupported',
  notAvailable = 'notAvailable',
  notEnrolled = 'notEnrolled',
  deviceNotSecure = 'deviceNotSecure',
  userCancel = 'userCancel',
  systemCancel = 'systemCancel',
  lockout = 'lockout',
  invalidContext = 'invalidContext',
  configurationError = 'configurationError',
  credentialNotFound = 'credentialNotFound',
  credentialAlreadyExists = 'credentialAlreadyExists',
  credentialInvalidated = 'credentialInvalidated',
  keyGenerationFailed = 'keyGenerationFailed',
  keyStoreUnavailable = 'keyStoreUnavailable',
  challengeMissing = 'challengeMissing',
  challengeInvalid = 'challengeInvalid',
  signatureFailed = 'signatureFailed',
  verificationRequired = 'verificationRequired',
  securityLevelInsufficient = 'securityLevelInsufficient',
  compromisedDevice = 'compromisedDevice',
  internalError = 'internalError',
}

export interface PluginError extends Error {
  name: 'PluginError'
  code: PluginErrorCode
  message: string
  platform: 'ios' | 'android' | 'web'
  nativeCode?: string | number
  nativeMessage?: string
  isRetryable: boolean
  isUserActionable: boolean
  details?: Record<string, unknown>
}

export interface CheckBiometryResult {
  isAvailable: boolean
  strongBiometryIsAvailable: boolean
  biometryType: BiometryType
  biometryTypes: BiometryType[]
  deviceIsSecure: boolean
  meetsSecurityRequirements: boolean
  reason: string
  code: PluginErrorCode | ''
}

export interface CheckRegistrationOptions {
  userId?: string
  credentialId?: string
}

export interface CheckRegistrationResult {
  isRegistered: boolean
  credentialId?: string
  userId?: string
  securityLevel?: CredentialSecurityLevel
  invalidated?: boolean
  reason?: string
  code?: PluginErrorCode | ''
}

export interface RegisterCredentialOptions {
  userId: string
  credentialId: string
  challenge: string
  displayName?: string
  requireBiometricVerification?: boolean
  requireStrongBiometry?: boolean
  requireHardwareBackedKey?: boolean
  invalidateOnBiometricEnrollmentChange?: boolean
  detectCompromisedDevice?: boolean
  iosPromptReason?: string
  androidTitle?: string
  androidSubtitle?: string
}

export interface RegisterCredentialResult {
  credentialId: string
  userId: string
  publicKey: string
  algorithm: string
  securityLevel: CredentialSecurityLevel
  signature: string
  signedPayload: string
  compromisedDeviceSignal?: boolean
}

export interface AuthenticateOptions {
  userId?: string
  credentialId?: string
  challenge: string
  requireBiometricVerification?: boolean
  requireStrongBiometry?: boolean
  detectCompromisedDevice?: boolean
  iosPromptReason?: string
  androidTitle?: string
  androidSubtitle?: string
}

export interface AuthenticateResult {
  credentialId: string
  userId?: string
  signature: string
  signedPayload: string
  algorithm: string
  securityLevel: CredentialSecurityLevel
  usedBiometry: true
  compromisedDeviceSignal?: boolean
}

export interface RemoveCredentialOptions {
  userId?: string
  credentialId?: string
}

export interface RemoveCredentialResult {
  removed: boolean
}

export interface BiometricCredentialPlugin {
  checkBiometry(): Promise<CheckBiometryResult>
  checkRegistration(options?: CheckRegistrationOptions): Promise<CheckRegistrationResult>
  registerCredential(options: RegisterCredentialOptions): Promise<RegisterCredentialResult>
  authenticate(options: AuthenticateOptions): Promise<AuthenticateResult>
  removeCredential(options?: RemoveCredentialOptions): Promise<RemoveCredentialResult>
}
