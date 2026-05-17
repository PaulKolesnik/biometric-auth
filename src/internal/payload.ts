import { utf8ToBase64Url } from './encoding'

export type SignedPayloadType = 'registration' | 'authentication'

export interface CanonicalSignedPayload {
  v: 2
  type: SignedPayloadType
  challenge: string
  credentialId: string
  userId?: string
  algorithm: 'ES256'
  securityLevel: string
  deviceIntegrity: boolean
}

export function buildCanonicalPayload(input: {
  type: SignedPayloadType
  challenge: string
  credentialId: string
  userId?: string
  securityLevel: string
  deviceIntegrity: boolean
}): CanonicalSignedPayload {
  return {
    v: 2,
    type: input.type,
    challenge: input.challenge,
    credentialId: input.credentialId,
    userId: input.userId,
    algorithm: 'ES256',
    securityLevel: input.securityLevel,
    deviceIntegrity: input.deviceIntegrity,
  }
}

export function serializeCanonicalPayload(payload: CanonicalSignedPayload): string {
  const stable: Record<string, unknown> = {
    v: payload.v,
    type: payload.type,
    challenge: payload.challenge,
    credentialId: payload.credentialId,
  }

  if (payload.userId) {
    stable.userId = payload.userId
  }

  stable.algorithm = payload.algorithm
  stable.securityLevel = payload.securityLevel
  stable.deviceIntegrity = payload.deviceIntegrity
  return JSON.stringify(stable)
}

export function encodeSignedPayload(payload: CanonicalSignedPayload): string {
  return utf8ToBase64Url(serializeCanonicalPayload(payload))
}
