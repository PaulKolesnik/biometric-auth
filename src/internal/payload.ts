import { utf8ToBase64Url } from './encoding'

export type SignedPayloadType = 'registration' | 'authentication'

export interface CanonicalSignedPayload {
  v: 1
  type: SignedPayloadType
  challenge: string
  credentialId: string
  userId?: string
  algorithm: 'ES256'
}

export function buildCanonicalPayload(input: {
  type: SignedPayloadType
  challenge: string
  credentialId: string
  userId?: string
}): CanonicalSignedPayload {
  return {
    v: 1,
    type: input.type,
    challenge: input.challenge,
    credentialId: input.credentialId,
    userId: input.userId,
    algorithm: 'ES256',
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
  return JSON.stringify(stable)
}

export function encodeSignedPayload(payload: CanonicalSignedPayload): string {
  return utf8ToBase64Url(serializeCanonicalPayload(payload))
}
