const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/

export function assertBase64UrlNonEmpty(value: string): void {
  if (!value || value.trim().length === 0) {
    throw new Error('missing')
  }

  if (!BASE64URL_PATTERN.test(value)) {
    throw new Error('invalid')
  }
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = ''
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i])
  }

  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

export function fromBase64Url(value: string): Uint8Array {
  const padded = value + '='.repeat((4 - (value.length % 4)) % 4)
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(base64)
  const out = new Uint8Array(binary.length)

  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i)
  }

  return out
}

export function utf8ToBase64Url(value: string): string {
  return toBase64Url(new TextEncoder().encode(value))
}

export function base64UrlToUtf8(value: string): string {
  return new TextDecoder().decode(fromBase64Url(value))
}

/**
 * Converts an ECDSA signature from IEEE P1363 format (r‖s, fixed 64 bytes for P-256)
 * to DER (RFC 3279 ASN.1 SEQUENCE of two INTEGERs).
 * This normalizes the web platform output to match iOS/Android native format.
 */
export function ieeeP1363ToDer(p1363: Uint8Array): Uint8Array {
  const n = p1363.length / 2
  const r = p1363.subarray(0, n)
  const s = p1363.subarray(n)

  const rDer = integerToDer(r)
  const sDer = integerToDer(s)

  const seqLen = rDer.length + sDer.length
  const der = new Uint8Array(2 + seqLen)
  der[0] = 0x30 // SEQUENCE tag
  der[1] = seqLen
  der.set(rDer, 2)
  der.set(sDer, 2 + rDer.length)

  return der
}

function integerToDer(value: Uint8Array): Uint8Array {
  // Strip leading zeros but keep at least one byte
  let start = 0
  while (start < value.length - 1 && value[start] === 0) {
    start += 1
  }
  const trimmed = value.subarray(start)

  // If high bit is set, prepend 0x00 to indicate positive integer
  const needsPad = trimmed[0] >= 0x80
  const len = trimmed.length + (needsPad ? 1 : 0)

  const out = new Uint8Array(2 + len)
  out[0] = 0x02 // INTEGER tag
  out[1] = len
  if (needsPad) {
    out[2] = 0x00
    out.set(trimmed, 3)
  } else {
    out.set(trimmed, 2)
  }

  return out
}
