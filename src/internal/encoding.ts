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
