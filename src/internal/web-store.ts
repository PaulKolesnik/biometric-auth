import { CredentialSecurityLevel } from '../definitions'

export interface StoredCredentialRecord {
  credentialId: string
  userId: string
  publicKeyJwk: JsonWebKey
  privateKeyJwk: JsonWebKey
  algorithm: 'ES256'
  securityLevel: CredentialSecurityLevel
  invalidated: boolean
}

const STORAGE_KEY = 'biometric_credential_plugin_records_v1'

function canUseLocalStorage(): boolean {
  try {
    return typeof localStorage !== 'undefined'
  } catch {
    return false
  }
}

export class WebCredentialStore {
  private records = new Map<string, StoredCredentialRecord>()

  constructor() {
    this.load()
  }

  getByCredentialId(credentialId: string): StoredCredentialRecord | undefined {
    return this.records.get(credentialId)
  }

  getByUserId(userId: string): StoredCredentialRecord[] {
    return [...this.records.values()].filter((record) => record.userId === userId)
  }

  getAll(): StoredCredentialRecord[] {
    return [...this.records.values()]
  }

  hasCredentialId(credentialId: string): boolean {
    return this.records.has(credentialId)
  }

  upsert(record: StoredCredentialRecord): void {
    this.records.set(record.credentialId, record)
    this.persist()
  }

  removeByCredentialId(credentialId: string): boolean {
    const removed = this.records.delete(credentialId)
    if (removed) {
      this.persist()
    }

    return removed
  }

  private load(): void {
    if (!canUseLocalStorage()) {
      return
    }

    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) {
      return
    }

    try {
      const parsed = JSON.parse(raw) as StoredCredentialRecord[]
      for (const record of parsed) {
        this.records.set(record.credentialId, record)
      }
    } catch {
      this.records.clear()
    }
  }

  private persist(): void {
    if (!canUseLocalStorage()) {
      return
    }

    localStorage.setItem(STORAGE_KEY, JSON.stringify([...this.records.values()]))
  }
}
