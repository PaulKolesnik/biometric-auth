import { registerPlugin } from '@capacitor/core'

import type { BiometricCredentialPlugin } from './definitions'

const BiometricCredential = registerPlugin<BiometricCredentialPlugin>('BiometricCredential', {
  web: () => import('./web').then((module) => new module.BiometricCredentialWeb()),
})

export * from './definitions'
export * from './errors'
export { BiometricCredential }
