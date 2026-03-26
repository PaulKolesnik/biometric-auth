import { PluginError, PluginErrorCode } from './definitions'

interface PluginErrorInit {
  code: PluginErrorCode
  message: string
  platform: 'ios' | 'android' | 'web'
  nativeCode?: string | number
  nativeMessage?: string
  isRetryable?: boolean
  isUserActionable?: boolean
  details?: Record<string, unknown>
}

export class BiometricPluginError extends Error implements PluginError {
  name: 'PluginError' = 'PluginError'
  code: PluginErrorCode
  platform: 'ios' | 'android' | 'web'
  nativeCode?: string | number
  nativeMessage?: string
  isRetryable: boolean
  isUserActionable: boolean
  details?: Record<string, unknown>

  constructor(init: PluginErrorInit) {
    super(init.message)
    this.code = init.code
    this.platform = init.platform
    this.nativeCode = init.nativeCode
    this.nativeMessage = init.nativeMessage
    this.isRetryable = init.isRetryable ?? false
    this.isUserActionable = init.isUserActionable ?? false
    this.details = init.details
  }
}

export function fail(init: PluginErrorInit): never {
  throw new BiometricPluginError(init)
}
