import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import {
  AuthenticateResult,
  BiometricCredential,
  CheckBiometryResult,
  CheckRegistrationResult,
  RegisterCredentialResult,
  RemoveCredentialResult,
} from 'capacitor-secure-biometric-credential-plugin';

@Component({
  selector: 'app-root',
  imports: [FormsModule],
  templateUrl: './app.html',
  styleUrl: './app.scss'
})
export class App {
  scenarioName = 'Happy Path';
  userId = 'demo-user-001';
  credentialId = 'cred-demo-001';
  challenge = this.generateBase64UrlChallenge();

  selectorMode: 'both' | 'credentialId' | 'userId' | 'none' = 'both';
  requireStrongBiometry = true;
  requireHardwareBackedKey = true;
  detectCompromisedDevice = false;

  loading = false;
  lastError = '';
  lastResult = '';

  checkBiometryResult?: CheckBiometryResult;
  checkRegistrationResult?: CheckRegistrationResult;
  registerResult?: RegisterCredentialResult;
  authenticateResult?: AuthenticateResult;
  removeResult?: RemoveCredentialResult;

  async checkBiometry(): Promise<void> {
    await this.runAction(async () => {
      this.checkBiometryResult = await BiometricCredential.checkBiometry();
      this.lastResult = this.pretty(this.checkBiometryResult);
    });
  }

  async checkRegistration(): Promise<void> {
    await this.runAction(async () => {
      const selector = this.buildSelector();
      this.checkRegistrationResult = await BiometricCredential.checkRegistration({
        ...selector,
      });
      this.lastResult = this.pretty(this.checkRegistrationResult);
    });
  }

  async registerCredential(): Promise<void> {
    await this.runAction(async () => {
      this.registerResult = await BiometricCredential.registerCredential({
        userId: this.userId,
        credentialId: this.credentialId,
        challenge: this.challenge,
        requireStrongBiometry: this.requireStrongBiometry,
        requireBiometricVerification: true,
        requireHardwareBackedKey: this.requireHardwareBackedKey,
        invalidateOnBiometricEnrollmentChange: true,
        detectCompromisedDevice: this.detectCompromisedDevice,
        iosPromptReason: 'Register biometric credential',
        androidTitle: 'Register credential',
        androidSubtitle: 'Use biometrics to register',
      });
      this.lastResult = this.pretty(this.registerResult);
    });
  }

  async authenticate(): Promise<void> {
    await this.runAction(async () => {
      const selector = this.buildSelector();
      this.authenticateResult = await BiometricCredential.authenticate({
        ...selector,
        challenge: this.challenge,
        requireStrongBiometry: this.requireStrongBiometry,
        requireBiometricVerification: true,
        detectCompromisedDevice: this.detectCompromisedDevice,
        iosPromptReason: 'Authenticate with biometrics',
        androidTitle: 'Authenticate',
        androidSubtitle: 'Use biometrics to sign challenge',
      });
      this.lastResult = this.pretty(this.authenticateResult);
    });
  }

  async removeCredential(): Promise<void> {
    await this.runAction(async () => {
      this.removeResult = await BiometricCredential.removeCredential({
        credentialId: this.credentialId,
      });
      this.lastResult = this.pretty(this.removeResult);
    });
  }

  regenerateChallenge(): void {
    this.challenge = this.generateBase64UrlChallenge();
  }

  applyScenarioHappyPath(): void {
    this.scenarioName = 'Happy Path';
    this.userId = 'demo-user-001';
    this.credentialId = 'cred-demo-001';
    this.challenge = this.generateBase64UrlChallenge();
    this.selectorMode = 'both';
    this.requireStrongBiometry = true;
    this.requireHardwareBackedKey = true;
    this.detectCompromisedDevice = false;
  }

  applyScenarioInvalidChallenge(): void {
    this.scenarioName = 'Invalid Challenge';
    this.challenge = 'invalid.challenge@@@';
  }

  applyScenarioMissingSelector(): void {
    this.scenarioName = 'Missing Selector';
    this.selectorMode = 'none';
    this.challenge = this.generateBase64UrlChallenge();
  }

  applyScenarioCompatibilityMode(): void {
    this.scenarioName = 'Compatibility Mode';
    this.selectorMode = 'both';
    this.requireStrongBiometry = false;
    this.requireHardwareBackedKey = false;
    this.detectCompromisedDevice = true;
    this.challenge = this.generateBase64UrlChallenge();
  }

  private buildSelector(): { userId?: string; credentialId?: string } {
    if (this.selectorMode === 'none') {
      return {};
    }

    if (this.selectorMode === 'credentialId') {
      return { credentialId: this.credentialId };
    }

    if (this.selectorMode === 'userId') {
      return { userId: this.userId };
    }

    return {
      userId: this.userId,
      credentialId: this.credentialId,
    };
  }

  private async runAction(action: () => Promise<void>): Promise<void> {
    this.loading = true;
    this.lastError = '';

    try {
      await action();
    } catch (error: unknown) {
      this.lastError = this.pretty(error);
    } finally {
      this.loading = false;
    }
  }

  private generateBase64UrlChallenge(): string {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    const b64 = btoa(String.fromCharCode(...bytes));
    return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }

  private pretty(value: unknown): string {
    return JSON.stringify(value, null, 2);
  }
}
