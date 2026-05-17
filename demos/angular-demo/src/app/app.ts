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
        iosPromptReason: 'Authenticate with biometrics',
        androidTitle: 'Authenticate',
        androidSubtitle: 'Use biometrics to sign challenge',
      });
      this.lastResult = this.pretty(this.authenticateResult);
    });
  }

  async verifyRegistration(): Promise<void> {
    await this.runAction(async () => {
      if (!this.registerResult) {
        throw new Error('No registration result to verify. Register a credential first.');
      }

      const { publicKey, signature, signedPayload } = this.registerResult;

      // publicKey is now SPKI (base64url) — import directly
      const publicKeyBytes = this.fromBase64Url(publicKey);
      const publicKeyObj = await crypto.subtle.importKey(
        'spki',
        publicKeyBytes.buffer as ArrayBuffer,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
      );

      // signature is DER — WebCrypto verify() expects IEEE P1363, so convert
      const derBytes = this.fromBase64Url(signature);
      const p1363Bytes = this.derToP1363(derBytes, 32);
      const payloadBytes = this.fromBase64Url(signedPayload);

      const isValid = await crypto.subtle.verify(
        { name: 'ECDSA', hash: 'SHA-256' },
        publicKeyObj,
        p1363Bytes.buffer as ArrayBuffer,
        payloadBytes.buffer as ArrayBuffer,
      );

      const payloadJson = JSON.parse(new TextDecoder().decode(payloadBytes));
      const challengeMatches = payloadJson.challenge === this.challenge;

      this.lastResult = this.pretty({
        signatureValid: isValid,
        challengeMatches,
        payloadType: payloadJson.type,
        payload: payloadJson,
      });
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

  private fromBase64Url(input: string): Uint8Array {
    const base64 = input.replace(/-/g, '+').replace(/_/g, '/');
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /** Converts a DER-encoded ECDSA signature to IEEE P1363 (r‖s) for WebCrypto verify(). */
  private derToP1363(der: Uint8Array, componentLength: number): Uint8Array {
    // DER: 0x30 <seqLen> 0x02 <rLen> <r> 0x02 <sLen> <s>
    let offset = 2; // skip SEQUENCE tag + length
    const rLen = der[offset + 1];
    const rData = der.subarray(offset + 2, offset + 2 + rLen);
    offset += 2 + rLen;
    const sLen = der[offset + 1];
    const sData = der.subarray(offset + 2, offset + 2 + sLen);

    const result = new Uint8Array(componentLength * 2);
    // Copy r, right-aligned (strip leading zero padding)
    const rTrimmed = rData.length > componentLength ? rData.subarray(rData.length - componentLength) : rData;
    result.set(rTrimmed, componentLength - rTrimmed.length);
    // Copy s, right-aligned
    const sTrimmed = sData.length > componentLength ? sData.subarray(sData.length - componentLength) : sData;
    result.set(sTrimmed, componentLength * 2 - sTrimmed.length);
    return result;
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
