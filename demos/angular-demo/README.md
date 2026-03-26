# Angular Capacitor Demo

This demo is a Capacitor mobile app (Angular UI) for exercising the secure biometric credential plugin.

## What It Tests

- checkBiometry
- checkRegistration
- registerCredential
- authenticate
- removeCredential

The screen lets you set userId, credentialId, challenge, then execute each method and inspect JSON output.

## Setup

```bash
npm install
```

## Mobile Workflow

```bash
npm run cap:sync
```

This command:
1. Builds the plugin package in the repo root.
2. Builds the Angular app.
3. Syncs web assets and plugins into native projects.

### Android

```bash
npm run cap:android
```

### Android Direct Run

```bash
npm run cap:run:android
```

If deployment fails, check these prerequisites:
1. Java JDK installed and JAVA_HOME configured (Android build requires it).
2. At least one emulator/device is available.

List available Android targets:

```bash
npm run cap:targets:android
```

## Web (Optional)

```bash
npm start
```

Web mode is for quick UI iteration only. Real biometric/security behavior must be validated on native devices.

## Notes

- Android and iOS native projects are created in this demo folder.
- iOS build/run still requires macOS + Xcode environment.
- Use `npm run cap:doctor` to inspect Capacitor environment health.
- If you see `JAVA_HOME is not set`, configure JDK 17 and restart the terminal.
