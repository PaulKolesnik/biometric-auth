# Capacitor Secure Biometric Credential Plugin

This repository contains the initial implementation of a reusable Capacitor plugin that combines OS biometric verification with local private-key signing.

## Status

MVP scaffolding in progress:
- Typed plugin API contract
- Canonical error model
- Web simulation for development flows
- Canonical signed payload helper
- Native iOS and Android plugin skeletons
- Native iOS and Android foundational biometric/key operations
- Plugin-first specification document for handoff

## Build

```bash
npm install
npm run build
```

## Notes

- Native iOS and Android now include foundational biometric prompt and key operations, but still require hardening, full device matrix validation, and production-grade error mapping.
- Web implementation is simulation only and does not claim hardware-backed security.
- The canonical requirements and decisions are documented in `docs/plugin-first-spec.md`.
