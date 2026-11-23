# DIFME edge app (README row 5.1, ADR-005, ADR-016)

An offline-first wallet for a phone: Vue 3 UI in a Tauri 2 shell over a Rust core. Pays offline from pre-granted
spending rights and syncs with the QUIC hub (services/hub) when connected.

| Part | What it is | Checks |
|---|---|---|
| `core/` | wallet state as an automerge CRDT (escrow balances, pending payments), Blake3 integrity, a simulated TEE (software key store standing in for StrongBox/KeyMint) that signs payment intents (COSE_Sign1) and produces EAT tokens the attestation verifier appraises, a Wasmtime WASI Preview 2 host for sandboxed rules, the HCE APDU responder, QUIC sync with the hub | `cargo test -p difme-edge-core`: CRDT merge, rule via the WASM component, attestation against `services/attestation`, sync against `services/hub` |
| `rules/offline-limit` | the offline limit rule as a WASI P2 component (`wit/offline-limit.wit`); its own workspace, built by `rules/build.sh` for wasm32-wasip2 | used by the core's rule tests |
| `app/` | Vue 3 UI: balance and offline rights, pay offline, sync, device attestation (`src/api.ts` calls the core; outside Tauri a stand-in with the same rules answers) | `npm test` (vitest), `npm run typecheck` |
| `app/src-tauri/` | Tauri 2 shell: the core behind four commands (`wallet_status`, `pay_offline`, `sync`, `attestation`), state in the app's data directory, strict CSP | `cargo check -p difme-edge-app` |

Run on desktop: `cd app && npm ci && npx tauri dev` (needs WebKitGTK 4.1 on Linux).

## Android (not built here: no Android SDK/NDK in this environment)

1. Install Android Studio's SDK and NDK; set `ANDROID_HOME` and `NDK_HOME`.
2. `cd app && npx tauri android init`, which generates `src-tauri/gen/android` (not committed).
3. Then run `npx tauri android dev` (emulator) or `npx tauri android build`.

Still to add for the phone: the Kotlin side of NFC and background sync.
- A `HostApduService` that hands each APDU to the core's `hce_apdu` (the Rust responder exists, `core/src/hce.rs`).
- A WorkManager job that calls `sync` when the device is online.
- A real StrongBox/KeyMint key store behind the core's `Tee` trait, in place of the software one.
- ONNX scoring on the device: the core has the interface (`core/src/ml.rs`); no model is shipped yet.
