# Next session: start here (updated 2026-11-22, night)

Read this, then `docs/status.md`.

## 0. Latest (2026-11-22, night) — read first
- **Keys only in the (emulated) TEE, enforced:** services/hsm starts only through attested key release (own KBS
  client; Trustee app `tee-key-release` in `security`; OpenBao mount `kbs`, roles `trustee-kbs` read-only and
  `hsm-bootstrap` create-only); no keys in Secrets (`ci/no-key-material.sh` in verify); ACS holds no keys (signing
  and HMAC in the hsm). Verified against real Trustee: `ci/hsm-key-release-test.sh` (needs TRUSTEE_DIR checkout).
- **card-issuer built** (`services/card-issuer`, Go): debit on Fineract savings holds, credit line with issuer-enforced
  open-to-buy, CVV2/dCVV2/PIN (ISO-4 from the app) via the hsm, issuer authorisation/clearing/reversal, ACS card
  lookup, Postgres store with the **card vault** (PAN only as HMAC index + AES-GCM ciphertext, keys in the hsm).
  The switch (scheme-sim) delegates issuer decisions to it (CVV2 field 48, PIN field 52, 0200 cleared, 0400 reversed).
  Live: `ci/card-issuer-live.sh` (Fineract docker + hsm + scheme-sim + ISO adapter + ACS) PASS.
- **Cluster:** apps `card-security` (hsm attested, ACS, card-issuer) and `tee-key-release`; images difme-hsm,
  difme-card-issuer, difme-scheme-sim (with acs). Not yet run on a cluster: next cluster-verify with
  core,streaming,security,rails,fraud. Watch: Trustee pod start (init keys, OpenBao login), hsm first-start bootstrap,
  Keycloak client card-issuer → Fineract user card-issuer (same mechanism as fineract-service-users, still failing in
  run 2: see §3).
 Owner rules still apply: commits as `pratikmohanty1994
<pratikmohanty1994@users.noreply.github.com>`, no assistant trailers (process.md rule 15); free and open source only
(OSI; no BSL/SSPL/ELv2); `[skip ci]` unless a run is wanted; one cluster-verify at a time; push to `main` and mirror to
the session branch; nothing runs on the owner's PC.

## 1. The carried-over list (A–F): what is done

| # | Item | State |
|---|---|---|
| A1 | Image names → `ghcr.io/pratikmohanty1994-ui/…` | **Done** |
| A2 | Argo CD repoURLs → this repo | **Done** (also Fleet, Tekton, bootstrap, Kyverno signing identity) |
| A3 | Actions enabled, `images.yml` / `verify.yml` green | **Done**: every image group green 2026-11-22 |
| A4 | Actions secrets / ghcr permissions | **Done**: none needed (GITHUB_TOKEN + keyless cosign); packages publish |
| A5 | Archive `pratikmohanty1994/difme` | **Owner** |
| A6 | Revoke the token pasted in chat | **Owner** (do this first) |
| B1 | Build every changed image (payment hub, Hyperswitch) | **Done**: all built and signed, both platforms |
| B2 | Cluster sync breaks the old hub / missing Hyperswitch image | **Resolved**: cluster run 2 (45020164756) rails **converged** |
| B3 | Hyperswitch OOM in 16 GB | **Resolved**: `-j 1`, router opt-level 0, LLD on arm64 (no bigger runner needed) |
| B4 | Router on OpenBao secrets, `/health`, admin API call | **Partly**: router up on OpenBao secrets (555 migrations), readiness `/health`; admin API call not yet checked |
| B5 | Image workflows for PH-EE connectors and Mojaloop | **Pending** |
| C1 | Cluster checks | OpenBao login/injector/seed for Hyperswitch **done**; Fineract `fineract-service-users` **failing** (CrashLoop, see §3); VMPodScrape / Hyperswitch telemetry **not verified** |
| C2 | Istio RequestAuthentication + AuthorizationPolicy for PH-EE channel | **Pending** (with the PH-EE manifests) |
| C3 | PH-EE pods' metrics label/annotation | **Pending** (with the PH-EE manifests) |
| C4 | Fineract demo user `interopUser` (super user) | **Owner yes/no**, then delete/disable in the bootstrap job |
| D1–D5 | PH-EE + Mojaloop manifests, Spring Boot 3 / Camel 4 / Java 25 upgrade, switch the exchange and delete the interim hub, known gaps, exchange rails wiring | **Pending** |
| E1 | Temporal vs Fluxnova | **Owner** |
| E2 | CKEditor GPL badge vs Quill | **Owner** |
| E3 | WTFPL `dom-set`, `spark-md5` | **Owner** |
| E4 | Hyperswitch runner vs features | **Resolved** by B3 |
| E5 | Testing Toolkit reports on FerretDB | **Noted** (only if reports are kept) |
| F1 | Keep status.md / component-reuse.md current | Ongoing |
| F2 | OpenBao `initialize` blocks only run on first init | **Pending**: a job that applies KV mount, policies, roles idempotently |

## 2. Done this session (beyond A–F)
- Tazama replaces Hyperswitch FRM (ADR-023): built from source on DIFME's stack, rules 901/902/D01/D02, payment-hub
  fraud check before capture, verified end to end locally.
- Network tokens in scheme-sim (ADR-024); attested key release Trustee + OpenBao (ADR-026).
- Fineract credit gate (ADR-025): revolving line works; limit enforced by card-issuer (Fineract's own is not revolving).
- Security module `services/hsm` (jPOS): CVV2, CVV, CAVV + HTTP interface; card-cryptography plan
  (`docs/architecture/card-cryptography-plan.md`, incl. dCVV/dCVV2 and full CAVV lifecycle).
- Lightweight 3DS ACS (ADR-027) connected to CMS, Tazama, hsm and the authorisation switch; `ci/acs-e2e.sh` passes.

## 3. Cluster runs
Run 3 (45026327939, core,streaming,security,rails,fraud) dispatched 13:13 UTC with the Tazama uid fix and failing-pod log capture; a check-in is scheduled.

### Run 2 result and fixes pushed
core, streaming, security, **rails converged**; **fraud failed**:
- Tazama pods `CreateContainerConfigError`: `runAsNonRoot` with the image's non-numeric user `node`. **Fixed**:
  `runAsUser/runAsGroup: 1000` (render.py). Needs the next cluster run.
- `fineract-service-users` CrashLoop; logs were not captured. Likely cause: the Keycloak client-credentials token
  (`service-account-fineract-admin`) maps to no Fineract user, so the first API call is 401. cluster-verify now saves
  events + logs of every failing pod (`failing-pods.txt` in the artifact) to confirm. Fix options: map the service
  account's username claim to Fineract's seed user, or seed that user in Fineract's DB.

## 3b. Crypto modules built this session (services/hsm, 37 tests, every value cross-checked; summary in ADR-026 "Progress … later")
| Area | Done (reference) | Still open |
|---|---|---|
| Keys | ceremony, generate, KCV, ZMK exchange; TR-31 **B and D** (psec interop); AES KBPK; **labelled key store** (HSM_KEYS / HSM_DEV_KEYS) | LMK rotation drill; key store rendered from OpenBao by the attested release |
| CNP | CVV2, CVV, CAVV, dCVV2; **TAVV** in scheme-sim (CAVV layout, result 3, ECI 07) | Mastercard AAV/SPA2, Amex AEVV (specs not public); attempts CAVV |
| PIN | Visa PVV generate/verify, **IBM 3624 offset** (ext), ZPK→ZPK translation (psec); **DUKPT TDES** (X9.24-1 vector); **ISO 9564 format 4** AES PIN blocks ↔ format 0 (psec) | AES DUKPT (X9.24-3; needs published vectors); PIN generation/weak-PIN list; app PIN reveal |
| Chip | ARQC/ARPC Visa CVN 10/18/22, Mastercard CVN 16/**17/20/21** (pyemv); dCVV, CVC3 | Interac; AES chip cryptograms (no open reference); TC/AAC at clearing (same function) |
| Scripts | script MAC Visa CVN 10/18/22 (pyemv); **offline PIN change** script, PIN + MAC byte-exact (pyemv) | Mastercard script formats; confidentiality-only commands |
| Messages | ISO 9797-1 alg 3 retail MAC (psec); AES-CMAC (NIST SP 800-38B vectors) | MAC verify endpoints; P2PE data encryption |
| Perso | **issuer (02) and ICC (04) certificates**, verified by jPOS's Book 2 recovery | issuer RSA key under the LMK; perso file for a card bureau |
| Service | HTTP endpoints for CAVV, CVV/CVV2, dCVV/dCVV2, CVC3, PIN (PVV, translate, ISO-4), ARQC/ARPC, script MAC, retail MAC, CMAC; **image difme-hsm, rails app card-security** (hsm + ACS) | first cluster run of card-security; callers in card-issuer (not built) |
Correction to the plan: pyemv's Visa CVN 22 is TDES (option B, common session keys), not AES.

## 4. Owner's latest asks, still open
1. **"Finish all crypto modules"** (progress in §3b): build every remaining row of `card-cryptography-plan.md` in `services/hsm` (keys/TR-31,
   CNP incl. dCVV2/AAV/TAVV, PIN incl. ISO-4/AES DUKPT/IBM 3624, chip ARQC/ARPC incl. AES CVN 22, dCVV/CVC3, issuer
   scripts, personalisation RSA, MACs/terminals), each cross-checked with psec/pyemv/published vectors, then wire the
   callers (card-issuer, scheme-sim TSP) and delete the stopgaps.
2. **ACS on EMV 3DS 2.3.1: DONE 2026-11-22** (ADR-027 "EMV 3DS 2.3.1 alignment": versions, channels incl. 3RI, PA/NPA, OTP, single-select, OOB app, decoupled, browser HTML + notificationURL, app JWE verified with jwcrypto). Remaining 3DS items are ADR-027's "Still open". Original ask for reference: 2.3.1 message fields (e.g. `messageVersion`
   2.3.1, `acsInfoInd`, `threeDSRequestorAuthenticationInfo`, `transStatusReason` codes incl. 2.3.1 additions,
   device channels 01 app / 02 browser / 03 3RI, message categories 01 PA / 02 NPA), challenge UIs: native text
   (OTP), single/multi select, out-of-band (DIFME app push with biometric), HTML; browser challenge page with
   base64url CReq/CRes and `notificationURL`; app channel JWE (ECDH-ES ephemeral key from the SDK, A128CBC-HS256 /
   A128GCM); decoupled authentication (`acsDecConInd`); 3RI; SPC/FIDO (WebAuthn) for 2.3.1 where possible; RReq/RRes
   with the DS; a DS simulator; attempts CAVV; durable challenge store.
3. **Image + manifests for hsm and ACS** (rails), mTLS AuthorizationPolicy naming callers, LMK via attested release.

## 5. Everything else pending (overall)
- **Cards:** card-issuer (CMS: debit/prepaid on Fineract savings with holds, then credit with open-to-buy, statements,
  grace, renewal), card vault, Hyperswitch JWE adapter for network tokens; credit gate parts still to run (interest,
  delinquency bucket, chargeback).
- **Lending:** loan origination on Form.io + Fluxnova + DMN + Tazama (ADR-025).
- **Fraud:** D02 end to end and its image; Tazama double counting of 3DS authentications (separate network map).
- **Payment hub:** PH-EE modernisation, rails manifests (PH-EE, Mojaloop), retire the interim Temporal hub (D1–D5).
- **Actions runs:** rails + fraud on a cluster (next run), all profiles at once (run 5), ml + fraud scorer and the
  FAIL path on a cluster, dbt lineage, dev memory halving, scale-to-zero decision after run 5.
- **PDF gaps:** §5.1 edge app, §13 deployment scenarios, rest of the §5.2 QUIC hub; README coverage matrix paths.
- **Later (owner):** migrate the authorisation switch to jPOS.
- **Owner actions:** A5, A6, C4, E1–E3; Codespaces idle timeout 30 min; retry the free arm64 VM.

## 6. Local tooling notes
JDK 25 at `/opt/jdk25` (system java is older: set JAVA_HOME); Maven/Gradle in `/opt`; Go 1.26; psec and pyemv via
pip; Docker may need `nohup dockerd` and mirror.gcr.io for Docker Hub 429s; Fineract test: `apache/fineract:latest`
(1.16.1 tag absent) with Postgres, see `ci/fineract-credit-gate.sh`.
