# Mojaloop (vendored)

The settlement leg's central switch and the other bank (owner decision 2026-11-21). Licence: Apache-2.0 (each
directory's `LICENSE.md`). Pinned versions and commits: `vendor/VENDORED.json`.

| Directory | Upstream | Role in DIFME |
|---|---|---|
| `testing-toolkit` | mojaloop/ml-testing-toolkit v18.19.2 | The central switch, in hub mode: routes FSPIOP requests and callbacks between participants by rules (party lookup by identifier range, quotes/transfers by `FSPIOP-Destination`) |
| `sdk-scheme-adapter` | mojaloop/sdk-scheme-adapter v24.20.0 | The other bank's connection to the switch (FSPIOP in/out); only `modules/api-svc` is installed |
| `simulator` | mojaloop/mojaloop-simulator v15.5.5 | The other bank's core banking behind the scheme adapter (parties, quotes, transfers) |

DIFME connects through Mifos PH-EE's own Mojaloop connector (`vendor/mifos-ph-ee/connector-mojaloop`).

Not committed: upstream private keys and test key stores (`ci/vendor-sync.sh` drops them; `ci/find-private-keys.py`).

Local changes:
- `simulator/package-lock.json` regenerated (`npm install --package-lock-only`): upstream's lock at v15.5.5 is out of
  sync with its package.json (missing argparse 1.0.10, sprintf-js 1.0.3), so `npm ci` refuses it.

- Critical CVEs with fixed releases (Trivy gate, images run 2026-11-24): `testing-toolkit` handlebars 4.7.10, mongoose
  9.9.2, overrides convict 6.2.5, fast-xml-parser 4.5.4, protobufjs 7.5.5, proxy-addr 2.0.8 (lock regenerated with
  `npm install --package-lock-only --ignore-scripts`); `sdk-scheme-adapter` resolution proxy-addr 2.0.8 (`yarn install
  --mode=update-lockfile`). Re-apply after a vendor sync until upstream ships them; images re-scanned locally: 0 critical.

- Keys only in the emulated TEE (patch `vendor/patches/ml-sdk-adapter/0001`): with `HSM_URL` set, the scheme adapter's
  ILP fulfilments are HMACed by DIFME's security module with key `ilp-<ILP_INSTITUTION>` (`api-svc/src/lib/HsmIlp.js`);
  packets are still built by sdk-standard-components with a public placeholder secret whose fulfilment is always
  replaced; the inbound fulfilment calls became async (`await`). Verified byte-identical to upstream's construction
  (key = ASCII of base64(secret), data = ASCII of the base64url packet). Without `HSM_URL`: upstream's `ILP_SECRET`.

Installing: `npm ci --omit=dev --ignore-scripts` (testing-toolkit, simulator); the scheme adapter with its bundled Yarn
(`node .yarn/releases/yarn-4.18.0.cjs workspaces focus @mojaloop/sdk-scheme-adapter-api-svc --production`; corepack
would download Yarn from a host the session blocks).

Images: `deploy/images/mojaloop/Dockerfile` (one per directory, `COMPONENT=`; Node 22 on Debian slim); manifests:
`deploy/platform/rails/mojaloop-switch` (Argo app `mojaloop-switch`, rails profile).

Infrastructure it expects and the DIFME component used instead: `docs/architecture/component-reuse.md`.
