# Mifos Payment Hub EE (vendored)

DIFME's payment hub (owner decision 2026-11-21): Mifos Payment Hub EE, with **Fluxnova in place of Zeebe** (Zeebe's
broker is under the Camunda License 1.0, not OSI). Licence: MPL-2.0 (`LICENSE` in each directory). Pinned versions and
commits are in `vendor/VENDORED.json`.

| Directory | Upstream | What it is |
|---|---|---|
| `connector-common` | openMF/ph-ee-connector-common v1.9.1 | Shared DTOs, Camel helpers, error mapping |
| `connector-channel` | openMF/ph-ee-connector-channel v1.9.0 | The channel API: starts payment flows, answers channels |
| `connector-ams-mifos` | openMF/ph-ee-connector-ams-mifos v1.7.0 | Fineract (AMS) connector: block / book / release funds through Fineract's interoperation API |
| `connector-mojaloop` | openMF/ph-ee-connector-mojaloop-java v1.5.2 | Mojaloop (FSPIOP) connector: party lookup, quotes, transfers through the central switch |
| `flows` | openMF/ph-ee-env-labs, `orchestration/feel` at a pinned commit (no release tags) | The BPMN payment flows |

Not committed on purpose: upstream's development TLS keystores (`keystore.jks` in both connectors; they hold private
keys). `ci/vendor-sync.sh` drops any `*.jks`, `*.p12`, `*.pfx`, `*.key`. DIFME runs the connectors with
`server.ssl.enabled=false`; pod-to-pod traffic is encrypted by the Istio ambient mesh.

Building: `deploy/images/mifos-ph-ee/build.sh <ams|channel|mojaloop> <out.jar> [test]` (JDK 21, Gradle 8.14, Maven; the
image build uses the same script). It installs DIFME's replacements to mavenLocal (services/zeebe-on-fluxnova; for
mojaloop also java-ilp-core and services/fspiop-ilp-models), publishes the vendored `connector-common`, then builds the
connector with `deploy/images/mifos-ph-ee/vendored-common.gradle` as init script instead of upstream's SNAPSHOTs from a
third-party Artifactory. Upstream's Gradle 7.3 wrappers are not used (they can't run on Java 21).

**Modernised (D2, 2026-11-23)**: upstream is on Spring Boot 2.6-2.7 / Spring 5 / Camel 3 / Java 13-17 (end of life). DIFME
builds the connectors on **Spring Boot 4.1.1 / Spring 7.0.9 / Camel 4.22.2 / Jakarta EE, Java 21 bytecode, running on
Java 25**. Spring Boot 3.5 / Spring 6.2 (with Camel 4.14 LTS) was done first and works, but its open-source support has
ended and the image gate (Trivy, CRITICAL) fails on spring-webmvc/webflux CVEs fixed only in Spring 7.0.9, so the
connectors went to Spring Boot 4 (the extra source changes were small: two package moves, one ambiguous constructor, one
Jackson 3 setting). Versions are set by the init script, not by editing upstream's build files: the Spring Boot and Camel
Spring Boot BOMs are enforced (Spring's dependency-management plugin told not to put declared versions back), every
`org.apache.camel*` artifact moves to the same Camel, `camel-cxf` -> `camel-cxf-spring-rest`, `javax.servlet-api` /
`validation-api` -> Jakarta, springfox (no Spring 6/7 release) -> springdoc 3, Lombok 1.18.48, Tomcat, Jackson 2/3 and commons-io pinned past the BOM
for CVE fixes, the unused JAX-WS RI and the Gradle plugins upstream lists as runtime dependencies are dropped, Error Prone
(upstream lint; 2.20 predates Java 21's javac) is off. The Prometheus registry now comes from the Spring Boot BOM
(Micrometer 1.17) instead of being pinned to 1.8.1. The source side is in patches (below). Verified 2026-11-23: unit
tests (mojaloop 8/8, channel 1/1, ams 1/1; connector-common's never ran upstream); each connector starts on Java 25 and
serves `/actuator/prometheus`; against a local Fluxnova 3.1.1 the channel API started PayerFundTransfer, the mojaloop
worker took its party-lookup job, and the ams worker fetched and handled a DifmeOnUsTransfer job. Not re-run on the new
stack: the full transfers against Fineract and the Mojaloop switch (below, 2026-11-21).

Local changes to the Mifos source: two patches to connector-mojaloop (`vendor/patches/ph-ee-mojaloop/`, re-applied by
`ci/vendor-sync.sh`), both making PH-EE talk to a real Mojaloop bank rather than to a second tenant of the same hub:
- `0001` quote: the payee's FSP is the one the party lookup found; upstream looked the payee FSP up as a local tenant.
- `0002` quote: the payer no longer re-derives the payee's ILP condition with its own secret (only possible when both
  FSPs share one secret); it checks the packet carries this quote and the condition is a 32-byte SHA-256. The
  fulfilment is checked at commit by the switch (see Known gaps).

- `0004` (D4) the payer checks the payee's ILP fulfilment at commit: condition = base64url(SHA-256(fulfilment)), the
  condition remembered when the transfer is sent. A mismatch, a COMMITTED callback without a fulfilment, or no
  condition on record (connector restarted in between) makes the transfer failed: the flow releases the block instead
  of booking (fail closed). A real Mojaloop switch checks this too; DIFME's dev switch (Testing Toolkit) does not.

Patches to connector-ams-mifos (`vendor/patches/ph-ee-ams-mifos/`), first for logins through Keycloak (component reuse):
- `0001` tenant `authtype: oauth` for Fineract 1.2 (upstream: "TODO implement") = OAuth2 client credentials at
  `ams.local.oauth.token-url`; the tenant's `user`/`password` are the Keycloak client id/secret. Fineract accepts the
  token through its OIDC federation (claim `fineract_user` → Fineract user `ph-ee-ams`, role "Payment hub").
  Verified 2026-11-21: cross-bank transfer through the Mojaloop switch with this login (payer 8,300 → 8,150 INR).

- `0002` no keystore file -> no client certificate (upstream failed at startup without its dev keystore, which is not
  vendored; DIFME calls Fineract over plain HTTP in the mesh).
- `0003` Jakarta / Spring Boot 4 / Camel 4 (D2): `javax.*` -> `jakarta.*`, `endpoints.xml` on Camel 4's CXF JAX-RS
  namespace (`http://camel.apache.org/schema/cxf/jaxrs`), springfox Docket and UI mapping removed (springdoc), Jackson
  2.21 API, `spring.jackson.serialization.WRITE_DATES_AS_TIMESTAMPS` dropped (no such feature in Jackson 3).

On-us routing (D3): `ph-ee-channel/0002` starts the tenant's `onus-transfer` flow when the payee is in the same FSP.
Modernisation patches to the others (D2): `ph-ee-common/0002`, `ph-ee-channel/0001`, `ph-ee-mojaloop/0003`
(`javax.*` -> `jakarta.*`; Spring Boot 4 package moves of `RestTemplateBuilder` and the Lettuce customizer; channel also
drops a springfox import, avoids Spring 7's ambiguous `ResponseEntity(null, status)` and uses Jackson 2.21's
`JsonMappingException.from`), and
`ph-ee-common/0001`: the JWS response filter's condition defaults to off like the other JWS beans (every connector
failed to start without `security.jws.*` set).

The channel's own token check (`rest.authorization`) is not used: in channel 1.9.0 the HTTP controllers call the
Camel routes without the `Authorization` header, so it would refuse every call. Callers are checked in the mesh
instead (Istio `RequestAuthentication` on Keycloak's keys + `AuthorizationPolicy` for realm role `ph-ee-transfer`),
added with the PH-EE deploy manifests.
Everything else is done around the source:
- `services/zeebe-on-fluxnova` replaces the Zeebe client (same API subset, on Fluxnova's REST API); the init script
  swaps it in (`io.camunda:zeebe-client-java` → `dev.difme:zeebe-client-fluxnova`). connector-common declares the Zeebe
  client without using it: dropped there. connector-channel uses Guava without declaring it (it came with the Zeebe
  client's gRPC stack): declared by the init script.
- Flows are converted by `ci/zeebe-bpmn-to-fluxnova.py` (`bill-request-DFSPID.bpmn` is an incomplete upstream draft:
  skipped). DIFME's own flow `processes/ph-ee/DifmeOnUsTransfer-DFSPID.bpmn` is written in the same Zeebe dialect from
  PH-EE task types only.

Licence fixes (owner rule: free and open source only), all in the init script, no source change:
- `org.mifos:interop-ilp-conditions` (needed by connector-mojaloop) is "All Rights Reserved ... use is prohibited
  without permission": replaced by `services/fspiop-ilp-models` (FSPIOP models written from the Mojaloop API
  specification, same package) and the vendored Apache-2.0 `vendor/interledger/java-ilp-core`.
- `org.json:json` before 20231013 is under the JSON License (not OSI): forced to 20240303 (public domain) everywhere.
- Rules are registered again after each project is evaluated: Spring's dependency-management plugin otherwise
  re-applies the declared versions.

Settings the connectors need beyond upstream's defaults (DIFME runtime config):
- `zeebe.broker.contactpoint`: Fluxnova's engine REST URL; `dfspids`: the Fineract tenant (worker topics are named after it).
- `security.jws.enable` / `security.jws.response.enable: false` (connector-common 1.9.1 conditions on them).
- connector-channel: `bpmns.tenants[].flows.payment-transfer` (a missing list is a NullPointerException on every
  transfer) and `redis.*` (its request idempotency store; DIFME's Valkey in the cluster).
- connector-ams-mifos: `ams.local.*` hosts and tenants (no keystore needed since patch `0002`).
- In the cluster: `deploy/platform/rails/ph-ee` (Spring profile `difme` from ConfigMaps; channel API checked at an Istio
  waypoint: Keycloak JWT with realm role `ph-ee-transfer` from client `difme-exchange`).

Upstream quirk noted: the payee-deposit worker completes its job twice (from the Fineract route, then unconditionally);
the second completion is refused as on Zeebe, and the first (real) outcome stands.

Verified 2026-11-21 (local, Fluxnova 3.1.1 + Fineract 1.16.1): a transfer posted to PH-EE's own channel API
(`POST /channel/transfer`) ran DifmeOnUsTransfer on Fluxnova through PH-EE's Fineract connector: local quote → block →
payee deposit → book → success; payer 10,000 → 8,500, payee 0 → 1,500. Over the balance: Fineract's interop quote
refuses (403), the flow ends at "send error to channel", balances unchanged.

Cross-bank, verified 2026-11-21 (local): PH-EE channel API → PayerFundTransfer on Fluxnova → party lookup, quote,
transfer through the Mojaloop switch (Testing Toolkit hub) to the other bank (SDK scheme adapter + mojaloop-simulator)
→ COMMITTED → payer booked in Fineract (8,500 → 8,300 INR). Needed besides the patches: the ILP v1 envelope fix in
java-ilp-core (`vendor/interledger`), `parties` (tenant → Mojaloop fspId) and `switch.*-host` in the runtime config.

Known gaps:
- Fulfilment vs condition at commit: Mojaloop's switch core (central-ledger) checks it; the Testing Toolkit hub does
  not, and PH-EE's payer side does not either. To close with the real switch core or a payer-side check.
- After COMMITTED the other bank's SDK asks the payer for the transfer (`GET /transfers/{id}`), which PH-EE's
  connector does not serve; harmless for the payment, noisy in the switch log.

Infrastructure it expects and the DIFME component used instead: `docs/architecture/component-reuse.md`.
