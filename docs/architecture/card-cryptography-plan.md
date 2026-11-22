# Card cryptography plan (ADR-026)

Every card-related cryptographic function DIFME needs as issuer, network (scheme-sim / TSP) and acquirer, all inside
`services/hsm`. Keys exist in clear only inside the module (LMK released by attestation, ADR-026). Callers hold keys
encrypted under the LMK and reach the module only through jPOS's `SMAdapter` interface, so a certified payment HSM
replaces the software module later without caller changes.

**Rule for every row:** a function is "done" only when (1) it is a `SecurityModule` method, (2) its tests match an
independent reference (published vector where one exists, else **psec** or **pyemv**, both MIT), including negative
cases, and (3) the caller named in the row uses it in place of any stopgap.

**Source of each function:** *jPOS* = already in jPOS 3.0.2 `JCESecurityModule` (checked in source 2026-11-22);
*ext* = not in jPOS's software module, implemented by DIFME in `DifmeSecurityModule extends JCESecurityModule` with the
JDK's JCE (DES/3DES/AES/RSA/HMAC), behind the same interface style. Gaps found in jPOS's software module: no AES
at all (so no ISO 9564 format 4 PIN blocks, AES DUKPT, AES key blocks or AES session keys), no IBM 3624 PIN offset, no
TR-31 key blocks, no RSA signing for chip personalisation (recovery/verification only).

## Phase 0 — key management (everything else depends on it)

| Function | Source | Reference test | Caller |
|---|---|---|---|
| LMK from attested key release (file on tmpfs in the TEE), LMK rotation (`translateKeyFromOldLMK`) | jPOS | reload/rotate round trip | hsm startup |
| Key ceremony: key from clear components, key check value (KCV) | jPOS | published KCVs | ops runbook |
| Generate keys by type: CVK, PVK, ZPK, TPK/TMK, ZMK, BDK, IMK-AC/SMI/SMC/CVC3/DCVV, MAC, HMAC | jPOS | KCV + use in later phases | card-issuer, scheme-sim |
| Export/import under a ZMK (key exchange with networks, acquirers) | jPOS | round trip, KCV | ops |
| TR-31 key blocks (version B and D/AES), export/import | ext | psec `tr31.wrap/unwrap` | ops, ATM/POS key loading |
| Audit log of every call (function, key KCV, caller identity; never data or keys) | ext | log assertions | all |

## Phase 1 — card-not-present (today's flows)

| Function | Source | Reference test | Caller |
|---|---|---|---|
| CVV2 / CVC2 generate + verify | jPOS | **done**: Visa vector 561 + psec | card-issuer (issue, authorise) replacing the keyed-hash CVV |
| Magstripe CVV, iCVV (chip track 2 equivalent, service code 999) | jPOS | **done** (CVV); psec for iCVV | card personalisation, scheme-sim |
| Visa CAVV (3-D Secure, CVV method) | jPOS | **done**: psec | 3DS ACS (later), card-issuer |
| Network token cryptogram (TAVV, CAVV format) replacing the HMAC cryptogram | jPOS | psec + existing scheme-sim token tests | scheme-sim TSP (ADR-024) |
| Mastercard AAV/UCAF (SPA2, HMAC-SHA-256) | ext | spec examples | card-issuer |
| Dynamic CVV2 for virtual cards (time/counter-based, DIFME-defined) | ext | own vectors + negative cases | card-issuer, app |

## Phase 2 — PIN

| Function | Source | Reference test | Caller |
|---|---|---|---|
| PIN blocks ISO 9564 formats 0, 1, 3 (3DES) | jPOS | psec `pinblock` encode/decode | all PIN flows |
| PIN block ISO 9564 format 4 (AES) | ext | psec `encipher/decipher_pinblock_iso_4` | app PIN set, newer terminals |
| PIN translation ZPK→ZPK, TPK→ZPK, format change (`translatePIN`) | jPOS | psec round trip | scheme-sim (network), acquirer |
| Visa PVV generate + verify (`calculatePVV`/`verifyPVV`) | jPOS | psec `generate_visa_pvv` | card-issuer online PIN |
| IBM 3624 PIN + offset generate + verify | ext | psec `generate_ibm3624_pin/offset` | card-issuer (alternative method) |
| PIN generation, PIN set/change from the app (PIN under a session key from the app, ISO 4), weak-PIN exclusion | jPOS + ext | psec | card-issuer, app |
| PIN mailer / app reveal (PIN encrypted to the app's key, never clear outside the module) | ext | round trip | card-issuer |
| DUKPT 3DES (ANSI X9.24-1) PIN decryption from terminals | jPOS | X9.24-1 published vectors | acquirer / POS |
| DUKPT AES (X9.24-3-2017) | ext | X9.24-3 published vectors | acquirer / newer POS |

## Phase 3 — chip (EMV contact and contactless)

| Function | Source | Reference test | Caller |
|---|---|---|---|
| ICC master key derivation option A/B (`deriveICCMasterKey`) | jPOS | pyemv `kd.derive_icc_mk_a/b` | card-issuer |
| Session keys: common session key (EMV CSK), EMV2000 tree, Visa VSDC/UKIS, M/Chip | jPOS | pyemv `kd.derive_common_sk`, `derive_emv2000_tree_sk` | card-issuer |
| ARQC verify + ARPC generate, method 1 and 2 (`verifyARQCGenerateARPC`) | jPOS | pyemv `cvn`: Visa CVN 10/18, Mastercard CVN 16/17/20/21 | card-issuer authorisation |
| AES cryptograms (Visa CVN 22 and later AES chip profiles) | ext | pyemv `cvn.VisaCVN22` | card-issuer |
| TC/AAC verification at clearing | jPOS | pyemv `ac.generate_ac` | card-issuer clearing |
| Contactless: Mastercard CVC3, Visa dCVV (MSD) | jPOS | pyemv `cvv.generate_cvc3`; Visa vectors | card-issuer |
| Mobile wallet / tokenised chip (DSRP, cloud cryptograms) on network tokens | jPOS + ext | pyemv `cvn` | scheme-sim TSP |
| Offline data authentication verification SDA/DDA/CDA | jPOS | EMV test certificates | scheme-sim / acquirer tests |

## Phase 4 — issuer scripts and card personalisation

| Function | Source | Reference test | Caller |
|---|---|---|---|
| Secure-messaging session keys (integrity, confidentiality) | jPOS | pyemv `kd.derive_visa_sm_sk`, `derive_common_sk` | card-issuer |
| Script MAC (ISO 9797-1 alg 3), command data encryption | jPOS | pyemv `sm.generate_command_mac`, `encrypt_command_data` | card-issuer |
| Offline PIN change / unblock script (PIN encrypted for the card, `encryptSecureMessagingPIN`) | jPOS | pyemv `sm.format_vis_pin_block`, `format_iso9564_2_pin_block` | card-issuer |
| Block/unblock application, update limits (PUT DATA) scripts | jPOS | pyemv MAC vectors | card-issuer |
| Data preparation: ICC keys (IMK → MK per card), iCVV, issuer RSA key pair, ICC RSA key pair + certificate signed by the issuer key | jPOS (derivation) + ext (RSA sign) | EMV Book 2 certificate format, round trip with jPOS's recovery | card-issuer (perso file for a card bureau) |

## Phase 5 — message security and terminals

| Function | Source | Reference test | Caller |
|---|---|---|---|
| ISO 8583 MAC (ISO 9797-1 alg 1 and 3, CMAC AES) generate + verify | jPOS (DES), ext (CMAC) | pyemv `mac.mac_iso9797_3`; NIST CMAC vectors | scheme-sim links |
| Terminal key loading (TMK → TPK/TAK), ATM remote key load | jPOS + ext (TR-31) | psec tr31 | acquirer / ATM driver |
| Data encryption for track/PAN (`encryptData`/`decryptData`), P2PE on terminals | jPOS | round trip | acquirer |

## Delivery order and size

1. **Service shell:** gRPC/HTTP with mTLS over the mesh, LMK from attestation, audit log, Phase 0 key management,
   then card-issuer and scheme-sim switched to the Phase 1 functions (stopgaps deleted). *Medium.*
2. **Phase 1 remainder** (TAVV, AAV, dynamic CVV2). *Small.*
3. **Phase 2 PIN** (3DES first, then format 4 / AES DUKPT ext). *Medium.*
4. **Phase 3 chip**, with card-present flows in scheme-sim (field 55 parsing via moov-iso8583 or jPOS TLV). *Large.*
5. **Phase 4 scripts and personalisation.** *Medium.*
6. **Phase 5 terminals,** together with an acquirer/POS simulator. *Medium.*

Extensions (*ext*) are written only where jPOS lacks the function and are kept upstreamable (AGPL-3.0, same
interfaces), so contributing them to jPOS remains an option. The software module is for development and the
attested-TEE deployment; scheme certification (PCI PIN, PCI HSM) still requires a certified HSM behind the same
`SMAdapter` interface (ADR-026).
