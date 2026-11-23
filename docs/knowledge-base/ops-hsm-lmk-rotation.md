# Ops runbook: security module LMK rotation drill

**Scope.** This runbook rotates the security module's master keys (ADR-026, `services/hsm`):

- the jPOS **LMK**, which encrypts every DES/TDES key;
- the AES **KBPK**, which wraps every AES and RSA key as a TR-31 block.

**When.** Run it:

- yearly, as a drill;
- when anyone suspects the LMK or KBPK is exposed;
- before a hardware HSM migration rehearsal.

**Rules.** The rotation keeps the module's rules:

- keys exist in clear only inside the module;
- old and new master keys arrive or are created only through attested key release;
- the new LMK is created only through the create-only bootstrap path.

The new LMK is never typed in, never put in a Secret, an env variable or the repo, and never read back by a person.

## How it works

The key release store (OpenBao KV v1 mount `kbs`, read by Trustee's KBS) holds one **generation** of master keys and
key list at a time. KBS resource names are `repository/type/tag`, so the generation is part of the tag:

| Generation | Resources (KBS) / OpenBao paths |
|---|---|
| 1 (first start) | `difme/hsm/lmk`, `difme/hsm/kbpk`, `difme/hsm/keys` |
| n ≥ 2 | `difme/hsm/lmk-gn`, `difme/hsm/kbpk-gn`, `difme/hsm/keys-gn` |

Every generation sits under the existing policies:

- `trustee-kbs` can read `kbs/difme/*`;
- `hsm-bootstrap` can only create `kbs/difme/hsm/*`.

No policy change is needed, and the hsm can never overwrite or read a generation.

The hsm starts with `HSM_KEY_GENERATION=n` and `HSM_ROTATE=true` while generation n does not exist yet. It then runs
`KeyRelease.rotateFrom` in these steps:

1. **Attests to the KBS.** It receives generation n-1's LMK, KBPK and key list as JWE to its TEE key, in memory.
2. **Creates generation n inside the module.**
   - jPOS writes a fresh random LMK to the memory-backed `/run/hsm`; the hsm reads it and deletes the file.
   - A new 32-byte KBPK comes from `SecureRandom`.
3. **Translates the whole key store** (`HsmServer.KeyStore.rotated`).
   - Every DES key goes through jPOS `translateKeyFromOldLMK`. jPOS's software module declares this but does not
     implement it; `DifmeSecurityModule` implements it. The key keeps its type, length and **check value**.
   - Every AES/RSA TR-31 block is unwrapped under the old KBPK and re-wrapped under the new one with the same header.
   - Certificates and public keys are copied.
   - A key that fails its DES parity under the old LMK, or a block whose MAC fails under the old KBPK, stops the
     rotation and stores nothing.
4. **Stores generation n through the create-only role** `hsm-bootstrap` (`lmk-gn`, `kbpk-gn`, `keys-gn`).
5. **Erases the old LMK and KBPK** from memory (`eraseOldLMK`) and serves on generation n.

Generation n-1 stays untouched in the store, so rollback is to set `HSM_KEY_GENERATION=n-1`.

**Guard.** A missing generation n without `HSM_ROTATE=true` is refused at start: the hsm never bootstraps an empty key
store over a later generation.

## Drill steps

1. **Before.** Record the check values. The hsm prints `hsm: key <label> <type> check value <KCV>` for every DES key
   at start; save them from the running pod's log:

   ```sh
   kubectl -n rails logs deploy/hsm | grep 'check value' > /tmp/kcv-before.txt
   ```

   Run the card-security smoke checks, for example `ci/card-issuer-live.sh` against a test cluster. Expect CVV2,
   PIN, ARQC and CAVV to pass.
2. **Rotate.** Bump the generation and turn on rotation for one start. In Git (`deploy/platform/rails/card-security`),
   add to the hsm container:

   ```yaml
   - { name: HSM_KEY_GENERATION, value: "2" }   # the next generation
   - { name: HSM_ROTATE, value: "true" }
   ```

   Argo CD rolls the pod. Expect in the log:

   ```
   hsm: LMK rotated to generation 2 (N DES keys translated, M key blocks re-wrapped); old keys erased from memory
   ```
3. **Verify.** Compare the check values with step 1. They must be **identical**, because the same keys now sit under a
   new LMK:

   ```sh
   kubectl -n rails logs deploy/hsm | grep 'check value' | diff /tmp/kcv-before.txt -
   ```

   Run the same smoke checks again; the results must not change.
4. **Settle.** Remove `HSM_ROTATE` from the manifest and keep `HSM_KEY_GENERATION=2`. Later restarts load generation 2
   by attested release like any other start. If a restart finds generation 2 incomplete, it refuses and does not
   re-rotate.
5. **Retire the old generation.** After the rollback window (one week for the drill), an OpenBao admin, not the hsm
   role, deletes `kbs/difme/hsm/{lmk,kbpk,keys}` (or `-g<n-1>`). This is the only step that needs admin rights. It
   uses the break-glass procedure of `deploy/platform/security/openbao-config` and is logged by OpenBao's audit device.

## Rollback

- **Before step 5:** set `HSM_KEY_GENERATION` back to n-1 and remove `HSM_ROTATE`. Generation n stays stored and
  unused.
- **After step 5:** there is no rollback. That is the point of retiring a suspected-exposed LMK.

## What the test covers

`services/hsm/src/test/java/dev/difme/hsm/LmkRotationTest.java` runs `KeyRelease.rotate` over a key store with every
key family: CVK, ZPK, PVK, MK-AC, TAK, AES M7/P0 and an RSA signing key. After rotation, every function gives the
same result against the independent references:

- psec: CVV2 523, PVV 0582, retail MAC, ISO 4 → ISO 0;
- pyemv: Visa CVN 10 ARQC/ARPC;
- NIST SP 800-38B: CMAC;
- the RSA key still signs for its certificate.

The test also checks:

- check values are unchanged, and every stored value and the LMK/KBPK are new;
- the new generation reloads as after a restart;
- keys under the old LMK fail under the new one, and the old LMK and KBPK are erased;
- a tampered key block, the wrong old LMK or the wrong old KBPK stop the rotation.

**Not covered by an automated test:** the KBS and OpenBao round trip of `rotateFrom`, which needs a live Trustee. It
runs on the first cluster drill, the same path as the first-start bootstrap.

## Hardware HSM later

A certified HSM behind jPOS's `SMAdapter` does the same: its own LMK migration command implements
`translateKeyFromOldLMK`. Only the generation and attested-release wrapping above is DIFME-specific.
