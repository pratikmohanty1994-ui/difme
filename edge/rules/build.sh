#!/usr/bin/env bash
# Builds the sandboxed rule components (ADR-016) and copies them where edge/core embeds them.
# Needs the wasm32-wasip2 target: rustup target add wasm32-wasip2. Uses edge/target (one target dir).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
export CARGO_TARGET_DIR="$here/../target"
cargo build -j "${JOBS:-2}" --release --target wasm32-wasip2 --manifest-path "$here/offline-limit/Cargo.toml"
out="$here/../core/rules/offline_limit.wasm"
cp "$CARGO_TARGET_DIR/wasm32-wasip2/release/difme_rule_offline_limit.wasm" "$out"
# The core pins the component by Blake3 (integrity gate before compiling) and reports its SHA-256 to the verifier
# (binary_hash). Write the pin next to the component; edge/core embeds both.
[ -f "$out.b3" ] || echo pending > "$out.b3"
cargo run -q -j "${JOBS:-2}" --manifest-path "$here/../Cargo.toml" -p difme-edge-core --bin edge-hash -- "$out" > "$out.b3"
echo "built $out ($(wc -c < "$out") bytes)"
echo "blake3 $(cat "$out.b3")"
echo "sha256 $(sha256sum "$out" | cut -d' ' -f1)  <- add to VERIFIER_APPROVED_WASM"
