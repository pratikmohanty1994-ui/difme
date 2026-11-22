# Juspay Hyperswitch router (PSP simulator), built from the vendored source (owner 2026-11-21: vendor/hyperswitch,
# v1.129.0). Context: repo root. Default features = v1 + dummy_connector (the simulated processor), without the
# `release` set (cloud KMS clients, encryption service, S3): DIFME needs none of them and they double the build.
# Native binary: built per arch on a matching runner (images.yml), never under emulation.
FROM rust:1.97-trixie AS build
RUN apt-get update && apt-get install -y --no-install-recommends libpq-dev libssl-dev pkg-config protobuf-compiler libprotobuf-dev lld \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY vendor/hyperswitch /src
# release-fast (upstream's profile: optimised, no LTO) without debug info, stripped: half the build time and memory
# of full LTO, which a simulator doesn't need.
# arm64: the unoptimised router's code exceeds the ±128 MB reach of a direct branch, and GNU ld then fails with
# "relocation truncated to fit: R_AARCH64_CALL26" (2026-11-22). LLD inserts range-extension thunks. amd64 keeps GNU ld.
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C link-arg=-fuse-ld=lld"
ENV CARGO_INCREMENTAL=0 CARGO_NET_RETRY=10 CARGO_PROFILE_RELEASE_FAST_DEBUG=0 CARGO_PROFILE_RELEASE_FAST_STRIP=symbols
# Memory (measured 2026-11-22, docs/knowledge-base/build.md): rustc peaks per crate at diesel 11.4 GB, router 13.6 GB
# (opt-level 0) and hyperswitch_connectors 8.1 GB. Building one crate at a time (-j 1) keeps those peaks from
# overlapping, so the build fits GitHub's 16 GB runners; images.yml adds a 24 GB swapfile only as a backstop. The router
# crate is built unoptimised (every other crate is optimised): at opt-level 1 or above it needs more than 16 GB.
# Features stay upstream's defaults: Hyperswitch does not compile with payouts, frm or kv_store turned off.
RUN cargo build --locked --profile release-fast --bin router -j 1 --config 'profile.release-fast.package.router.opt-level=0' \
    && cp target/release-fast/router /router

FROM debian:trixie-slim
# postgresql-client + migrate.sh: the same image runs the schema migrations as an init container.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata libpq5 postgresql-client \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home app
COPY --from=build /router /local/bin/router
COPY vendor/hyperswitch/config/docker_compose.toml /local/config/docker_compose.toml
COPY vendor/hyperswitch/config/superposition_seed.toml /local/config/superposition_seed.toml
COPY vendor/hyperswitch/migrations /migrations
COPY deploy/images/hyperswitch/migrate.sh /local/bin/migrate.sh
ENV TZ=Etc/UTC CONFIG_DIR=/local/config RUST_MIN_STACK=6291456
USER 10001
WORKDIR /local
EXPOSE 8080
# Upstream config file, with DIFME's hosts and secrets layered on as ROUTER__* environment overrides (see the manifest).
ENTRYPOINT ["/local/bin/router", "-f", "/local/config/docker_compose.toml"]
