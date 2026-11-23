# DIFME QUIC hub (PDF §5.2) and the scenario D local QUIC relay (services/hub/quic-relay), one image, two binaries:
# the relay runs with `command: [/usr/local/bin/quic-relay]`. Context: repo root (the build reads api/proto). Cross-compiled on the build platform for
# each target arch (no QEMU emulation of rustc), then copied into a distroless glibc image: ~4 MiB binary, ~6 MiB RSS.
FROM --platform=$BUILDPLATFORM rust:1.97-bookworm AS build
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      arm64) apt-get update -qq && apt-get install -y -qq gcc-aarch64-linux-gnu >/dev/null && rustup target add aarch64-unknown-linux-gnu ;; \
      amd64) rustup target add x86_64-unknown-linux-gnu ;; esac
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
WORKDIR /src
COPY api/proto /src/api/proto
COPY services/hub /src/services/hub
WORKDIR /src/services/hub
RUN T=$([ "$TARGETARCH" = arm64 ] && echo aarch64-unknown-linux-gnu || echo x86_64-unknown-linux-gnu) \
    && cargo build --release --locked --target "$T" \
    && cp "target/$T/release/difme-quinn-hub" /hub && cp "target/$T/release/difme-quic-relay" /relay

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /hub /usr/local/bin/quinn-hub
COPY --from=build /relay /usr/local/bin/quic-relay
EXPOSE 4443/udp 9100 9101
ENTRYPOINT ["/usr/local/bin/quinn-hub"]
