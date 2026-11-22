# Card-scheme simulator + ISO 8583 adapter + 3-D Secure ACS (services/scheme-sim), built from the vendored moov-io/iso8583.
# Context: repo root. Cross-compiled on the build platform (pure Go, CGO off), one image with both binaries.
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS build
ARG TARGETOS TARGETARCH
WORKDIR /src
COPY vendor/moov-iso8583 vendor/moov-iso8583
COPY services/scheme-sim services/scheme-sim
WORKDIR /src/services/scheme-sim
RUN go mod download && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/ ./cmd/...

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/scheme-sim /out/iso-adapter /out/acs /usr/local/bin/
EXPOSE 8583 8080
ENTRYPOINT ["/usr/local/bin/scheme-sim"]
