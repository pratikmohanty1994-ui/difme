# DIFME card issuer (services/card-issuer, ADR-024/025). Context: repo root. Pure Go, cross-compiled on the build platform.
FROM --platform=$BUILDPLATFORM golang:1.27-bookworm AS build
ARG TARGETOS TARGETARCH
WORKDIR /src/services/card-issuer
COPY services/card-issuer/go.mod services/card-issuer/go.sum ./
RUN go mod download
COPY services/card-issuer .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/card-issuer ./cmd/card-issuer

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/card-issuer /usr/local/bin/
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/card-issuer"]
