# Tazama real-time fraud and AML monitoring (ADR-023), one image per service, built from vendor/tazama with DIFME's
# patches (Kafka transport, OpenTelemetry, stdout logs, vendored libraries). Context: repo root.
#   docker build -f deploy/images/tazama/Dockerfile --build-arg SERVICE=tms-service .
#   docker build -f deploy/images/tazama/Dockerfile --build-arg SERVICE=rule-executer --build-arg RULE=rule-902 .
# Node 22 (upstream: 20). Runs as the unprivileged node user; glibc for the Kafka client's native module.
FROM node:22-bookworm AS build
ARG SERVICE=tms-service
ARG RULE=rule-901
# Repository layout: upstream under vendor/tazama, DIFME's own rules under services/fraud-rules.
WORKDIR /src
COPY vendor/tazama/ vendor/tazama/
COPY services/fraud-rules/ services/fraud-rules/
COPY deploy/images/tazama/build.sh /usr/local/bin/tazama-build
WORKDIR /src/vendor/tazama
RUN tazama-build "$SERVICE" "$RULE" && mkdir /out && cp -r "$SERVICE/build" "$SERVICE/node_modules" "$SERVICE/package.json" /out/

# Run stage: Debian slim with security updates applied at build time. The distroless Node image lagged a CRITICAL
# OpenSSL fix (libssl3, CVE-2026-31789, 2026-11-22) that Debian already ships; Trivy blocks such images.
FROM node:22-bookworm-slim
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /opt/yarn* /usr/local/bin/yarn*
WORKDIR /home/app
COPY --from=build /out/ ./
# DIFME defaults: Kafka transport, OpenTelemetry to Alloy, production mode. Hosts, databases and credentials come from
# the manifests (deploy/platform/fraud/tazama).
ENV NODE_ENV=production STARTUP_TYPE=kafka APM_ACTIVE=true APM_URL=http://alloy.observability.svc:4317 \
    MAX_CPU=1 PORT=3000
USER node
CMD ["node", "build/index.js"]
