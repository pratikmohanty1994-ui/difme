# Mojaloop settlement leg (owner 2026-11-21), built from vendor/mojaloop (Apache-2.0), one image per component:
#   testing-toolkit     the central switch (Testing Toolkit in hub mode; routing from deploy/platform/rails/mojaloop-switch)
#   sdk-scheme-adapter  the other bank's connection to the switch (only modules/api-svc)
#   simulator           the other bank's core banking behind the scheme adapter
# Context: repo root.  docker build -f deploy/images/mojaloop/Dockerfile --build-arg COMPONENT=simulator .
# Node 22 on Debian (upstream: Alpine). Runtime: Debian slim with security updates applied at build time, npm/yarn
# removed, unprivileged node user (as deploy/images/tazama).
FROM node:22-bookworm AS build
ARG COMPONENT=testing-toolkit
WORKDIR /src
COPY vendor/mojaloop/${COMPONENT}/ app/
WORKDIR /src/app
# Dependency install scripts are off except where a native module needs them: sqlite3 (simulator; the in-memory model
# database) and the scheme adapter's Kafka client (node-rdkafka builds its bundled librdkafka; the Kafka handlers stay off).
RUN set -eux; case "$COMPONENT" in \
      testing-toolkit) npm ci --omit=dev --ignore-scripts; mkdir -p uploads ;; \
      simulator) npm ci --omit=dev --ignore-scripts; npm rebuild sqlite3 ;; \
      sdk-scheme-adapter) \
        Y="node .yarn/releases/yarn-4.18.0.cjs"; \
        $Y workspaces focus @mojaloop/sdk-scheme-adapter-api-svc @mojaloop/sdk-scheme-adapter-private-shared-lib; \
        $Y workspace @mojaloop/sdk-scheme-adapter-private-shared-lib run build; \
        $Y workspaces focus @mojaloop/sdk-scheme-adapter-api-svc --production; \
        rm -rf .yarn/cache .yarn/install-state.gz ;; \
      *) echo "unknown COMPONENT $COMPONENT"; exit 1 ;; \
    esac; \
    rm -rf test docs .git* || true   # LICENSE.md stays

FROM node:22-bookworm-slim
ARG COMPONENT=testing-toolkit
RUN apt-get update && apt-get upgrade -y --no-install-recommends && apt-get install -y --no-install-recommends libsasl2-2 \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /opt/yarn* /usr/local/bin/yarn*
WORKDIR /opt/app
COPY --from=build --chown=node:node /src/app/ ./
# One entry point for all three (the manifests set the working directory where it differs).
RUN printf '#!/bin/sh\ncase "%s" in\n  sdk-scheme-adapter) cd /opt/app/modules/api-svc && exec node src/index.js ;;\n  *) exec node src/index.js ;;\nesac\n' "$COMPONENT" > /usr/local/bin/start \
    && chmod 755 /usr/local/bin/start
ENV NODE_ENV=production
USER node
CMD ["/usr/local/bin/start"]
