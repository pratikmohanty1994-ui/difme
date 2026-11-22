// SPDX-License-Identifier: Apache-2.0

// DIFME patch (ADR-023): the Elasticsearch log stream (pino-elasticsearch + ECS format) is removed. DIFME collects
// container stdout with Alloy into Loki, so logs are written as JSON to stdout only.

export type LogCallback = (...args: unknown[]) => unknown;
