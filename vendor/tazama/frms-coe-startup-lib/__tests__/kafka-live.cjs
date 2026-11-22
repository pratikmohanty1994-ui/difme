// SPDX-License-Identifier: Apache-2.0
// DIFME live test of the Kafka transport (ADR-023) against a real broker: node __tests__/kafka-live.cjs
// (KAFKA=host:port, default localhost:9092; build first with `npx tsc`). Each role runs in its own process, as each
// Tazama processor does, because the startup config is read from the environment once per process.
//  1. rule:  consumes sub-rule-901@1.0.0 (a subject Kafka can't use as-is), answers on pub-rule-901@1.0.0
//  2. sink:  consumes pub-rule-901@1.0.0 and reports what arrived
//  3. two rule instances in one group share the load (NATS queue-group behaviour)
//  4. service channel: both instances receive every message (broadcast)
//  5. addConsumers: a subject added at runtime is consumed
'use strict';
const { fork } = require('node:child_process');
const assert = require('node:assert');
const KAFKA = process.env.KAFKA ?? 'localhost:9092';
const RUN = Date.now().toString(36);
const N = 20;

function role(name) {
  const { StartupFactory } = require('../lib');
  const send = (m) => process.send(m);
  const logger = { log() {}, warn() {}, error: (m) => send({ err: String(m) }), debug() {}, trace() {}, fatal() {} };
  (async () => {
    const server = new StartupFactory();
    if (name.startsWith('rule')) {
      await server.init(async (msg) => {
        send({ got: msg.transactionID, by: name });
        await server.handleResponse({ ...msg, TxTp: 'pacs.002.001.12', alreadySent: name });
      }, logger);
      await server.initServiceChannel((bytes) => send({ svc: Buffer.from(bytes).toString(), by: name }), undefined, logger);
      process.on('message', async (m) => {
        if (m.add) send({ added: await server.addConsumers([m.add], async (msg) => send({ late: msg.transactionID, by: name })) });
      });
    } else if (name === 'sink') {
      await server.init(async (msg) => send({ result: msg.transactionID, from: msg.alreadySent, TxTp: msg.TxTp }), logger);
    } else if (name === 'source') {
      await server.initProducer(logger);
      await server.initServiceChannelProducer(logger);
      process.on('message', async (m) => {
        if (m.tx) await server.handleResponse({ transactionID: m.tx, TxTp: 'pacs.008.001.10', TenantId: 'DEFAULT' }, [m.subject]);
        if (m.svc) await server.publishServiceChannel(Buffer.from(m.svc));
        send({ sent: m.tx ?? m.svc });
      });
    }
    send({ ready: name });
  })().catch((e) => { send({ err: String(e && e.stack || e) }); process.exit(1); });
}

if (process.argv[2]) { role(process.argv[2]); return; }

const env = (fn, extra) => ({ ...process.env, NODE_ENV: 'test', STARTUP_TYPE: 'kafka', SERVER_URL: KAFKA, FUNCTION_NAME: fn, ...extra });
const SUB = `sub-rule-901@1.0.0-${RUN}`, PUB = `pub-rule-901@1.0.0-${RUN}`, SVC = `svc-${RUN}`, LATE = `late-${RUN}@x`;
const events = [];
const kids = {};
function start(name, fn, extra) {
  const c = fork(__filename, [name], { env: env(fn, extra), stdio: ['ignore', 'inherit', 'inherit', 'ipc'] });
  c.on("message", (m) => { events.push(m); if (m.err) console.error(`[${name}]`, m.err); if (process.env.DEBUG_LIVE) console.log(name, JSON.stringify(m)); });
  kids[name] = c;
}
const until = async (pred, ms, what) => {
  const t0 = Date.now();
  while (!pred()) { if (Date.now() - t0 > ms) throw new Error(`timeout waiting for ${what}`); await new Promise((r) => setTimeout(r, 200)); }
};
const count = (f) => events.filter(f).length;

(async () => {
  start('rule-a', `rule-901-${RUN}`, { CONSUMER_STREAM: SUB, PRODUCER_STREAM: PUB, SERVICE_CHANNEL_CONSUMER: SVC });
  start('rule-b', `rule-901-${RUN}`, { CONSUMER_STREAM: SUB, PRODUCER_STREAM: PUB, SERVICE_CHANNEL_CONSUMER: SVC });
  start('sink', `sink-${RUN}`, { CONSUMER_STREAM: PUB });
  start('source', `source-${RUN}`, { SERVICE_CHANNEL_PRODUCER: SVC });
  await until(() => count((e) => e.ready) === 4, 60000, 'all roles ready');
  await new Promise((r) => setTimeout(r, 8000)); // consumer-group rebalance settles (two members)

  for (let i = 0; i < N; i++) kids.source.send({ tx: `tx-${i}`, subject: SUB });
  await until(() => count((e) => e.result) === N, 60000, `${N} results at the sink`);
  const results = events.filter((e) => e.result);
  assert.deepStrictEqual(new Set(results.map((e) => e.result)).size, N, 'every transaction arrives exactly once');
  assert.ok(results.every((e) => e.TxTp === 'pacs.002.001.12'), 'responses decoded as FRMSMessage');
  const a = count((e) => e.got && e.by === 'rule-a'), b = count((e) => e.got && e.by === 'rule-b');
  assert.strictEqual(a + b, N, 'each transaction handled by exactly one instance');
  console.log(`1-3 ok: ${N} transactions through '${SUB}' -> '${PUB}'; shared by the group: rule-a ${a}, rule-b ${b}`);

  kids.source.send({ svc: 'reload-network-map' });
  await until(() => count((e) => e.svc === 'reload-network-map') === 2, 30000, 'service channel on both instances');
  console.log('4 ok: service-channel message reached both instances (broadcast)');

  kids['rule-a'].send({ add: LATE });
  await until(() => count((e) => e.added === true) === 1, 30000, 'addConsumers');
  await new Promise((r) => setTimeout(r, 6000));
  kids.source.send({ tx: 'late-1', subject: LATE });
  await until(() => count((e) => e.late === 'late-1') === 1, 30000, 'message on the subject added at runtime');
  console.log(`5 ok: subject '${LATE}' added at runtime is consumed`);

  const errors = events.filter((e) => e.err);
  assert.strictEqual(errors.length, 0, `no handler errors (${errors.map((e) => e.err).join('; ')})`);
  console.log('PASS');
  for (const c of Object.values(kids)) c.kill();
  process.exit(0);
})().catch((e) => { console.error('FAIL:', e.message); for (const c of Object.values(kids)) c.kill(); process.exit(1); });
