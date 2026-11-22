// SPDX-License-Identifier: Apache-2.0
// Rule D01 against a real local HTTP server standing in for services/fraud-scorer, with the same banding function
// Tazama's rule-executer uses.
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { RuleConfig, RuleRequest, RuleResult } from '@tazama-lf/frms-coe-lib/lib/interfaces';
import { determineOutcome } from '@tazama-lf/frms-coe-lib/lib/tests/mocks/mock-rule-executor';
import { handleTransaction } from '../src';

const ruleConfig = {
  id: 'D01@1.0.0',
  cfg: '1.0.0',
  tenantId: 'DEFAULT',
  desc: 'ONNX fraud model',
  config: {
    // Generous: image builds run these tests under arm64 emulation, where a first call took ~300 ms (2026-11-22).
    parameters: { timeoutMs: 2000 },
    exitConditions: [{ subRuleRef: '.x00', reason: 'Incoming transaction is unsuccessful' }],
    bands: [
      { subRuleRef: '.01', upperLimit: 150, reason: 'Model: low fraud probability' },
      { subRuleRef: '.02', lowerLimit: 150, upperLimit: 500, reason: 'Model: review' },
      { subRuleRef: '.03', lowerLimit: 500, reason: 'Model: high fraud probability' },
    ],
  },
} as unknown as RuleConfig;

const logger = { trace: jest.fn(), log: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(), fatal: jest.fn() };

const request = (txSts = 'ACCC', amt = 1234.56, dbtrAcctId: string | null = 'acct-1'): RuleRequest =>
  ({
    transaction: {
      TxTp: 'pacs.002.001.12',
      TenantId: 'DEFAULT',
      FIToFIPmtSts: {
        GrpHdr: { MsgId: 'msg-1', CreDtTm: new Date().toISOString() },
        TxInfAndSts: { OrgnlInstrId: 'i', OrgnlEndToEndId: 'e', TxSts: txSts },
      },
    },
    networkMap: {},
    DataCache: { dbtrAcctId: dbtrAcctId ?? undefined, instdAmt: { amt, ccy: 'INR' } },
  }) as unknown as RuleRequest;

const result = (): RuleResult => ({ id: 'D01@1.0.0', cfg: '1.0.0', subRuleRef: '.err', tenantId: 'DEFAULT' }) as RuleResult;

let server: Server;
let reply: (body: Record<string, unknown>) => { status: number; body: unknown; delayMs?: number };
let received: Record<string, unknown>[] = [];

beforeAll(async () => {
  server = createServer((req, res) => {
    let data = '';
    req.on('data', (c) => (data += c));
    req.on('end', () => {
      const body = JSON.parse(data) as Record<string, unknown>;
      received.push({ path: req.url, ...body });
      const r = reply(body);
      setTimeout(() => {
        res.writeHead(r.status, { 'content-type': 'application/json' });
        res.end(JSON.stringify(r.body));
      }, r.delayMs ?? 0);
    });
  });
  await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok));
  process.env.FRAUD_SCORER_URL = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => server.close());
beforeEach(() => (received = []));

const scored = (probability: number) => () => ({
  status: 200,
  body: { probability, riskScore: Math.round((1 - probability) * 1000), decision: 'X', model: 'fraud-gbt-0.1.0', missing: ['device_*'] },
});

const run = async (req = request(), cfg: RuleConfig = ruleConfig) => handleTransaction(req, determineOutcome, result(), logger as never, cfg);
const withTimeout = (timeoutMs: number): RuleConfig =>
  ({ ...ruleConfig, config: { ...ruleConfig.config, parameters: { timeoutMs } } }) as unknown as RuleConfig;

test.each([
  [0.05, '.01'],
  [0.149, '.01'],
  [0.15, '.02'],
  [0.49, '.02'],
  [0.5, '.03'],
  [0.97, '.03'],
])('probability %p falls in band %p', async (p, band) => {
  reply = scored(p);
  const r = await run();
  expect(r.subRuleRef).toBe(band);
  expect(r.indpdntVarbl).toBe(Math.round(p * 1000));
});

test('sends the debtor account, the amount in minor units and the unknown-device id', async () => {
  reply = scored(0.1);
  await run(request('ACCC', 1234.56));
  expect(received).toEqual([{ path: '/v1/score/order', accountId: 'acct-1', deviceId: 'unknown', amountMinor: 123456 }]);
});

test('an unsuccessful payment exits with .x00 and never calls the scorer', async () => {
  reply = scored(0.9);
  const r = await run(request('RJCT'));
  expect(r.subRuleRef).toBe('.x00');
  expect(received).toHaveLength(0);
});

test('a slow scorer gives .err (no weight), not a hang', async () => {
  reply = () => ({ ...scored(0.9)(), delayMs: 3000 });
  const t0 = Date.now();
  const r = await run(request(), withTimeout(200));
  expect(r.subRuleRef).toBe('.err');
  expect(r.reason).toMatch(/unavailable/);
  expect(Date.now() - t0).toBeLessThan(2500);
});

test('a scorer error status gives .err', async () => {
  reply = () => ({ status: 503, body: { error: 'no feature store configured (FEAST_URL)' } });
  const r = await run();
  expect(r.subRuleRef).toBe('.err');
  expect(r.reason).toBe('Fraud scorer answered HTTP 503');
});

test('a malformed score gives .err', async () => {
  reply = () => ({ status: 200, body: { probability: 'high' } });
  expect((await run()).subRuleRef).toBe('.err');
});

test('a missing debtor account gives .err without calling the scorer', async () => {
  reply = scored(0.9);
  const r = await run(request('ACCC', 10, null));
  expect(r.subRuleRef).toBe('.err');
  expect(received).toHaveLength(0);
});

test('no scorer configured gives .err', async () => {
  const url = process.env.FRAUD_SCORER_URL;
  delete process.env.FRAUD_SCORER_URL;
  try {
    expect((await run()).reason).toMatch(/No fraud scorer configured/);
  } finally {
    process.env.FRAUD_SCORER_URL = url;
  }
});
