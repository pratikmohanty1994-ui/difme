// SPDX-License-Identifier: Apache-2.0
// Rule D02 with the event-history query answered by a stub, and Tazama's banding function.
import type { RuleConfig, RuleRequest, RuleResult } from '@tazama-lf/frms-coe-lib/lib/interfaces';
import { determineOutcome } from '@tazama-lf/frms-coe-lib/lib/tests/mocks/mock-rule-executor';
import { handleTransaction } from '../src';

const ruleConfig = {
  id: 'D02@1.0.0',
  cfg: '1.0.0',
  tenantId: 'DEFAULT',
  config: {
    parameters: { minHistory: 5, maxQueryRange: 7776000000 },
    exitConditions: [
      { subRuleRef: '.x00', reason: 'Incoming transaction is unsuccessful' },
      { subRuleRef: '.x01', reason: 'Insufficient payment history' },
    ],
    bands: [
      { subRuleRef: '.01', upperLimit: 200, reason: 'Amount usual for the debtor' },
      { subRuleRef: '.02', lowerLimit: 200, upperLimit: 300, reason: 'Amount 2-3 standard deviations above usual' },
      { subRuleRef: '.03', lowerLimit: 300, reason: 'Amount over 3 standard deviations above usual' },
    ],
  },
} as unknown as RuleConfig;

const logger = { trace: jest.fn(), log: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn(), fatal: jest.fn() };
const result = (): RuleResult => ({ id: 'D02@1.0.0', cfg: '1.0.0', subRuleRef: '.err', tenantId: 'DEFAULT' }) as RuleResult;

const request = (amt: number, txSts = 'ACCC'): RuleRequest =>
  ({
    transaction: {
      TxTp: 'pacs.002.001.12',
      TenantId: 'DEFAULT',
      FIToFIPmtSts: { GrpHdr: { MsgId: 'm', CreDtTm: new Date().toISOString() }, TxInfAndSts: { OrgnlEndToEndId: 'e2e-1', TxSts: txSts } },
    },
    networkMap: {},
    DataCache: { dbtrAcctId: 'acct-1', instdAmt: { amt, ccy: 'INR' } },
  }) as unknown as RuleRequest;

let stats: { n: number; mean: string | null; sd: string | null };
const query = jest.fn(async () => ({ rows: [stats] }));
const db = { _eventHistory: { query } } as never;
const run = async (amt: number, txSts?: string) => handleTransaction(request(amt, txSts), determineOutcome, result(), logger as never, ruleConfig, db);

beforeEach(() => query.mockClear());

test.each([
  [1000, '.01', 0], // at the mean
  [1150, '.01', 150], // 1.5 sd
  [1250, '.02', 250], // 2.5 sd
  [1400, '.03', 400], // 4 sd: the §7.4 "z > 3" case
  [500, '.01', 0], // smaller than usual is not suspicious
])('amount %p -> band %p (z x100 = %p)', async (amt, band, value) => {
  stats = { n: 12, mean: '1000.00', sd: '100.00' };
  const r = await run(amt);
  expect(r.subRuleRef).toBe(band);
  expect(r.indpdntVarbl).toBe(value);
});

test('queries the debtor history excluding this payment, within the window and tenant', async () => {
  stats = { n: 12, mean: '1000', sd: '100' };
  await run(1000);
  const [, values] = query.mock.calls[0] as unknown as [string, unknown[]];
  expect(values[0]).toBe('acct-1');
  expect(values[1]).toBe('e2e-1');
  expect(values[3]).toBe(7776000000);
  expect(values[4]).toBe('DEFAULT');
});

test('too little history exits with .x01 (no weight)', async () => {
  stats = { n: 3, mean: '1000', sd: '100' };
  expect((await run(99999)).subRuleRef).toBe('.x01');
});

test('no spread (all payments equal) exits with .x01', async () => {
  stats = { n: 10, mean: '1000', sd: '0' };
  expect((await run(5000)).subRuleRef).toBe('.x01');
});

test('an unsuccessful payment exits with .x00 without querying', async () => {
  expect((await run(1000, 'RJCT')).subRuleRef).toBe('.x00');
  expect(query).not.toHaveBeenCalled();
});
