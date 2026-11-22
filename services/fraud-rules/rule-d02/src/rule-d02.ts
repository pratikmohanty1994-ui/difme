// SPDX-License-Identifier: Apache-2.0
// DIFME rule D02 (ADR-023, PDF §7.4 L1 "amount z-score > 3 is high risk"): how unusual this payment's amount is for
// the debtor. Compares it with the debtor's earlier credit transfers (pacs.008) in Tazama's event history within the
// configured window and returns the z-score x100, banded by the rule configuration (default: .01 below 2 standard
// deviations, .02 from 2, .03 from 3). With fewer than minHistory earlier payments, or no spread at all, it exits with
// .x01 (insufficient history), which carries no weight. Velocity is rule 901's; device, geography and attestation reach
// Tazama through the ONNX model (rule D01).
import type { DatabaseManagerInstance, LoggerService, ManagerConfig } from '@tazama-lf/frms-coe-lib';
import { isPacs002Transaction, isStructuredTransaction } from '@tazama-lf/frms-coe-lib';
import type { OutcomeResult, RuleConfig, RuleRequest, RuleResult } from '@tazama-lf/frms-coe-lib/lib/interfaces';

export const RULE_ID = 'D02';

export type RuleExecutorConfig = ManagerConfig & Required<Pick<ManagerConfig, 'eventHistory'>>;

const DEFAULT_MIN_HISTORY = 5;
const DEFAULT_WINDOW_MS = 90 * 24 * 3600 * 1000;
const SCALE = 100;

interface Stats {
  n: number;
  mean: string | number | null;
  sd: string | number | null;
}

const exit = (ruleRes: RuleResult, ruleConfig: RuleConfig, ref: string, fallback: string): RuleResult => {
  const c = ruleConfig.config.exitConditions?.find((b: OutcomeResult) => b.subRuleRef === ref);
  return { ...ruleRes, subRuleRef: ref, reason: c?.reason ?? fallback };
};

export async function handleTransaction(
  req: RuleRequest,
  determineOutcome: (value: number, ruleConfig: RuleConfig, ruleResult: RuleResult) => RuleResult,
  ruleRes: RuleResult,
  loggerService: LoggerService,
  ruleConfig: RuleConfig,
  databaseManager: DatabaseManagerInstance<RuleExecutorConfig>,
): Promise<RuleResult> {
  if (!isStructuredTransaction(req.transaction) || !isPacs002Transaction(req.transaction)) {
    return { ...ruleRes, subRuleRef: '.err', reason: 'Unsupported transaction type' };
  }
  const tx = req.transaction;
  if (tx.FIToFIPmtSts.TxInfAndSts.TxSts !== 'ACCC') return exit(ruleRes, ruleConfig, '.x00', 'Incoming transaction is unsuccessful');

  const cache = req.DataCache as typeof req.DataCache & { amt?: { amt: number } };
  const amount = (cache.instdAmt ?? cache.intrBkSttlmAmt ?? cache.amt)?.amt;
  if (!cache.dbtrAcctId || amount === undefined) {
    return { ...ruleRes, subRuleRef: '.err', reason: 'Data cache lacks the debtor account or the amount' };
  }
  const params = (ruleConfig.config.parameters ?? {}) as Record<string, unknown>;
  const minHistory = Number(params.minHistory ?? DEFAULT_MIN_HISTORY);
  const windowMs = Number(params.maxQueryRange ?? DEFAULT_WINDOW_MS);

  // The debtor's earlier credit transfers, this one excluded (its pacs.008 is already stored).
  const res = await databaseManager._eventHistory.query<Stats>(
    `SELECT COUNT(*)::int AS n, AVG(tr.amt) AS mean, STDDEV_SAMP(tr.amt) AS sd
FROM transaction tr
WHERE tr.source = $1
AND tr."txtp" = 'pacs.008.001.10'
AND tr."endtoendid" <> $2
AND tr."credttm"::timestamptz <= $3::timestamptz
AND ($3::timestamptz - tr."credttm"::timestamptz) <= $4 * interval '1 millisecond'
AND tr.tenantId = $5;`,
    [cache.dbtrAcctId, tx.FIToFIPmtSts.TxInfAndSts.OrgnlEndToEndId, tx.FIToFIPmtSts.GrpHdr.CreDtTm, windowMs, tx.TenantId],
  );
  const { n, mean, sd } = res.rows[0];
  const m = Number(mean);
  const s = Number(sd);
  if (n < minHistory || !Number.isFinite(s) || s === 0) {
    return exit(ruleRes, ruleConfig, '.x01', 'Insufficient payment history for an amount comparison');
  }
  const z = (amount - m) / s;
  loggerService.trace(`amount ${amount} vs mean ${m.toFixed(2)} sd ${s.toFixed(2)} over ${n}: z ${z.toFixed(2)}`, `Rule-${ruleConfig.id}`);
  // Only unusually large payments are suspicious; smaller than usual counts as 0.
  return determineOutcome(Math.max(0, Math.round(z * SCALE)), ruleConfig, ruleRes);
}
