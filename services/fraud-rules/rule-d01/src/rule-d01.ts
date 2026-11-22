// SPDX-License-Identifier: Apache-2.0
// DIFME rule D01 (ADR-023): the ONNX fraud model as a Tazama rule processor, so one engine combines the model with the
// typologies instead of a parallel scoring path. On a settled pacs.002 it asks DIFME's fraud scorer
// (services/fraud-scorer, POST /v1/score/order) for the debtor account and amount, and maps the fraud probability
// (x1000) to the bands in the rule configuration: by default .01 below 150 (the scorer's ALLOW), .02 up to 500
// (REVIEW), .03 from 500 (BLOCK). A scorer that can't answer within the configured time gives .err, which carries no
// weight: whether a payment proceeds without a score is the payment hub's fail-open/closed setting, not this rule's.
// ISO 20022 payment messages carry no device, so the configured unknown-device id is sent and the scorer reports the
// device features it defaulted.
import type { DatabaseManagerInstance, LoggerService, ManagerConfig } from '@tazama-lf/frms-coe-lib';
import { isPacs002Transaction, isPain001Transaction, isStructuredTransaction } from '@tazama-lf/frms-coe-lib';
import type { OutcomeResult, RuleConfig, RuleRequest, RuleResult } from '@tazama-lf/frms-coe-lib/lib/interfaces';

export const RULE_ID = 'D01';

export type RuleExecutorConfig = ManagerConfig;

const DEFAULT_TIMEOUT_MS = 300;
const DEFAULT_UNKNOWN_DEVICE = 'unknown';
const PROBABILITY_SCALE = 1000;
const MINOR_UNITS = 100;

interface OrderScore {
  probability: number;
  riskScore: number;
  decision: string;
  model: string;
  missing?: string[];
}

interface Amount {
  amt: number;
  ccy: string;
}

const failed = (ruleRes: RuleResult, reason: string): RuleResult => ({ ...ruleRes, subRuleRef: '.err', reason });

// Warm Node's HTTP client and the connection once at load: the first fetch in a process loads undici, which on a busy
// node took longer than the 300 ms budget and turned the first transaction's score into .err (end-to-end test,
// 2026-11-22). Best effort; errors are ignored here and surface on real calls.
if (process.env.FRAUD_SCORER_URL) {
  void fetch(new URL('/healthz', process.env.FRAUD_SCORER_URL), { signal: AbortSignal.timeout(5000) }).catch(() => undefined);
}

export async function handleTransaction(
  req: RuleRequest,
  determineOutcome: (value: number, ruleConfig: RuleConfig, ruleResult: RuleResult) => RuleResult,
  ruleRes: RuleResult,
  loggerService: LoggerService,
  ruleConfig: RuleConfig,
  _databaseManager?: DatabaseManagerInstance<RuleExecutorConfig>,
): Promise<RuleResult> {
  const context = `Rule-${ruleConfig.id} handleTransaction()`;
  if (!isStructuredTransaction(req.transaction)) return failed(ruleRes, 'Unsupported transaction type');
  // pacs.002: a settled payment (from the payment hub). pain.001: a payment initiation, which is how the 3-D Secure
  // ACS asks for a risk verdict before the payment exists (ADR-027), scored the same way from its instructed amount.
  let msgId: string;
  let initiatedAmount: Amount | undefined;
  if (isPacs002Transaction(req.transaction)) {
    msgId = req.transaction.FIToFIPmtSts.GrpHdr.MsgId;
    const unsuccessful = ruleConfig.config.exitConditions?.find((b: OutcomeResult) => b.subRuleRef === '.x00');
    if (req.transaction.FIToFIPmtSts.TxInfAndSts.TxSts !== 'ACCC' && unsuccessful) {
      return { ...ruleRes, reason: unsuccessful.reason, subRuleRef: unsuccessful.subRuleRef };
    }
  } else if (isPain001Transaction(req.transaction)) {
    msgId = req.transaction.CstmrCdtTrfInitn.GrpHdr.MsgId;
    const instd = req.transaction.CstmrCdtTrfInitn.PmtInf.CdtTrfTxInf.Amt.InstdAmt.Amt as unknown as { Amt: number; Ccy: string };
    initiatedAmount = { amt: Number(instd.Amt), ccy: instd.Ccy } as Amount;
  } else {
    return failed(ruleRes, 'Unsupported transaction type');
  }

  const params = (ruleConfig.config.parameters ?? {}) as Record<string, unknown>;
  const scorerUrl = process.env.FRAUD_SCORER_URL ?? (params.scorerUrl as string | undefined);
  if (!scorerUrl) return failed(ruleRes, 'No fraud scorer configured (FRAUD_SCORER_URL)');

  const cache = req.DataCache as typeof req.DataCache & { amt?: Amount };
  const accountId = cache.dbtrAcctId;
  const amount = cache.instdAmt ?? cache.intrBkSttlmAmt ?? cache.amt ?? initiatedAmount;
  if (!accountId || !amount || !(amount.amt > 0)) return failed(ruleRes, 'Data cache lacks the debtor account or the amount');

  const timeoutMs = Number(params.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  let score: OrderScore;
  try {
    const res = await fetch(new URL('/v1/score/order', scorerUrl), {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        accountId,
        deviceId: (params.unknownDeviceId as string | undefined) ?? DEFAULT_UNKNOWN_DEVICE,
        amountMinor: Math.round(amount.amt * MINOR_UNITS),
      }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return failed(ruleRes, `Fraud scorer answered HTTP ${res.status}`);
    score = (await res.json()) as OrderScore;
  } catch (err) {
    const why = err instanceof Error ? err.message : String(err);
    loggerService.warn(`Fraud scorer unavailable: ${why}`, context, msgId);
    return failed(ruleRes, `Fraud scorer unavailable: ${why}`);
  }
  if (typeof score.probability !== 'number' || score.probability < 0 || score.probability > 1) {
    return failed(ruleRes, 'Fraud scorer returned no probability');
  }
  loggerService.trace(`model ${score.model}: probability ${score.probability} (${score.decision})`, context, msgId);
  return determineOutcome(Math.round(score.probability * PROBABILITY_SCALE), ruleConfig, ruleRes);
}
