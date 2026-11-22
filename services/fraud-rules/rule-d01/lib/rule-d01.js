"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RULE_ID = void 0;
exports.handleTransaction = handleTransaction;
const frms_coe_lib_1 = require("@tazama-lf/frms-coe-lib");
exports.RULE_ID = 'D01';
const DEFAULT_TIMEOUT_MS = 300;
const DEFAULT_UNKNOWN_DEVICE = 'unknown';
const PROBABILITY_SCALE = 1000;
const MINOR_UNITS = 100;
const failed = (ruleRes, reason) => ({ ...ruleRes, subRuleRef: '.err', reason });
// Warm Node's HTTP client and the connection once at load: the first fetch in a process loads undici, which on a busy
// node took longer than the 300 ms budget and turned the first transaction's score into .err (end-to-end test,
// 2026-11-22). Best effort; errors are ignored here and surface on real calls.
if (process.env.FRAUD_SCORER_URL) {
    void fetch(new URL('/healthz', process.env.FRAUD_SCORER_URL), { signal: AbortSignal.timeout(5000) }).catch(() => undefined);
}
async function handleTransaction(req, determineOutcome, ruleRes, loggerService, ruleConfig, _databaseManager) {
    const context = `Rule-${ruleConfig.id} handleTransaction()`;
    if (!(0, frms_coe_lib_1.isStructuredTransaction)(req.transaction) || !(0, frms_coe_lib_1.isPacs002Transaction)(req.transaction)) {
        return failed(ruleRes, 'Unsupported transaction type');
    }
    const msgId = req.transaction.FIToFIPmtSts.GrpHdr.MsgId;
    const unsuccessful = ruleConfig.config.exitConditions?.find((b) => b.subRuleRef === '.x00');
    if (req.transaction.FIToFIPmtSts.TxInfAndSts.TxSts !== 'ACCC' && unsuccessful) {
        return { ...ruleRes, reason: unsuccessful.reason, subRuleRef: unsuccessful.subRuleRef };
    }
    const params = (ruleConfig.config.parameters ?? {});
    const scorerUrl = process.env.FRAUD_SCORER_URL ?? params.scorerUrl;
    if (!scorerUrl)
        return failed(ruleRes, 'No fraud scorer configured (FRAUD_SCORER_URL)');
    const cache = req.DataCache;
    const accountId = cache.dbtrAcctId;
    const amount = cache.instdAmt ?? cache.intrBkSttlmAmt ?? cache.amt;
    if (!accountId || !amount || !(amount.amt > 0))
        return failed(ruleRes, 'Data cache lacks the debtor account or the amount');
    const timeoutMs = Number(params.timeoutMs ?? DEFAULT_TIMEOUT_MS);
    let score;
    try {
        const res = await fetch(new URL('/v1/score/order', scorerUrl), {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
                accountId,
                deviceId: params.unknownDeviceId ?? DEFAULT_UNKNOWN_DEVICE,
                amountMinor: Math.round(amount.amt * MINOR_UNITS),
            }),
            signal: AbortSignal.timeout(timeoutMs),
        });
        if (!res.ok)
            return failed(ruleRes, `Fraud scorer answered HTTP ${res.status}`);
        score = (await res.json());
    }
    catch (err) {
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
//# sourceMappingURL=rule-d01.js.map