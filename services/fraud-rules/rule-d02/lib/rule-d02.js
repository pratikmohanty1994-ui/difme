"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RULE_ID = void 0;
exports.handleTransaction = handleTransaction;
const frms_coe_lib_1 = require("@tazama-lf/frms-coe-lib");
exports.RULE_ID = 'D02';
const DEFAULT_MIN_HISTORY = 5;
const DEFAULT_WINDOW_MS = 90 * 24 * 3600 * 1000;
const SCALE = 100;
const exit = (ruleRes, ruleConfig, ref, fallback) => {
    const c = ruleConfig.config.exitConditions?.find((b) => b.subRuleRef === ref);
    return { ...ruleRes, subRuleRef: ref, reason: c?.reason ?? fallback };
};
async function handleTransaction(req, determineOutcome, ruleRes, loggerService, ruleConfig, databaseManager) {
    if (!(0, frms_coe_lib_1.isStructuredTransaction)(req.transaction) || !(0, frms_coe_lib_1.isPacs002Transaction)(req.transaction)) {
        return { ...ruleRes, subRuleRef: '.err', reason: 'Unsupported transaction type' };
    }
    const tx = req.transaction;
    if (tx.FIToFIPmtSts.TxInfAndSts.TxSts !== 'ACCC')
        return exit(ruleRes, ruleConfig, '.x00', 'Incoming transaction is unsuccessful');
    const cache = req.DataCache;
    const amount = (cache.instdAmt ?? cache.intrBkSttlmAmt ?? cache.amt)?.amt;
    if (!cache.dbtrAcctId || amount === undefined) {
        return { ...ruleRes, subRuleRef: '.err', reason: 'Data cache lacks the debtor account or the amount' };
    }
    const params = (ruleConfig.config.parameters ?? {});
    const minHistory = Number(params.minHistory ?? DEFAULT_MIN_HISTORY);
    const windowMs = Number(params.maxQueryRange ?? DEFAULT_WINDOW_MS);
    // The debtor's earlier credit transfers, this one excluded (its pacs.008 is already stored).
    const res = await databaseManager._eventHistory.query(`SELECT COUNT(*)::int AS n, AVG(tr.amt) AS mean, STDDEV_SAMP(tr.amt) AS sd
FROM transaction tr
WHERE tr.source = $1
AND tr."txtp" = 'pacs.008.001.10'
AND tr."endtoendid" <> $2
AND tr."credttm"::timestamptz <= $3::timestamptz
AND ($3::timestamptz - tr."credttm"::timestamptz) <= $4 * interval '1 millisecond'
AND tr.tenantId = $5;`, [cache.dbtrAcctId, tx.FIToFIPmtSts.TxInfAndSts.OrgnlEndToEndId, tx.FIToFIPmtSts.GrpHdr.CreDtTm, windowMs, tx.TenantId]);
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
//# sourceMappingURL=rule-d02.js.map