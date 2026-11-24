/**************************************************************************
 *  DIFME (keys only in the emulated TEE): the ILP fulfilment HMAC from the  *
 *  security module (services/hsm, POST /v1/ilp/<institution>/hmac) with    *
 *  this FSP's own key ilp-<institution>; the adapter holds no ILP secret.  *
 **************************************************************************/
'use strict';

const crypto = require('crypto');

// Packets are still built by sdk-standard-components (no secret involved); its fulfilment, computed with this placeholder,
// is always replaced by the security module's. The placeholder is public and never protects anything.
const PLACEHOLDER = 'difme-placeholder-not-a-key';

/**
 * Wraps an Ilp instance (built with PLACEHOLDER) so that every fulfilment comes from the security module:
 * calculateFulfil, getResponseIlp, getQuoteResponseIlp and getFxQuoteResponseIlp become async. Methods that need no
 * secret (getTransactionObject, validateFulfil, calculateConditionFromFulfil, ...) are passed through.
 *
 * MAC input: the ASCII bytes of the base64url ILP packet; key = ilp-<institution>, the same construction as
 * sdk-standard-components' HMAC (key = ASCII of base64(secret), data = ASCII of the packet) with the secret replaced by a
 * key generated inside the security module.
 */
function hsmIlp(ilp, { hsmUrl, institution, logger, fetchImpl }) {
    const url = `${hsmUrl.replace(/\/+$/, '')}/v1/ilp/${institution}/hmac`;
    const doFetch = fetchImpl || fetch;

    async function calculateFulfil(base64EncodedPacket) {
        const data = Buffer.from(base64EncodedPacket, 'ascii').toString('hex');
        const res = await doFetch(url, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ data }),
            signal: AbortSignal.timeout(5000),
        });
        if (res.status !== 200) throw new Error(`security module answered HTTP ${res.status} for the ILP fulfilment`);
        const { mac } = await res.json();
        if (!/^[0-9a-fA-F]{64}$/.test(mac || '')) throw new Error('security module returned no MAC');
        return Buffer.from(mac, 'hex').toString('base64url');
    }

    async function withHsmFulfilment(result) {
        const fulfilment = await calculateFulfil(result.ilpPacket);
        return { ...result, fulfilment, condition: ilp.calculateConditionFromFulfil(fulfilment) };
    }

    logger?.isInfoEnabled && logger.info(`ILP fulfilments from the security module (${url})`);
    return new Proxy(ilp, {
        get(target, prop) {
            switch (prop) {
            case 'calculateFulfil': return calculateFulfil;
            case 'getResponseIlp': return (tx) => withHsmFulfilment(target.getResponseIlp(tx));
            case 'getQuoteResponseIlp': return (q, r) => withHsmFulfilment(target.getQuoteResponseIlp(q, r));
            case 'getFxQuoteResponseIlp': return (q, r) => withHsmFulfilment(target.getFxQuoteResponseIlp(q, r));
            default: {
                const v = target[prop];
                return typeof v === 'function' ? v.bind(target) : v;
            }
            }
        },
    });
}

/** The Ilp the models use: the security module's when HSM_URL is set; otherwise upstream's, with the in-process secret. */
function makeIlp(Ilp, ilpVersion, config) {
    if (config.hsmUrl) {
        const ilp = Ilp.ilpFactory(ilpVersion, { secret: PLACEHOLDER, logger: config.logger });
        return hsmIlp(ilp, { hsmUrl: config.hsmUrl, institution: config.ilpInstitution || config.dfspId, logger: config.logger });
    }
    config.logger?.isWarnEnabled && config.logger.warn('ILP secret held in this process (HSM_URL not set): local runs only');
    return Ilp.ilpFactory(ilpVersion, { secret: config.ilpSecret, logger: config.logger });
}

module.exports = { hsmIlp, makeIlp, PLACEHOLDER, _sha: (b) => crypto.createHash('sha256').update(b).digest() };
