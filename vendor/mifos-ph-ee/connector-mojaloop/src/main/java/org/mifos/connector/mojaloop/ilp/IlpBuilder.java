/*
 * This Source Code Form is subject to the terms of the Mozilla
 * Public License, v. 2.0. If a copy of the MPL was not distributed
 * with this file, You can obtain one at
 *
 *  https://mozilla.org/MPL/2.0/.
 */
package org.mifos.connector.mojaloop.ilp;

import com.ilp.conditions.models.pdp.Money;
import com.ilp.conditions.models.pdp.PartyIdInfo;
import com.ilp.conditions.models.pdp.Transaction;
import org.mifos.connector.common.util.ContextUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import java.io.IOException;
import java.math.BigDecimal;

@Component
public class IlpBuilder {

    private static final String ILP_ADDRESS_TEMPLATE = "g.tz.%s.%s.%s";

    @Autowired
    private IlpConditionHandlerImpl ilpConditionHandlerImpl;

    @Autowired
    private IlpMac ilpMac;   // DIFME: the fulfilment HMAC comes from the security module (keys only in the TEE)

    public Ilp build(String transactionId, String quoteId, BigDecimal transactionAmount, String currency, Party payer,
                     Party payee, BigDecimal transferAmount) throws IOException {
        Transaction transaction = mapToTransaction(transactionId, quoteId, transactionAmount, currency, payer, payee);
        return build(transaction, transferAmount);
    }

    public Ilp build(Transaction transaction, BigDecimal amount) throws IOException {
        String ilpAddress = buildIlpAddress(transaction);
        String ilpPacket = ilpConditionHandlerImpl.getILPPacket(ilpAddress, ContextUtil.formatAmount(amount), transaction);
        byte[] mac = ilpMac.mac(ilpPacket);
        String ilpCondition = ilpConditionHandlerImpl.conditionFromMac(mac);
        String fulfillment = ilpConditionHandlerImpl.fulfillmentFromMac(mac);

        return new Ilp(ilpPacket, ilpCondition, fulfillment, transaction);
    }

    public Ilp parse(String packet, String condition)  {
        return new Ilp(packet, condition, ilpConditionHandlerImpl.getTransactionFromIlpPacket(packet));
    }

    public boolean isValidPacketAgainstCondition(String packet, String condition) {
        return ilpConditionHandlerImpl.conditionFromMac(ilpMac.mac(packet)).equals(condition);
    }

    public String buildIlpAddress(Transaction transaction) {
        PartyIdInfo partyIdInfo = transaction.getPayee().getPartyIdInfo();
        return String.format(ILP_ADDRESS_TEMPLATE, partyIdInfo.getFspId(), partyIdInfo.getPartyIdType(), partyIdInfo.getPartyIdentifier());
    }

    private Transaction mapToTransaction(String transactionId, String quoteId, BigDecimal transactionAmount, String currency,
                                         Party payer, Party payee) {
        Money money = new Money();
        money.setAmount(ContextUtil.formatAmount(transactionAmount));
        money.setCurrency(currency);

        return mapToTransaction(transactionId, quoteId, money, payer, payee);
    }

    private Transaction mapToTransaction(String transactionId, String quoteId, Money transactionAmount, Party payer, Party payee) {
        Transaction transaction = new Transaction();

        transaction.setTransactionId(transactionId);
        transaction.setQuoteId(quoteId);
        transaction.setAmount(transactionAmount);
        transaction.setPayer(payer.getIlpParty());
        transaction.setPayee(payee.getIlpParty());

        return transaction;
    }
}
