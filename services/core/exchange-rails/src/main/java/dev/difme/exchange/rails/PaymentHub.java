package dev.difme.exchange.rails;

/**
 * DIFME's payment hub (services/core/payment-hub): the exchange's way to the real rails, i.e. the PSP (card payments)
 * and the core banking system (escrow accounts). Every call carries the caller's id; repeating it returns the first
 * result and moves no money twice.
 */
public interface PaymentHub {
    /** status: SETTLED, REFUNDED, DONE, DECLINED, INSUFFICIENT_FUNDS, REJECTED, FAILED. detail: the reason or reference. */
    record Outcome(String status, String detail) {}

    /** A buying partner's card on file (test cards on the scheme simulator). Never logged. */
    /** ref: the configuration key the card came from ("42", "*"); PH-EE's card flows carry only this, never the PAN. */
    record CardOnFile(String pan, String expiryMonth, String expiryYear, String cvc, String ref) {
        public CardOnFile(String pan, String expiryMonth, String expiryYear, String cvc) { this(pan, expiryMonth, expiryYear, cvc, null); }
        @Override public String toString() { return "CardOnFile[****]"; }
    }

    /** Money arriving from outside DIFME's books into a named CBS account. */
    Outcome deposit(String id, String account, long amountMinor);

    Outcome transfer(String id, String from, String to, long amountMinor, String note);

    Outcome payCard(String paymentId, String merchant, long amountMinor, CardOnFile card);

    Outcome refundCard(String refundId, String paymentId, String merchant, long amountMinor, String reason);
}
