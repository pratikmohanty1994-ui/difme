package dev.difme.hub.cbs;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

/** Live against a Fineract (HUB_LIVE_FINERACT, password login): accounts opened by name are addressable by PH-EE. */
@EnabledIfEnvironmentVariable(named = "HUB_LIVE_FINERACT", matches = ".+")
class FineractInteropLiveTest {
    @Test
    void openedAccountsGetTheirInteropIdentifierOnce() {
        Fineract f = new Fineract(System.getenv("HUB_LIVE_FINERACT"), "mifos", "password", "default");
        String name = "interop-" + System.nanoTime();
        f.account(name);
        assertEquals(name, f.interopAccount(name), "ACCOUNT_ID identifier resolves to the account's external id");
        // A second client (cold cache) resolving the same account must not fail on the existing identifier.
        new Fineract(System.getenv("HUB_LIVE_FINERACT"), "mifos", "password", "default").account(name);
        assertEquals(name, f.interopAccount(name));
    }
}
