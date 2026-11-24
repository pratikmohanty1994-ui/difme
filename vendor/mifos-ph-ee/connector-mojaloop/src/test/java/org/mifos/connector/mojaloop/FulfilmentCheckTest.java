package org.mifos.connector.mojaloop;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import org.junit.jupiter.api.Test;
import org.mifos.connector.mojaloop.transfer.FulfilmentCheck;

class FulfilmentCheckTest {
    private static final Base64.Encoder B64URL = Base64.getUrlEncoder().withoutPadding();

    private static String[] pair(byte seed) throws Exception {
        byte[] f = new byte[32];
        java.util.Arrays.fill(f, seed);
        return new String[] {B64URL.encodeToString(f), B64URL.encodeToString(MessageDigest.getInstance("SHA-256").digest(f))};
    }

    @Test
    void theMatchingFulfilmentProvesTheTransferOnce() throws Exception {
        String[] p = pair((byte) 7);
        FulfilmentCheck.remember("tx-1", p[1], Instant.now().plusSeconds(60));
        assertNull(FulfilmentCheck.verify("tx-1", p[0]));
        assertNotNull(FulfilmentCheck.verify("tx-1", p[0]), "a second callback has nothing to match against");
    }

    @Test
    void anyOtherFulfilmentIsRefused() throws Exception {
        String[] p = pair((byte) 7), q = pair((byte) 8);
        FulfilmentCheck.remember("tx-2", p[1], null);
        assertEquals("fulfilment does not match the transfer's condition", FulfilmentCheck.verify("tx-2", q[0]));
        FulfilmentCheck.remember("tx-3", p[1], null);
        assertEquals("COMMITTED without a fulfilment", FulfilmentCheck.verify("tx-3", null));
        FulfilmentCheck.remember("tx-4", p[1], null);
        assertNotNull(FulfilmentCheck.verify("tx-4", "not base64 !!"));
        FulfilmentCheck.remember("tx-5", p[1], null);
        assertNotNull(FulfilmentCheck.verify("tx-5", B64URL.encodeToString(new byte[16])));   // wrong length
    }

    @Test
    void anUnknownTransferFailsClosed() {
        assertNotNull(FulfilmentCheck.verify("never-sent", "AAAA"));
    }
}
