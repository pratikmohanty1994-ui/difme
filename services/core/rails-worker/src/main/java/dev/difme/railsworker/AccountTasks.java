package dev.difme.railsworker;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * DifmeOpenAccount (D3: account provisioning off the interim hub): fineract-open-account opens the named account in
 * Fineract on first use (client + DIFME Wallet / DIFME Settlement savings account, approved and active, external id =
 * the name) and registers its interop identifier ACCOUNT_ID = the name, so PH-EE's transfers can address it. Opening an
 * account that exists only registers a missing identifier: the task is safe to repeat.
 */
final class AccountTasks implements Tasks {
    static final String OPEN = "fineract-open-account";

    /** The account opening the worker needs from Fineract (Fineract.account in production). */
    interface Cbs {
        long open(String name);
    }

    private final Cbs cbs;

    AccountTasks(Cbs cbs) {
        this.cbs = cbs;
    }

    @Override
    public List<String> topics() { return List.of(OPEN); }

    @Override
    public Map<String, Object> handle(Fluxnova.Task t) {
        String name = t.str("accountName");
        Map<String, Object> out = new LinkedHashMap<>();
        if (name == null || !name.matches("[a-z0-9][a-z0-9-]{0,47}")) {
            out.put("accountStatus", "rejected");
            out.put("accountMessage", "account name: lower-case letters, digits and -, up to 48");
            return out;
        }
        try {
            out.put("accountId", cbs.open(name));
            out.put("accountStatus", "open");
        } catch (Fineract.Rejected e) {
            out.put("accountStatus", "rejected");
            out.put("accountMessage", e.getMessage());
        }
        return out;
    }
}
