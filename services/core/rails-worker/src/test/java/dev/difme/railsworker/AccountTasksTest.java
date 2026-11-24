package dev.difme.railsworker;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

class AccountTasksTest {
    private static final ObjectMapper JSON = new ObjectMapper();

    private static Fluxnova.Task task(String name) {
        var v = JSON.createObjectNode();
        if (name != null) v.putObject("accountName").put("value", name);
        return new Fluxnova.Task("t", AccountTasks.OPEN, 3, v);
    }

    @Test
    void opensNamedAccountsAndRefusesBadNames() {
        List<String> opened = new ArrayList<>();
        AccountTasks tasks = new AccountTasks(name -> {
            if (name.startsWith("closed")) throw new Fineract.Rejected("client is closed");
            opened.add(name);
            return 42;
        });
        assertEquals("open", tasks.handle(task("merchant-acme")).get("accountStatus"));
        assertEquals(42L, tasks.handle(task("escrow")).get("accountId"));
        assertEquals("rejected", tasks.handle(task("Merchant ACME")).get("accountStatus"));   // not a DIFME account name
        assertEquals("rejected", tasks.handle(task(null)).get("accountStatus"));
        assertEquals("client is closed", tasks.handle(task("closed-1")).get("accountMessage"));
        assertEquals(List.of("merchant-acme", "escrow"), opened);
    }

    @Test
    void combinedTasksRouteByTopic() {
        Tasks all = Tasks.of(new AccountTasks(name -> 1), new CardTasks(null, new CardsOnFile("")));
        assertEquals(List.of(AccountTasks.OPEN), all.topics().subList(0, 1));
        assertEquals("open", all.handle(task("escrow")).get("accountStatus"));
    }
}
