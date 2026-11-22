package dev.difme.hub.api;

import dev.difme.hub.Hub;
import dev.difme.hub.flow.Flows.Result;
import dev.difme.hub.psp.Hyperswitch;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import java.util.Set;

/**
 * The hub's API for DIFME services (in-mesh only). Every money-moving call carries the caller's id; repeating it
 * returns the first result. 200 for a completed outcome (including DECLINED / INSUFFICIENT_FUNDS: the call worked),
 * 422 for a malformed request, 502 when a system behind the hub is unreachable.
 */
@Path("/v1")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class HubResource {
    @Inject Hub hub;

    public record CardIn(String number, String expiryMonth, String expiryYear, String cvc, String holder) {}
    /** payer: DIFME's account id for the cardholder (fraud check); optional. */
    public record PayIn(String paymentId, String merchant, Long amountMinor, String currency, CardIn card, String payer) {}
    public record ReviewIn(String merchant, Boolean approve) {}
    public record RefundIn(String refundId, String merchant, Long amountMinor, String reason) {}
    public record TransferIn(String transferId, String from, String to, Long amountMinor, String note) {}
    public record DepositIn(String depositId, Long amountMinor) {}

    private static final Set<String> CURRENCIES = Set.of("INR");   // the CBS books are in INR

    @POST @Path("/card-payments")
    public Response pay(PayIn in) {
        if (in == null || in.card() == null || in.card().number() == null || in.amountMinor() == null) return bad("paymentId, merchant, amountMinor and card are required");
        String cur = in.currency() == null ? "INR" : in.currency();
        if (!CURRENCIES.contains(cur)) return bad("currency: INR only");
        CardIn c = in.card();
        return guard(() -> hub.pay(in.paymentId(), in.merchant(), in.amountMinor(), cur,
                new Hyperswitch.Card(c.number(), c.expiryMonth(), c.expiryYear(), c.cvc(), c.holder() == null ? "" : c.holder()), in.payer()));
    }

    /** Decision on a card payment held for fraud review (status REVIEW): approve captures and settles, reject releases. */
    @POST @Path("/card-payments/{paymentId}/review")
    public Response review(@PathParam("paymentId") String paymentId, ReviewIn in) {
        if (in == null || in.merchant() == null || in.approve() == null) return bad("merchant and approve are required");
        return guard(() -> hub.review(paymentId, in.merchant(), in.approve()));
    }

    @POST @Path("/card-payments/{paymentId}/refunds")
    public Response refund(@PathParam("paymentId") String paymentId, RefundIn in) {
        if (in == null || in.amountMinor() == null) return bad("refundId, merchant and amountMinor are required");
        return guard(() -> hub.refund(in.refundId(), paymentId, in.merchant(), in.amountMinor(), in.reason()));
    }

    @POST @Path("/transfers")
    public Response transfer(TransferIn in) {
        if (in == null || in.amountMinor() == null || in.to() == null) return bad("transferId, from, to and amountMinor are required");
        return guard(() -> hub.transfer(in.transferId(), in.from(), in.to(), in.amountMinor(), in.note()));
    }

    @POST @Path("/accounts/{account}/deposits")
    public Response deposit(@PathParam("account") String account, DepositIn in) {
        if (in == null || in.amountMinor() == null) return bad("depositId and amountMinor are required");
        return guard(() -> hub.deposit(in.depositId(), account, in.amountMinor()));
    }

    @GET @Path("/accounts/{account}")
    public Response account(@PathParam("account") String account) {
        try {
            return Response.ok(Map.of("account", account, "balanceMinor", hub.balanceMinor(account), "currency", "INR")).build();
        } catch (IllegalArgumentException e) {
            return bad(e.getMessage());
        } catch (IllegalStateException e) {
            return Response.status(502).entity(Map.of("error", e.getMessage())).build();
        }
    }

    private interface Call { Result run(); }

    private static Response guard(Call c) {
        try {
            return Response.ok(c.run()).build();
        } catch (IllegalArgumentException e) {
            return bad(e.getMessage());
        } catch (IllegalStateException e) {
            return Response.status(502).entity(Map.of("error", e.getMessage())).build();
        }
    }

    private static Response bad(String why) {
        return Response.status(422).entity(Map.of("error", why)).build();
    }
}
