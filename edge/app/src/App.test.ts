import { describe, expect, it } from "vitest";
import { flushPromises, mount } from "@vue/test-utils";
import App from "./App.vue";
import { standIn } from "./api";

describe("wallet screen", () => {
  it("shows balance and rights, pays offline and lists the pending payment", async () => {
    const w = mount(App, { props: { api: standIn() } });
    await flushPromises();
    expect(w.get("[data-test=balance]").text()).toContain("10,000.00");
    expect(w.get("[data-test=rights]").text()).toContain("2,000.00");
    await w.get("input[name=payee]").setValue("Chai stall");
    await w.get("input[name=amount]").setValue("150.50");
    await w.get("form").trigger("submit");
    await flushPromises();
    expect(w.get("[role=status]").text()).toContain("Chai stall");
    expect(w.get("[data-test=rights]").text()).toContain("1,849.50");
    expect(w.get("[data-test=pending]").text()).toContain("1 payment");
    expect(w.text()).toContain("PENDING");
  });

  it("refuses a payment above the offline rights", async () => {
    const w = mount(App, { props: { api: standIn() } });
    await flushPromises();
    await w.get("input[name=payee]").setValue("Shop");
    await w.get("input[name=amount]").setValue("5000");
    await w.get("form").trigger("submit");
    await flushPromises();
    expect(w.get("[role=alert]").text()).toContain("not enough offline spending rights");
    expect(w.get("[data-test=rights]").text()).toContain("2,000.00");
  });

  it("shows the attestation result", async () => {
    const w = mount(App, { props: { api: standIn() } });
    await flushPromises();
    await w.findAll("button").find((b) => b.text().includes("attestation"))!.trigger("click");
    await flushPromises();
    expect(w.get("[data-test=selfcheck]").text()).toContain("not passed");
  });
});
