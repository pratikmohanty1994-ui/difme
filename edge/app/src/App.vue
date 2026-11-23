<script setup lang="ts">
import { onMounted, ref } from "vue";
import { api as defaultApi, money, type Attestation, type WalletApi, type WalletStatus } from "./api";

const props = defineProps<{ api?: WalletApi }>();
const api = props.api ?? defaultApi;

const status = ref<WalletStatus | null>(null);
const attestation = ref<Attestation | null>(null);
const payee = ref("");
const amount = ref("");
const message = ref("");
const error = ref("");
const busy = ref(false);

async function refresh() {
  status.value = await api.status();
}

async function run(action: () => Promise<string>) {
  busy.value = true;
  error.value = message.value = "";
  try {
    message.value = await action();
    await refresh();
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  } finally {
    busy.value = false;
  }
}

function pay() {
  return run(async () => {
    const minor = Math.round(Number(amount.value) * 100);
    const p = await api.payOffline(payee.value, minor);
    payee.value = amount.value = "";
    return `Paid ${money(p.amountMinor, p.currency)} to ${p.payee} offline; it settles at the next sync.`;
  });
}

function sync() {
  return run(async () => {
    const s = await api.sync();
    const r = s.lastSync;
    return r ? `Synced: ${r.accepted} accepted, ${r.failed} failed.` : "Synced.";
  });
}

async function attest() {
  error.value = "";
  try {
    attestation.value = await api.attestation();
  } catch (e) {
    error.value = e instanceof Error ? e.message : String(e);
  }
}

onMounted(refresh);
</script>

<template>
  <main>
    <h1>DIFME wallet</h1>
    <section v-if="status" aria-label="balance">
      <p>Balance <strong data-test="balance">{{ money(status.ledgerBalance, status.currency) }}</strong></p>
      <p>Offline spending rights <strong data-test="rights">{{ money(status.rightsAvailable, status.currency) }}</strong></p>
      <p data-test="pending">{{ status.pendingCount }} payment(s) waiting for sync</p>
    </section>

    <form aria-label="pay offline" @submit.prevent="pay">
      <h2>Pay offline</h2>
      <label>Payee <input v-model="payee" name="payee" required /></label>
      <label>Amount <input v-model="amount" name="amount" inputmode="decimal" required /></label>
      <button type="submit" :disabled="busy">Pay</button>
    </form>

    <p>
      <button type="button" :disabled="busy || !status?.hubConfigured" @click="sync">Sync with the hub</button>
      <button type="button" @click="attest">Check device attestation</button>
    </p>

    <p v-if="message" role="status">{{ message }}</p>
    <p v-if="error" role="alert" class="error">{{ error }}</p>

    <section v-if="attestation" aria-label="attestation">
      <h2>Device attestation</h2>
      <p>Key store: {{ attestation.securityLevel }}, token profile {{ attestation.eatProfile }}</p>
      <p data-test="selfcheck">Self-check {{ attestation.selfCheck ? "passed" : "not passed" }}</p>
      <ul><li v-for="c in attestation.caveats" :key="c">{{ c }}</li></ul>
    </section>

    <section v-if="status?.payments.length" aria-label="payments">
      <h2>Payments</h2>
      <ul>
        <li v-for="p in status.payments" :key="p.id">{{ p.payee }}: {{ money(p.amountMinor, p.currency) }} ({{ p.status }})</li>
      </ul>
    </section>
  </main>
</template>

<style>
body { font: 16px system-ui, sans-serif; margin: 16px; max-width: 480px; }
label { display: block; margin: 8px 0; }
input, button { font: inherit; padding: 8px; }
.error { color: #b00020; }
</style>
