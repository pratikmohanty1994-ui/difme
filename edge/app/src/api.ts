// The wallet core (edge/core) through Tauri commands (src-tauri/src/lib.rs). Outside Tauri (browser dev server,
// tests) a stand-in with the same behaviour answers, so the UI can be developed and tested without the native shell.
import { invoke, isTauri } from "@tauri-apps/api/core";

export interface Payment {
  id: string;
  payee: string;
  amountMinor: number;
  currency: string;
  createdMs: number;
  status: string;
}

export interface WalletStatus {
  walletId: string;
  deviceId: string;
  currency: string;
  ledgerBalance: number;
  rightsAvailable: number;
  offlineSpent: number;
  pendingCount: number;
  payments: Payment[];
  hubConfigured: boolean;
  lastSync: { submitted: number; accepted: number; failed: number } | null;
  rule: string;
  fraudModel: string;
}

export interface Attestation {
  deviceId: string;
  securityLevel: string;
  eatProfile: string;
  ruleSha256: string;
  selfCheck: boolean;
  caveats: string[];
}

export interface WalletApi {
  status(): Promise<WalletStatus>;
  payOffline(payee: string, amountMinor: number): Promise<Payment>;
  sync(): Promise<WalletStatus>;
  attestation(): Promise<Attestation>;
}

const tauri: WalletApi = {
  status: () => invoke("wallet_status"),
  payOffline: (payee, amountMinor) => invoke("pay_offline", { payee, amountMinor }),
  sync: () => invoke("sync"),
  attestation: () => invoke("attestation"),
};

/** Browser stand-in: the same rules as the core's demo provisioning (offline rights 2,000.00, limit per payment). */
export function standIn(): WalletApi {
  const s: WalletStatus = {
    walletId: "wallet-demo", deviceId: "browser", currency: "INR", ledgerBalance: 1_000_000, rightsAvailable: 200_000,
    offlineSpent: 0, pendingCount: 0, payments: [], hubConfigured: false, lastSync: null,
    rule: "offline-limit (stand-in)", fraudModel: "none",
  };
  return {
    status: async () => structuredClone(s),
    payOffline: async (payee, amountMinor) => {
      if (!payee.trim() || !Number.isInteger(amountMinor) || amountMinor <= 0) throw new Error("payee and a positive amount are required");
      if (amountMinor > s.rightsAvailable) throw new Error(`not enough offline spending rights: need ${amountMinor}, hold ${s.rightsAvailable}`);
      const p: Payment = { id: `pay-${s.payments.length + 1}`, payee, amountMinor, currency: s.currency, createdMs: Date.now(), status: "PENDING" };
      s.payments.unshift(p);
      s.rightsAvailable -= amountMinor;
      s.offlineSpent += amountMinor;
      s.pendingCount++;
      return p;
    },
    sync: async () => {
      throw new Error("no hub configured (stand-in)");
    },
    attestation: async () => ({ deviceId: "browser", securityLevel: "none", eatProfile: "stand-in", ruleSha256: "", selfCheck: false, caveats: ["not running in the app: no key store"] }),
  };
}

export const api: WalletApi = isTauri() ? tauri : standIn();

export function money(minor: number, currency: string): string {
  return new Intl.NumberFormat("en-IN", { style: "currency", currency }).format(minor / 100);
}
