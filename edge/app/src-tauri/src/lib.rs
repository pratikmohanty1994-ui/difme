//! Tauri commands over the wallet core (edge/core). The UI (edge/app/src/api.ts) calls them by name; errors reach it
//! as their message. The core's state lives in the app's data directory (automerge document, sealed key store).

use difme_edge_core::{AttestationStatus, EdgeConfig, EdgeCore, WalletStatus, wallet::PaymentRecord};
use tauri::{Manager, State};
use tokio::sync::Mutex;

struct Core(Mutex<EdgeCore>);

fn err(e: impl std::fmt::Display) -> String {
    e.to_string()
}

#[tauri::command]
async fn wallet_status(core: State<'_, Core>) -> Result<WalletStatus, String> {
    Ok(core.0.lock().await.status())
}

#[tauri::command]
async fn pay_offline(core: State<'_, Core>, payee: String, amount_minor: i64) -> Result<PaymentRecord, String> {
    if payee.trim().is_empty() || amount_minor <= 0 {
        return Err("payee and a positive amount are required".into());
    }
    core.0.lock().await.pay_offline(payee.trim(), amount_minor).map_err(err)
}

#[tauri::command]
async fn sync(core: State<'_, Core>) -> Result<WalletStatus, String> {
    let mut c = core.0.lock().await;
    c.sync().await.map_err(err)?;
    Ok(c.status())
}

#[tauri::command]
async fn attestation(core: State<'_, Core>) -> Result<AttestationStatus, String> {
    core.0.lock().await.attestation().map_err(err)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let cfg = EdgeConfig { data_dir: Some(app.path().app_data_dir()?), ..EdgeConfig::default() };
            app.manage(Core(Mutex::new(EdgeCore::open(cfg).map_err(|e| e.to_string())?)));
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![wallet_status, pay_offline, sync, attestation])
        .run(tauri::generate_context!())
        .expect("DIFME wallet failed to start");
}
