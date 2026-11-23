// Desktop entry point; on mobile Tauri calls the library's entry point (lib.rs) directly.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    difme_edge_app_lib::run()
}
