import { defineConfig } from "vitest/config";
import vue from "@vitejs/plugin-vue";

// Tauri serves the built UI from dist/ and uses this dev server during `tauri dev` (src-tauri/tauri.conf.json).
export default defineConfig({
  plugins: [vue()],
  clearScreen: false,
  server: { port: 1420, strictPort: true },
  test: { environment: "happy-dom" },
});
