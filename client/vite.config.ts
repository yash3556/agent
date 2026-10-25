import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), "");
  const configuredApi = env.VITE_API_BASE_URL?.trim();
  const proxyTarget = env.VITE_API_PROXY_TARGET?.trim()
    || (configuredApi ? new URL(configuredApi, "http://127.0.0.1:3001").origin : "http://127.0.0.1:3001");

  return {
    plugins: [react()],
    server: {
      port: 5173,
      ...(proxyTarget ? { proxy: { "/api": { target: proxyTarget, changeOrigin: true } } } : {}),
    },
  };
});
