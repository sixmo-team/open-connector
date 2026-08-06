import tailwindcss from "@tailwindcss/vite";
import { presetIcons } from "@unocss/preset-icons";
import UnoCSS from "@unocss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import { providerIconsPlugin } from "./provider-icons-plugin";

const localAdminBff = "http://127.0.0.1:4400";

export default defineConfig({
  base: "/integration-console/",
  plugins: [react(), tailwindcss(), UnoCSS({ presets: [presetIcons()] }), providerIconsPlugin({ iconUrls: {} })],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    port: 5174,
    proxy: {
      "/internal/integration-admin": localAdminBff,
    },
  },
  preview: {
    proxy: {
      "/internal/integration-admin": localAdminBff,
    },
  },
  build: {
    outDir: "../dist/web-saas",
    emptyOutDir: true,
    rollupOptions: {
      input: fileURLToPath(new URL("./saas.html", import.meta.url)),
      output: {
        manualChunks(id) {
          if (id.includes("/node_modules/recharts/")) return "charts";
        },
      },
    },
  },
});
