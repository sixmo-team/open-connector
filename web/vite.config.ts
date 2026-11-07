import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { fileURLToPath, URL } from "node:url";
import { defineConfig } from "vite";
import { providerIconsPlugin } from "./provider-icons-plugin.ts";

export default defineConfig({
  base: "/integration-console/",
  plugins: [react(), tailwindcss(), providerIconsPlugin()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
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
