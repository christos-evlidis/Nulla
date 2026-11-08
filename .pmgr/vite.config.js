import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const pmgrDir = path.dirname(fileURLToPath(import.meta.url));
const pmgrModules = path.join(pmgrDir, "node_modules");
const srcRoot = path.resolve(pmgrDir, "../project/src");

export default defineConfig({
  root: "../project/src",
  resolve: {
    alias: {
      "@": srcRoot,
      "@fortawesome/fontawesome-free": path.join(pmgrModules, "@fortawesome/fontawesome-free"),
    },
  },
  build: {
    outDir: "../../.pmgr/dist",
    emptyOutDir: true,
    minify: false,
    rollupOptions: {
      output: {
        compact: false,
        entryFileNames: "js/[name].js",
        chunkFileNames: "js/[name].js",
        assetFileNames: (assetInfo) => {
          const name = assetInfo.names?.[0] ?? assetInfo.name ?? "";
          if (name.endsWith(".css")) {
            return "css/[name][extname]";
          }
          return "assets/[name][extname]";
        },
      },
    },
  },
  server: {
    port: 5173,
    strictPort: true,
    hmr: {
      port: 5173,
    },
  },
});

