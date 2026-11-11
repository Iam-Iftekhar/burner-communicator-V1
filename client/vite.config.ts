import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

// libsodium-wrappers 0.7.16 ships an ESM entry that imports "./libsodium.mjs", which lives in the
// sibling `libsodium` package, so the ESM build fails to resolve. Use the package's CJS entry instead.
const sodiumCjs = fileURLToPath(new URL("./node_modules/libsodium-wrappers/dist/modules/libsodium-wrappers.js", import.meta.url));

export default defineConfig({
  resolve: { alias: { "libsodium-wrappers": sodiumCjs } },
  build: { target: "es2022", outDir: "dist" },
  server: { host: true, proxy: { "/ws": { target: "ws://127.0.0.1:8000", ws: true }, "/ice": "http://127.0.0.1:8000", "/identity": "http://127.0.0.1:8000" } },
  test: { environment: "node" },
});
