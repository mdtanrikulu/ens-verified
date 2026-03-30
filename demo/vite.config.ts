import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { nodePolyfills } from "vite-plugin-node-polyfills";

export default defineConfig({
  base: "/ens-verified/",
  plugins: [
    react(),
    nodePolyfills({
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
      protocolImports: false,
      exclude: ["stream"],
    }),
  ],
  define: {
    "process.env": {},
  },
  resolve: {
    dedupe: ["viem"],
  },
  optimizeDeps: {
    include: ["snarkjs"],
    esbuildOptions: {
      target: "esnext",
    },
  },
  build: {
    target: "esnext",
    commonjsOptions: {
      transformMixedEsModules: true,
    },
  },
});
