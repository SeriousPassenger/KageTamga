import { defineConfig } from "vitest/config";
import react from "@vitejs/plugin-react";

export default defineConfig({
  base: "./",
  plugins: [react()],
  build: {
    target: "es2023",
    sourcemap: false,
  },
  test: {
    environment: "node",
  },
});
