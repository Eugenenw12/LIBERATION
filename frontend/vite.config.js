import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// If you serve from a subpath later, set base accordingly.
// For root domain deploys, "/" is fine.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist"
  }
});
