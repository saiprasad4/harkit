import { defineConfig } from "astro/config";
import react from "@astrojs/react";

// Static site: the page prerenders, the sanitizer hydrates as a React island.
// Everything the tool does runs client-side, so a plain static dist/ is all we ship.
export default defineConfig({
  site: "https://sealedhar.pages.dev",
  integrations: [react()],
});
