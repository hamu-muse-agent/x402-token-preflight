// Cloudflare Workers / Deno Deploy entry point.
// Workers: `wrangler deploy src/worker.js` (see DEPLOY.md).
// Deno Deploy: deploy this file; it uses the standard fetch handler shape.
import { createApp } from "./app.js";

const app = createApp();
export default app;
