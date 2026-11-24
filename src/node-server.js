// Node.js entry point (also used for local verification).
import { serve } from "@hono/node-server";
import { createApp } from "./app.js";

const port = Number(process.env.PORT || 4021);
const app = createApp();
serve({ fetch: app.fetch, port }, (info) => {
  console.log(`x402 token preflight listening on http://localhost:${info.port}`);
});
