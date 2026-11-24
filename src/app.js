// x402 token preflight check API.
//
// - GET /        free: service description JSON
// - GET /check   paid: $0.04 USDC on Base via x402 (exact scheme),
//                facilitated by PayAI (no account / API key needed for the
//                free tier). Receiving address is a receive-only agent
//                wallet; this service never signs anything.
//
// Runs unchanged on Node (@hono/node-server), Cloudflare Workers and
// Deno Deploy — see worker.js / node-server.js entry points.

import { Hono } from "hono";
import { paymentMiddleware, x402ResourceServer } from "@x402/hono";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { CHAINS, checkToken } from "./check.js";

export const PAY_TO = "0x384F27a30557b4d19bD54dAb196D170F429C6D90";
export const PRICE = "$0.04";
export const NETWORK = "eip155:8453"; // Base mainnet
export const FACILITATOR_URL = "https://facilitator.payai.network";

const ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;

const SERVICE_INFO = {
  name: "Token Preflight Check",
  description:
    "Deterministic on-chain preflight check for an ERC-20 token: metadata, proxy detection (EIP-1967 and ZeppelinOS), owner, and a bytecode scan for admin-control functions (mint, pause, blacklist, freeze, fee control, transfer restriction, upgrade). Returns structured JSON with flags and a verdict.",
  paidEndpoint: {
    method: "GET",
    path: "/check",
    query: {
      chain: "base | ethereum",
      token: "0x… ERC-20 contract address",
    },
    price: PRICE,
    currency: "USDC",
    network: NETWORK,
    payTo: PAY_TO,
    protocol: "x402 (exact scheme), facilitated by PayAI",
    example: "/check?chain=base&token=0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  },
  supportedCheckChains: Object.keys(CHAINS),
};

export function createApp() {
  const app = new Hono();

  const facilitator = new HTTPFacilitatorClient({ url: FACILITATOR_URL });
  const resourceServer = new x402ResourceServer(facilitator).register(
    NETWORK,
    new ExactEvmScheme(),
  );

  app.get("/", (c) => c.json(SERVICE_INFO));

  // Validate input BEFORE the payment middleware, so malformed requests
  // are rejected with 400 instead of being charged.
  app.use("/check", async (c, next) => {
    const chain = c.req.query("chain");
    const token = c.req.query("token");
    if (!chain || !(chain in CHAINS)) {
      return c.json({ error: "invalid_chain", message: "chain must be one of: base, ethereum" }, 400);
    }
    if (!token || !ADDRESS_RE.test(token)) {
      return c.json({ error: "invalid_token", message: "token must be a 0x-prefixed 40-hex address" }, 400);
    }
    await next();
  });

  app.use(
    paymentMiddleware(
      {
        "GET /check": {
          accepts: {
            scheme: "exact",
            price: PRICE,
            network: NETWORK,
            payTo: PAY_TO,
          },
          description: SERVICE_INFO.description,
          mimeType: "application/json",
        },
      },
      resourceServer,
    ),
  );

  app.get("/check", async (c) => {
    const chain = c.req.query("chain");
    const token = c.req.query("token");
    try {
      const result = await checkToken(chain, token);
      return c.json(result, result.error ? 422 : 200);
    } catch (err) {
      return c.json(
        { error: "upstream_rpc_failure", message: String(err?.message || err) },
        502,
      );
    }
  });

  return app;
}
