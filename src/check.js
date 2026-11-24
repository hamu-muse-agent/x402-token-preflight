// Token preflight check: deterministic, stateless inspection of an ERC-20
// token contract via public JSON-RPC (no API keys).
//
// What it reads:
//   - ERC-20 metadata: name / symbol / decimals / totalSupply
//   - Ownable owner() (null when the call reverts or returns the zero address)
//   - EIP-1967 proxy slots (implementation + admin). When a proxy is found,
//     the implementation contract's bytecode is scanned as well.
//   - Bytecode selector scan for admin-control function families
//     (mint, pause, blacklist, freeze, fee control, transfer restriction,
//     upgrade). Selectors are derived from signature strings with a local
//     Keccak-256 implementation, so this table is exactly what it claims.
//
// Determinism: the output is a pure function of the on-chain state read.
// No timestamps, no randomness, sorted flag lists.

import { keccak256, selector, bytesToHex } from "./keccak.js";

// Public, key-less RPC endpoints. Multiple endpoints per chain are tried in
// order (they all serve the same chain state, so output is unaffected).
// Override with BASE_RPC_URL / ETH_RPC_URL (single URL) if needed.
export const CHAINS = {
  base: {
    chainId: 8453,
    rpcUrls: process.env.BASE_RPC_URL
      ? [process.env.BASE_RPC_URL]
      : ["https://mainnet.base.org", "https://base.drpc.org"],
  },
  ethereum: {
    chainId: 1,
    rpcUrls: process.env.ETH_RPC_URL
      ? [process.env.ETH_RPC_URL]
      : [
          "https://eth.drpc.org",
          "https://eth-mainnet.public.blastapi.io",
          "https://rpc.mevblocker.io",
        ],
  },
};

const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

// EIP-1967 slots: keccak256("eip1967.proxy.implementation") - 1, etc.
const IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const ADMIN_SLOT = "0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";

// ZeppelinOS / OpenZeppelin legacy proxy slots (used e.g. by Circle's
// FiatTokenProxy and Tether's proxy). Derived from the slot-name strings
// with the local Keccak implementation instead of hardcoding the digests.
const slotOf = (name) =>
  "0x" + bytesToHex(keccak256(new TextEncoder().encode(name)));
const ZOS_IMPL_SLOT = slotOf("org.zeppelinos.proxy.implementation");
const ZOS_OWNER_SLOT = slotOf("org.zeppelinos.proxy.owner");

// Well-known call selectors (derived, not hardcoded, except these four
// metadata calls which are asserted against keccak in the test suite too).
const SEL = {
  name: selector("name()"),
  symbol: selector("symbol()"),
  decimals: selector("decimals()"),
  totalSupply: selector("totalSupply()"),
  owner: selector("owner()"),
};

// signature -> risk family. Presence is detected by scanning deployed
// bytecode for the PUSH4 pattern of the derived selector.
const SIGNATURE_FAMILIES = {
  mint: [
    "mint(address,uint256)",
    "mint(uint256)",
    "mint(address)",
    "mint()",
    "issue(uint256)",
  ],
  pause: ["pause()", "unpause()", "paused()"],
  blacklist: [
    "blacklist(address)",
    "addBlacklist(address)",
    "addToBlacklist(address)",
    "addBlackList(address)",
    "removeBlacklist(address)",
    "isBlacklisted(address)",
    "isBlackList(address)",
    "destroyBlackFunds(address)",
  ],
  freeze: ["freeze(address)", "freezeAccount(address,bool)", "frozenAccount(address)"],
  fee_control: [
    "setFee(uint256)",
    "setFees(uint256)",
    "setFees(uint256,uint256)",
    "setTax(uint256)",
    "setTaxFeePercent(uint256)",
    "setBuyFee(uint256)",
    "setSellFee(uint256)",
    "setTxFee(uint256)",
    "setTransactionFee(uint256)",
    "excludeFromFee(address,bool)",
    "excludeFromFees(address,bool)",
  ],
  transfer_restriction: [
    "setMaxTxAmount(uint256)",
    "setMaxTx(uint256)",
    "setMaxWallet(uint256)",
    "setTradingEnabled(bool)",
    "setTransferLimit(uint256)",
  ],
  upgrade: ["upgradeTo(address)", "upgradeToAndCall(address,bytes)"],
  burn: ["burn(uint256)", "burnFrom(address,uint256)", "redeem(uint256)"],
};

// ---------------------------------------------------------------------------
// JSON-RPC plumbing (fetch only; retries cover transient network failures
// and never change the returned data).

async function rpcPost(chain, payload, timeoutMs) {
  const { rpcUrls } = CHAINS[chain];
  let lastError;
  // One pass over the endpoint list, then one retry pass.
  for (let attempt = 0; attempt < rpcUrls.length * 2; attempt++) {
    const rpcUrl = rpcUrls[attempt % rpcUrls.length];
    try {
      const res = await fetch(rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (!res.ok) throw new Error(`RPC HTTP ${res.status}`);
      return await res.json();
    } catch (err) {
      lastError = err;
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  throw lastError;
}

async function rpc(chain, method, params) {
  const body = await rpcPost(chain, { jsonrpc: "2.0", id: 1, method, params }, 20000);
  if (body.error) throw new Error(`RPC error: ${body.error.message || JSON.stringify(body.error)}`);
  return body.result;
}

// Batched reads: one HTTP request for many calls (public RPCs support
// JSON-RPC batching). Per-call errors resolve to null when allowError is
// set, mirroring ethCall semantics.
async function rpcBatch(chain, calls) {
  const payload = calls.map((c, i) => ({ jsonrpc: "2.0", id: i + 1, method: c.method, params: c.params }));
  try {
    const body = await rpcPost(chain, payload, 30000);
    if (!Array.isArray(body)) throw new Error("RPC batch response was not an array");
    const byId = new Map(body.map((r) => [r.id, r]));
    return calls.map((c, i) => {
      const r = byId.get(i + 1);
      if (!r || r.error) {
        if (c.allowError) return null;
        throw new Error(`RPC error: ${r?.error?.message || "missing batch result"}`);
      }
      return r.result;
    });
  } catch {
    // Some public endpoints reject batch requests outright; fall back to
    // individual calls (same data, more requests).
    return Promise.all(
      calls.map((c) =>
        rpc(chain, c.method, c.params).catch((err) => {
          if (c.allowError) return null;
          throw err;
        }),
      ),
    );
  }
}

const getCode = (chain, address) => rpc(chain, "eth_getCode", [address, "latest"]);

// ---------------------------------------------------------------------------
// ABI decoding helpers for the tiny set of return types we read.

function hexToBytes(hex) {
  const clean = hex.startsWith("0x") ? hex.slice(2) : hex;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function wordAt(bytes, index) {
  return bytes.slice(index * 32, index * 32 + 32);
}

function bytesToBigInt(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function decodeStringResult(hex) {
  if (!hex || hex === "0x") return null;
  const bytes = hexToBytes(hex);
  if (bytes.length === 32) {
    // Legacy bytes32-encoded symbol/name.
    const end = bytes.findIndex((b) => b === 0);
    const slice = end === -1 ? bytes : bytes.slice(0, end);
    try {
      return new TextDecoder().decode(slice);
    } catch {
      return null;
    }
  }
  if (bytes.length >= 64) {
    const offset = Number(bytesToBigInt(wordAt(bytes, 0)));
    if (offset + 32 <= bytes.length) {
      const len = Number(bytesToBigInt(bytes.slice(offset, offset + 32)));
      if (offset + 32 + len <= bytes.length) {
        return new TextDecoder().decode(bytes.slice(offset + 32, offset + 32 + len));
      }
    }
  }
  return null;
}

function decodeUintResult(hex) {
  if (!hex || hex === "0x") return null;
  return bytesToBigInt(hexToBytes(hex));
}

function decodeAddressResult(hex) {
  if (!hex || hex === "0x") return null;
  const bytes = hexToBytes(hex);
  if (bytes.length < 32) return null;
  const addr = "0x" + [...bytes.slice(12, 32)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return addr === ZERO_ADDRESS ? null : addr;
}

function addressFromStorage(hex) {
  if (!hex || hex === "0x") return null;
  const bytes = hexToBytes(hex);
  if (bytes.length < 32) return null;
  const addr = "0x" + [...bytes.slice(12, 32)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return addr === ZERO_ADDRESS ? null : addr;
}

function formatUnits(raw, decimals) {
  const s = raw.toString().padStart(decimals + 1, "0");
  if (decimals === 0) return s;
  const intPart = s.slice(0, s.length - decimals);
  const fracPart = s.slice(s.length - decimals).replace(/0+$/, "");
  return fracPart ? `${intPart}.${fracPart}` : intPart;
}

// ---------------------------------------------------------------------------
// Bytecode selector scan. Matches the PUSH4 (0x63) immediate pattern; a
// selector can also appear inside unrelated constant data, so results are
// reported as "signals", and the verdict wording says so.

function scanSelectors(codeHex) {
  const code = hexToBytes(codeHex || "0x");
  const found = {};
  for (const [family, signatures] of Object.entries(SIGNATURE_FAMILIES)) {
    const hits = [];
    for (const sig of signatures) {
      const sel = hexToBytes("0x" + selector(sig));
      outer: for (let i = 0; i + 4 < code.length; i++) {
        if (code[i] !== 0x63) continue;
        for (let j = 0; j < 4; j++) {
          if (code[i + 1 + j] !== sel[j]) continue outer;
        }
        hits.push(sig);
        break;
      }
    }
    if (hits.length) found[family] = hits.sort();
  }
  return found;
}

function mergeSignals(a, b) {
  const out = { ...a };
  for (const [family, sigs] of Object.entries(b)) {
    out[family] = [...new Set([...(out[family] || []), ...sigs])].sort();
  }
  return out;
}

// ---------------------------------------------------------------------------

export async function checkToken(chain, tokenAddress) {
  const token = tokenAddress.toLowerCase();

  const code = await getCode(chain, token);
  if (!code || code === "0x") {
    return { error: "no_contract_code", chain, token, message: "No contract code at this address." };
  }

  const call = (data) => ({
    method: "eth_call",
    params: [{ to: token, data }, "latest"],
    allowError: true,
  });
  const slot = (s) => ({
    method: "eth_getStorageAt",
    params: [token, s, "latest"],
    allowError: true,
  });
  let [nameRaw, symbolRaw, decimalsRaw, supplyRaw, ownerRaw, implRaw, adminRaw, zosImplRaw, zosOwnerRaw] =
    await rpcBatch(chain, [
      call("0x" + SEL.name),
      call("0x" + SEL.symbol),
      call("0x" + SEL.decimals),
      call("0x" + SEL.totalSupply),
      call("0x" + SEL.owner),
      slot(IMPL_SLOT),
      slot(ADMIN_SLOT),
      slot(ZOS_IMPL_SLOT),
      slot(ZOS_OWNER_SLOT),
    ]);

  // Public RPCs occasionally drop individual calls; give every read one
  // individual second chance when it came back empty. (A null can also be
  // legitimate, e.g. an empty storage slot; one retry is cheap and keeps
  // results stable.)
  const retryRead = async (raw, method, params) =>
    raw ?? (await rpc(chain, method, params).catch(() => null));
  const callParams = (data) => [{ to: token, data }, "latest"];
  const slotParams = (s) => [token, s, "latest"];
  [nameRaw, symbolRaw, decimalsRaw, supplyRaw, ownerRaw, implRaw, adminRaw, zosImplRaw, zosOwnerRaw] =
    await Promise.all([
      retryRead(nameRaw, "eth_call", callParams("0x" + SEL.name)),
      retryRead(symbolRaw, "eth_call", callParams("0x" + SEL.symbol)),
      retryRead(decimalsRaw, "eth_call", callParams("0x" + SEL.decimals)),
      retryRead(supplyRaw, "eth_call", callParams("0x" + SEL.totalSupply)),
      retryRead(ownerRaw, "eth_call", callParams("0x" + SEL.owner)),
      retryRead(implRaw, "eth_getStorageAt", slotParams(IMPL_SLOT)),
      retryRead(adminRaw, "eth_getStorageAt", slotParams(ADMIN_SLOT)),
      retryRead(zosImplRaw, "eth_getStorageAt", slotParams(ZOS_IMPL_SLOT)),
      retryRead(zosOwnerRaw, "eth_getStorageAt", slotParams(ZOS_OWNER_SLOT)),
    ]);

  const decimals = decimalsRaw ? Number(bytesToBigInt(hexToBytes(decimalsRaw))) : null;
  const totalSupply = decodeUintResult(supplyRaw);
  const eip1967Impl = addressFromStorage(implRaw);
  const zosImpl = addressFromStorage(zosImplRaw);
  const implementation = eip1967Impl || zosImpl;
  const proxyStandard = eip1967Impl ? "EIP-1967" : zosImpl ? "ZeppelinOS" : null;
  const proxyAdmin =
    addressFromStorage(adminRaw) || addressFromStorage(zosOwnerRaw);

  const scannedContracts = [token];
  let signals = scanSelectors(code);
  if (implementation && implementation !== token) {
    const implCode = await getCode(chain, implementation).catch(() => "0x");
    if (implCode && implCode !== "0x") {
      scannedContracts.push(implementation);
      signals = mergeSignals(signals, scanSelectors(implCode));
    }
  }

  const owner = decodeAddressResult(ownerRaw);
  const has = (family) => Array.isArray(signals[family]) && signals[family].length > 0;

  const flags = [];
  if (implementation) flags.push(proxyStandard === "EIP-1967" ? "PROXY_EIP1967" : "PROXY_ZEPPELINOS");
  if (has("upgrade")) flags.push("UPGRADE_FUNCTION_PRESENT");
  if (has("mint")) flags.push("MINT_OR_ISSUE_FUNCTION_PRESENT");
  if (has("pause")) flags.push("PAUSABLE_FUNCTION_PRESENT");
  if (has("blacklist")) flags.push("BLACKLIST_FUNCTION_PRESENT");
  if (has("freeze")) flags.push("FREEZE_FUNCTION_PRESENT");
  if (has("fee_control")) flags.push("FEE_CONTROL_FUNCTION_PRESENT");
  if (has("transfer_restriction")) flags.push("TRANSFER_RESTRICTION_FUNCTION_PRESENT");
  if (has("burn")) flags.push("BURN_FUNCTION_PRESENT");
  flags.push(owner ? "OWNER_PRESENT" : "NO_OWNER");
  flags.sort();

  let verdict;
  let verdictSummary;
  if (has("blacklist") || has("freeze")) {
    verdict = "elevated_admin_control";
    verdictSummary =
      "Blacklist or freeze functions are present: an operator can block specific holders or their balances.";
  } else if (
    (has("mint") && owner) ||
    (has("pause") && owner) ||
    has("fee_control") ||
    has("transfer_restriction") ||
    has("upgrade")
  ) {
    verdict = "admin_controls_present";
    verdictSummary =
      "Admin-control functions are present (supply issuance, pausing, fee or transfer control, or upgradeability). Review who controls them before trusting the token.";
  } else if (owner) {
    verdict = "limited_admin_surface";
    verdictSummary =
      "An owner exists but no mint, pause, blacklist, freeze, fee-control, transfer-restriction or upgrade functions were detected.";
  } else {
    verdict = "minimal_admin_surface";
    verdictSummary =
      "No owner and no admin-control function signals detected in the scanned bytecode.";
  }

  return {
    service: "token-preflight-check",
    version: 1,
    chain,
    chainId: CHAINS[chain].chainId,
    token,
    tokenInfo: {
      name: decodeStringResult(nameRaw),
      symbol: decodeStringResult(symbolRaw),
      decimals,
      totalSupply: totalSupply !== null ? totalSupply.toString() : null,
      totalSupplyFormatted:
        totalSupply !== null && decimals !== null ? formatUnits(totalSupply, decimals) : null,
    },
    proxy: {
      isProxy: Boolean(implementation),
      standard: proxyStandard,
      implementation,
      admin: proxyAdmin,
    },
    owner,
    scannedContracts,
    functionSignals: signals,
    flags,
    verdict,
    verdictSummary,
    caveats:
      "Selector scan is a bytecode heuristic: a matched selector proves the function is very likely exposed; a missing selector does not prove absence (e.g. logic behind other proxy patterns or EIP-2535 diamond facets is not scanned).",
  };
}
