import http from "node:http";
import crypto from "node:crypto";
import { createPublicClient, createWalletClient, http as httpTransport } from "viem";
import { privateKeyToAccount } from "viem/accounts";

const PORT = Number(process.env.PORT || 8790);
const RPC_URL = process.env.POLYGON_RPC_URL || "https://rpc-amoy.polygon.technology";
const CHAIN_ID = Number(process.env.POLYGON_CHAIN_ID || 80002);
const CONTRACT = String(process.env.POLYGON_SBT_CONTRACT || "").trim();
const MINTER_KEY = String(process.env.POLYGON_SBT_MINTER_KEY || "").trim();
const SHARED_SECRET = String(process.env.POLYGON_SBT_WEBHOOK_SECRET || "").trim();
const MAX_SKEW_MS = 5 * 60 * 1000;

const ABI = [
  {
    type: "function",
    name: "mint",
    stateMutability: "nonpayable",
    inputs: [{ name: "to", type: "address" }],
    outputs: [{ name: "tokenId", type: "uint256" }],
  },
];

function json(res, status, payload) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(payload, null, 2));
}

function normalizeKey(raw) {
  if (!raw) return "";
  return raw.startsWith("0x") ? raw : `0x${raw}`;
}

function verifySignature(rawBody, tsHeader, sigHeader) {
  if (!SHARED_SECRET) return true;
  if (!tsHeader || !sigHeader) return false;
  const ts = Number(tsHeader);
  if (!Number.isFinite(ts)) return false;
  if (Math.abs(Date.now() - ts) > MAX_SKEW_MS) return false;
  const expected = crypto
    .createHmac("sha256", SHARED_SECRET)
    .update(`${tsHeader}.${rawBody}`)
    .digest("hex");
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(sigHeader)));
}

async function mintSbt(to) {
  if (!CONTRACT) throw new Error("POLYGON_SBT_CONTRACT is required");
  if (!MINTER_KEY) throw new Error("POLYGON_SBT_MINTER_KEY is required");

  const chain = {
    id: CHAIN_ID,
    name: "Polygon",
    network: "polygon",
    nativeCurrency: { name: "POL", symbol: "POL", decimals: 18 },
    rpcUrls: { default: { http: [RPC_URL] } },
  };
  const account = privateKeyToAccount(normalizeKey(MINTER_KEY));
  const transport = httpTransport(RPC_URL);
  const walletClient = createWalletClient({ account, chain, transport });
  const publicClient = createPublicClient({ chain, transport });

  const hash = await walletClient.writeContract({
    address: CONTRACT,
    abi: ABI,
    functionName: "mint",
    args: [to],
  });
  const receipt = await publicClient.waitForTransactionReceipt({ hash });
  return { txid: hash, receipt };
}

const server = http.createServer((req, res) => {
  if (req.method !== "POST" || req.url !== "/mint") {
    return json(res, 404, { ok: false, error: "not_found" });
  }

  let raw = "";
  req.on("data", (chunk) => (raw += chunk));
  req.on("end", async () => {
    const tsHeader = req.headers["x-sitebuilder-timestamp"];
    const sigHeader = req.headers["x-sitebuilder-signature"];
    if (!verifySignature(raw, tsHeader, sigHeader)) {
      return json(res, 401, { ok: false, error: "invalid_signature" });
    }

    let body = null;
    try {
      body = JSON.parse(raw || "{}");
    } catch {
      return json(res, 400, { ok: false, error: "invalid_json" });
    }

    const wallet = String(body?.wallet_address || "").trim();
    if (!wallet) return json(res, 400, { ok: false, error: "wallet_address_required" });

    try {
      const result = await mintSbt(wallet);
      return json(res, 200, { ok: true, ...result });
    } catch (error) {
      return json(res, 500, { ok: false, error: String(error?.message || error) });
    }
  });
});

server.listen(PORT, () => {
  console.log(`Polygon SBT webhook listening on :${PORT}`);
});
