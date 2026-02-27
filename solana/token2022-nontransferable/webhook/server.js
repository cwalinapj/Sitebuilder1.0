import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import { Connection, Keypair, PublicKey, Transaction } from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  getAssociatedTokenAddressSync,
  createAssociatedTokenAccountIdempotentInstruction,
  createMintToInstruction,
} from "@solana/spl-token";

const PORT = Number(process.env.PORT || 8788);
const RPC_URL = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
const MINT_ADDRESS = String(process.env.SOLANA_SBT_MINT || "").trim();
const AUTHORITY_JSON = process.env.SOLANA_MINT_AUTHORITY_JSON || "";
const AUTHORITY_PATH = process.env.SOLANA_MINT_AUTHORITY_PATH || "";
const SHARED_SECRET = process.env.SOLANA_SBT_WEBHOOK_SECRET || "";
const MAX_SKEW_MS = 5 * 60 * 1000;

function json(res, status, payload) {
  res.writeHead(status, { "content-type": "application/json" });
  res.end(JSON.stringify(payload, null, 2));
}

function loadAuthorityKeypair() {
  if (AUTHORITY_JSON) {
    const arr = JSON.parse(AUTHORITY_JSON);
    return Keypair.fromSecretKey(Uint8Array.from(arr));
  }
  if (AUTHORITY_PATH && fs.existsSync(AUTHORITY_PATH)) {
    const arr = JSON.parse(fs.readFileSync(AUTHORITY_PATH, "utf8"));
    return Keypair.fromSecretKey(Uint8Array.from(arr));
  }
  throw new Error("Missing SOLANA_MINT_AUTHORITY_JSON or SOLANA_MINT_AUTHORITY_PATH");
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

async function mintSbt({ wallet }) {
  if (!MINT_ADDRESS) throw new Error("SOLANA_SBT_MINT is required");
  const payer = loadAuthorityKeypair();
  const connection = new Connection(RPC_URL, "confirmed");
  const mint = new PublicKey(MINT_ADDRESS);
  const owner = new PublicKey(wallet);

  const ata = getAssociatedTokenAddressSync(mint, owner, false, TOKEN_2022_PROGRAM_ID, ASSOCIATED_TOKEN_PROGRAM_ID);
  const ataInfo = await connection.getAccountInfo(ata, "confirmed");
  if (ataInfo) {
    try {
      const bal = await connection.getTokenAccountBalance(ata, "confirmed");
      if (Number(bal?.value?.amount || 0) > 0) {
        return { already_minted: true, ata: ata.toBase58() };
      }
    } catch {
      // Continue if balance check fails.
    }
  }

  const tx = new Transaction();
  tx.add(
    createAssociatedTokenAccountIdempotentInstruction(
      payer.publicKey,
      ata,
      owner,
      mint,
      TOKEN_2022_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    )
  );
  tx.add(
    createMintToInstruction(
      mint,
      ata,
      payer.publicKey,
      1,
      [],
      TOKEN_2022_PROGRAM_ID
    )
  );

  const signature = await connection.sendTransaction(tx, [payer], { skipPreflight: false });
  await connection.confirmTransaction(signature, "confirmed");
  return { txid: signature, ata: ata.toBase58() };
}

const server = http.createServer(async (req, res) => {
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
      const result = await mintSbt({ wallet });
      return json(res, 200, { ok: true, ...result });
    } catch (error) {
      return json(res, 500, { ok: false, error: String(error?.message || error) });
    }
  });
});

server.listen(PORT, () => {
  console.log(`SPL Token-2022 SBT webhook listening on :${PORT}`);
});
