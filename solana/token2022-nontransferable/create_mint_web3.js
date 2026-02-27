import fs from "node:fs";
import { Connection, Keypair, SystemProgram, Transaction, sendAndConfirmTransaction } from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  ExtensionType,
  getMintLen,
  createInitializeNonTransferableMintInstruction,
  createInitializeMintInstruction,
  getAssociatedTokenAddressSync,
  createAssociatedTokenAccountIdempotentInstruction,
} from "@solana/spl-token";

const RPC_URL = process.env.SOLANA_RPC_URL || "https://api.mainnet-beta.solana.com";
const AUTHORITY_PATH = process.env.SOLANA_MINT_AUTHORITY_PATH || "";
const AUTHORITY_JSON = process.env.SOLANA_MINT_AUTHORITY_JSON || "";
const DECIMALS = Number(process.env.SOLANA_MINT_DECIMALS || 0);
const CREATE_ATA = String(process.env.SOLANA_CREATE_ATA || "true").toLowerCase() !== "false";

function loadAuthority() {
  if (AUTHORITY_JSON) {
    const arr = JSON.parse(AUTHORITY_JSON);
    return Keypair.fromSecretKey(Uint8Array.from(arr));
  }
  if (AUTHORITY_PATH && fs.existsSync(AUTHORITY_PATH)) {
    const arr = JSON.parse(fs.readFileSync(AUTHORITY_PATH, "utf8"));
    return Keypair.fromSecretKey(Uint8Array.from(arr));
  }
  throw new Error("Provide SOLANA_MINT_AUTHORITY_PATH or SOLANA_MINT_AUTHORITY_JSON");
}

async function main() {
  const connection = new Connection(RPC_URL, "confirmed");
  const payer = loadAuthority();
  const mintKeypair = Keypair.generate();

  const extensions = [ExtensionType.NonTransferable];
  const mintLen = getMintLen(extensions);
  const rentLamports = await connection.getMinimumBalanceForRentExemption(mintLen);

  const tx = new Transaction();
  tx.add(
    SystemProgram.createAccount({
      fromPubkey: payer.publicKey,
      newAccountPubkey: mintKeypair.publicKey,
      space: mintLen,
      lamports: rentLamports,
      programId: TOKEN_2022_PROGRAM_ID,
    })
  );
  tx.add(createInitializeNonTransferableMintInstruction(mintKeypair.publicKey, TOKEN_2022_PROGRAM_ID));
  tx.add(
    createInitializeMintInstruction(
      mintKeypair.publicKey,
      DECIMALS,
      payer.publicKey,
      payer.publicKey,
      TOKEN_2022_PROGRAM_ID
    )
  );

  let ata = null;
  if (CREATE_ATA) {
    ata = getAssociatedTokenAddressSync(
      mintKeypair.publicKey,
      payer.publicKey,
      false,
      TOKEN_2022_PROGRAM_ID,
      ASSOCIATED_TOKEN_PROGRAM_ID
    );
    tx.add(
      createAssociatedTokenAccountIdempotentInstruction(
        payer.publicKey,
        ata,
        payer.publicKey,
        mintKeypair.publicKey,
        TOKEN_2022_PROGRAM_ID,
        ASSOCIATED_TOKEN_PROGRAM_ID
      )
    );
  }

  const sig = await sendAndConfirmTransaction(connection, tx, [payer, mintKeypair]);
  console.log("Mint:", mintKeypair.publicKey.toBase58());
  if (ata) console.log("ATA:", ata.toBase58());
  console.log("Tx:", sig);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
