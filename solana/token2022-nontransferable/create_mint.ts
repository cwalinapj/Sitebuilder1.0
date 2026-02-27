import { getCreateAccountInstruction } from "@solana-program/system";
import {
  extension,
  findAssociatedTokenPda,
  getCreateAssociatedTokenInstructionAsync,
  getInitializeMintInstruction,
  getInitializeNonTransferableMintInstruction,
  getMintSize,
  TOKEN_2022_PROGRAM_ADDRESS,
} from "@solana-program/token-2022";
import {
  airdropFactory,
  appendTransactionMessageInstructions,
  createSolanaRpc,
  createSolanaRpcSubscriptions,
  createTransactionMessage,
  generateKeyPairSigner,
  getSignatureFromTransaction,
  lamports,
  pipe,
  sendAndConfirmTransactionFactory,
  setTransactionMessageFeePayerSigner,
  setTransactionMessageLifetimeUsingBlockhash,
  signTransactionMessageWithSigners,
} from "@solana/kit";

// Minimal non-transferable mint creation (Token-2022)
// RPC defaults to local validator; set SOLANA_RPC / SOLANA_WS to override.
const rpcUrl = process.env.SOLANA_RPC || "http://127.0.0.1:8899";
const wsUrl = process.env.SOLANA_WS || "ws://127.0.0.1:8900";

async function main() {
  const rpc = createSolanaRpc(rpcUrl);
  const rpcSubscriptions = createSolanaRpcSubscriptions(wsUrl);

  const authority = await generateKeyPairSigner();
  await airdropFactory({ rpc, rpcSubscriptions })({
    recipientAddress: authority.address,
    lamports: lamports(5_000_000_000n),
    commitment: "confirmed",
  });

  const mint = await generateKeyPairSigner();
  const nonTransferableExtension = extension("NonTransferable", {});
  const space = BigInt(getMintSize([nonTransferableExtension]));
  const rent = await rpc.getMinimumBalanceForRentExemption(space).send();
  const { value: latestBlockhash } = await rpc.getLatestBlockhash().send();

  const createMintAccountInstruction = getCreateAccountInstruction({
    payer: authority,
    newAccount: mint,
    lamports: rent,
    space,
    programAddress: TOKEN_2022_PROGRAM_ADDRESS,
  });

  const initializeNonTransferableInstruction = getInitializeNonTransferableMintInstruction({
    mint: mint.address,
  });

  const initializeMintInstruction = getInitializeMintInstruction({
    mint: mint.address,
    decimals: 0,
    mintAuthority: authority.address,
    freezeAuthority: authority.address,
  });

  const [associatedTokenAddress] = await findAssociatedTokenPda({
    mint: mint.address,
    owner: authority.address,
    tokenProgram: TOKEN_2022_PROGRAM_ADDRESS,
  });

  const createAtaInstruction = await getCreateAssociatedTokenInstructionAsync({
    payer: authority,
    mint: mint.address,
    owner: authority.address,
  });

  const instructions = [
    createMintAccountInstruction,
    initializeNonTransferableInstruction,
    initializeMintInstruction,
    createAtaInstruction,
  ];

  const transactionMessage = pipe(
    createTransactionMessage({ version: 0 }),
    (tx) => setTransactionMessageFeePayerSigner(authority, tx),
    (tx) => setTransactionMessageLifetimeUsingBlockhash(latestBlockhash, tx),
    (tx) => appendTransactionMessageInstructions(instructions, tx)
  );

  const signedTransaction = await signTransactionMessageWithSigners(transactionMessage);
  await sendAndConfirmTransactionFactory({ rpc, rpcSubscriptions })(
    signedTransaction,
    { commitment: "confirmed", skipPreflight: true }
  );

  const transactionSignature = getSignatureFromTransaction(signedTransaction);
  console.log("Mint Address:", mint.address);
  console.log("ATA Address:", associatedTokenAddress);
  console.log("Transaction Signature:", transactionSignature);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
