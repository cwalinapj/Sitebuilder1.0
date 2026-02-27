# Solana Token-2022 (Non-Transferable) Early Adopter Token

This folder provides a minimal script to create a **non-transferable** Token-2022 mint (SBT-style) using the official Token-2022 program and its NonTransferable extension.

## What this does
- Creates a Token-2022 mint with the NonTransferable extension.
- Creates the mint's Associated Token Account (ATA) for the authority.
- Logs the mint, ATA, and signature.

> This does **not** mint tokens to additional wallets. Non-transferable mints are typically used as soulbound badges (early adopter, verified user, etc.).

## Requirements
- Node 18+
- A Solana RPC endpoint (devnet or mainnet-beta)

## Install dependencies
```bash
cd solana/token2022-nontransferable
npm install
```

## Run (local validator default)
```bash
npm run create:local
```

## Run (mainnet/devnet via web3.js)
```bash
export SOLANA_RPC_URL="https://api.mainnet-beta.solana.com"
export SOLANA_MINT_AUTHORITY_PATH="/path/to/authority.json"
npm run create:web3
```

## Run (devnet or mainnet)
```bash
SOLANA_RPC=https://api.devnet.solana.com \
SOLANA_WS=wss://api.devnet.solana.com \
npm run create
```

## Files
- `create_mint.ts` — creates a non-transferable mint and its ATA.
- `webhook/` — optional mint webhook service (recommended so the Worker doesn't hold keys).

## Notes
- Token-2022 uses a different program id than the legacy SPL Token program.
- Token-2022 program id: `TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`.
- The NonTransferable extension prevents token transfers after minting.

## Next steps
- Add minting logic if you want to issue SBTs to wallets.
- Add on-chain metadata or use an off-chain registry for SBT meaning.
