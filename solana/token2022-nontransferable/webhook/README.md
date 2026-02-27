# SPL Token-2022 SBT Mint Webhook

This is a minimal HTTP service that mints a **non-transferable** Token-2022 SBT to a wallet address. It is designed to be called by the Sitebuilder Worker via a signed webhook.

## Install
```bash
cd solana/token2022-nontransferable/webhook
npm install
```

## Environment
```bash
export SOLANA_RPC_URL="https://api.mainnet-beta.solana.com"
export SOLANA_SBT_MINT="<your_token2022_mint_address>"
export SOLANA_MINT_AUTHORITY_PATH="/path/to/mint-authority.json"
export SOLANA_SBT_WEBHOOK_SECRET="<shared_secret>"
```

`SOLANA_MINT_AUTHORITY_PATH` should point to a standard Solana keypair JSON file.

## Run
```bash
npm start
```

## Request
`POST /mint`
```json
{
  "wallet_address": "<solana_wallet>"
}
```

### Signed headers
The Worker sends:
- `x-sitebuilder-timestamp`
- `x-sitebuilder-signature`

Signature is HMAC‑SHA256 over `${timestamp}.${raw_body}` with `SOLANA_SBT_WEBHOOK_SECRET`.

## Notes
- If the recipient already has a token, this returns `already_minted: true`.
- The mint must already be created with the NonTransferable extension.
