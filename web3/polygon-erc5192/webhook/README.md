# Polygon ERC-5192 SBT Mint Webhook

This is a minimal HTTP service that mints the ERC‑5192 SBT to a wallet. It is designed to be called by the Sitebuilder Worker via a signed webhook.

## Install
```bash
cd web3/polygon-erc5192/webhook
npm install
```

## Environment
```bash
export POLYGON_RPC_URL="https://rpc-amoy.polygon.technology"
export POLYGON_CHAIN_ID=80002
export POLYGON_SBT_CONTRACT="0xYourSbtContract"
export POLYGON_SBT_MINTER_KEY="0xYourPrivateKey"
export POLYGON_SBT_WEBHOOK_SECRET="<shared_secret>"
```

## Run
```bash
npm start
```

## Request
`POST /mint`
```json
{
  "wallet_address": "0x..."
}
```

### Signed headers
The Worker sends:
- `x-sitebuilder-timestamp`
- `x-sitebuilder-signature`

Signature is HMAC‑SHA256 over `${timestamp}.${raw_body}` with `POLYGON_SBT_WEBHOOK_SECRET`.
