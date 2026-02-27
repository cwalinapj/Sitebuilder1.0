# Polygon ERC-5192 (SBT) Early Adopter Token

This is a minimal ERC-5192 soulbound (non-transferable) token contract for Polygon.

## Contract
- `contracts/EarlyAdopterSBT.sol`

## Notes
- Non-transferable by design: any transfer after mint will revert.
- Approvals are disabled to prevent operator-based transfer attempts.
- Minting is `onlyOwner`.

## Webhook mint service
Use the included webhook server if you don't want to mint from the Worker:
- `webhook/` contains a small Node service that mints the SBT on request.

## Deploy (Foundry example)
```bash
forge create \
  --rpc-url $POLYGON_RPC_URL \
  --private-key $DEPLOYER_PRIVATE_KEY \
  web3/polygon-erc5192/contracts/EarlyAdopterSBT.sol:EarlyAdopterSBT \
  --constructor-args "Sitebuilder Early Adopter" "SBEA" "https://your-domain.com/metadata/"
```

## Metadata
- Use a standard ERC-721 metadata base URI. Tokens are still NFTs, but they are soulbound.

## Reward usage
- Store on-chain proofs for early adopter rewards without enabling transfers or farming.
