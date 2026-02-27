#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${POLYGON_RPC_URL:-}" ]]; then
  echo "POLYGON_RPC_URL is required" >&2
  exit 1
fi
if [[ -z "${DEPLOYER_PRIVATE_KEY:-}" ]]; then
  echo "DEPLOYER_PRIVATE_KEY is required" >&2
  exit 1
fi

forge create \
  --rpc-url "$POLYGON_RPC_URL" \
  --private-key "$DEPLOYER_PRIVATE_KEY" \
  web3/polygon-erc5192/contracts/EarlyAdopterSBT.sol:EarlyAdopterSBT \
  --constructor-args "Sitebuilder Early Adopter" "SBEA" "https://your-domain.com/metadata/"
