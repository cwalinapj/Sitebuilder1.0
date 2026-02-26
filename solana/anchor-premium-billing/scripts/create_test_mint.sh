#!/usr/bin/env bash
set -euo pipefail

RPC_URL="${1:-http://127.0.0.1:8899}"
DECIMALS="${DECIMALS:-6}"
INITIAL_SUPPLY="${INITIAL_SUPPLY:-1000000}"
OWNER_KEYPAIR="${OWNER_KEYPAIR:-$HOME/.config/solana/id.json}"

if ! command -v spl-token >/dev/null 2>&1; then
  echo "spl-token not found. Install Solana CLI first." >&2
  exit 1
fi

if ! command -v solana-keygen >/dev/null 2>&1; then
  echo "solana-keygen not found. Install Solana CLI first." >&2
  exit 1
fi

OWNER_PUBKEY="$(solana-keygen pubkey "$OWNER_KEYPAIR")"

echo "Using RPC: $RPC_URL"
echo "Owner: $OWNER_PUBKEY"

echo "Creating SPL mint..."
MINT_OUTPUT="$(spl-token --url "$RPC_URL" create-token --decimals "$DECIMALS" --owner "$OWNER_KEYPAIR")"
MINT="$(printf '%s\n' "$MINT_OUTPUT" | awk '/Creating token/ {print $3}')"
if [[ -z "$MINT" ]]; then
  echo "Failed to parse mint address from spl-token output:" >&2
  echo "$MINT_OUTPUT" >&2
  exit 1
fi

echo "Creating token account..."
ACCOUNT_OUTPUT="$(spl-token --url "$RPC_URL" create-account "$MINT" --owner "$OWNER_PUBKEY")"
TOKEN_ACCOUNT="$(printf '%s\n' "$ACCOUNT_OUTPUT" | awk '/Creating account/ {print $3}')"
if [[ -z "$TOKEN_ACCOUNT" ]]; then
  echo "Failed to parse token account from spl-token output:" >&2
  echo "$ACCOUNT_OUTPUT" >&2
  exit 1
fi

echo "Minting initial supply..."
spl-token --url "$RPC_URL" mint "$MINT" "$INITIAL_SUPPLY" "$TOKEN_ACCOUNT" >/dev/null

echo ""
echo "SPL test mint ready"
echo "MINT=$MINT"
echo "TOKEN_ACCOUNT=$TOKEN_ACCOUNT"
echo "OWNER_PUBKEY=$OWNER_PUBKEY"
echo "INITIAL_SUPPLY=$INITIAL_SUPPLY"
