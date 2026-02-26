# Anchor Premium Billing Program

This workspace adds an on-chain SPL billing rail for premium usage and is Surfpool-ready.

## What this program does

- Holds project SPL in a PDA-controlled vault.
- Grants free SPL credits for a wallet+session (one-time per wallet/session hash).
- Charges SPL from user wallet for premium usage.
- Records per-session totals (granted, spent, points-equivalent).

## Program accounts

1. `PremiumConfig` PDA (`seed = ["config"]`)
- `authority`: backend/admin signer
- `mint`: SPL mint used for premium billing
- `vault`: PDA ATA for `mint`
- `free_grant_amount`: default free grant in raw token units
- `points_per_token`: internal conversion for analytics
- `paused`: emergency switch

2. `SessionLedger` PDA (`seed = ["ledger", config, user, session_hash]`)
- Stores one ledger per `wallet + session_hash`.
- Prevents duplicate free grant for same wallet/session.

## Instructions

1. `initialize_config(free_grant_amount, points_per_token)`
2. `update_config(free_grant_amount, points_per_token, paused)`
3. `grant_free_session(session_hash, grant_amount)` (authority signs)
4. `charge_premium(session_hash, token_amount, points_equivalent)` (user signs)
5. `withdraw_from_vault(amount)` (authority signs)

## Surfpool + Anchor quickstart

1. Build the Anchor program:

```bash
cd solana/anchor-premium-billing
anchor build
```

2. Start Surfpool (mainnet/devnet forked local simnet, RPC on `127.0.0.1:8899` by default):

```bash
./scripts/start_surfpool.sh
```

3. In another terminal, deploy the program runbook:

```bash
cd solana/anchor-premium-billing
surfpool run deployment --manifest-file-path ./txtx.yml --env localnet
```

4. Create a test SPL mint for Sitebuilder premium testing:

```bash
cd solana/anchor-premium-billing
./scripts/create_test_mint.sh http://127.0.0.1:8899
```

Set optional env before running mint script:

```bash
export DECIMALS=6
export INITIAL_SUPPLY=1000000
export OWNER_KEYPAIR=~/.config/solana/id.json
```

The script prints:
- `MINT=<mint_pubkey>`
- `TOKEN_ACCOUNT=<owner_token_account>`

Use that `MINT` when initializing `PremiumConfig`.

## Suggested backend flow (current Worker)

1. Wallet user starts session and signs challenge in worker.
2. Worker computes `session_hash = sha256(session_id)`.
3. Backend authority submits `grant_free_session(session_hash, 0)`.
4. For premium run:
- UI asks user to sign `charge_premium(session_hash, token_amount, points_equivalent)`.
- Worker verifies tx success and continues generation.

## Non-wallet users (points mode)

Keep points off-chain in Worker/D1 as you already do. Do not expose point-token conversion publicly.

## Build

```bash
cd solana/anchor-premium-billing
anchor build
```

## Test

```bash
cd solana/anchor-premium-billing
anchor test
```

## Notes

- Replace placeholder `declare_id!` before mainnet deploy.
- Use a dedicated mint and decimals policy for predictable billing units.
- For production, require backend signing policy + strict tx verification in worker.
