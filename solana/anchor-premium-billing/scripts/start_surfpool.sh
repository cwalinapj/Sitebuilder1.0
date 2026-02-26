#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

surfpool start --manifest-file-path "$ROOT_DIR/txtx.yml" --network devnet
