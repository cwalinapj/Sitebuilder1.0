#!/usr/bin/env bash
set -euo pipefail

APP_DIR=${APP_DIR:-/opt/sitebuilder/solana-sbt-webhook}
ENV_FILE=${ENV_FILE:-/etc/sitebuilder/solana-sbt-webhook.env}
SERVICE_NAME=${SERVICE_NAME:-sitebuilder-solana-sbt}

if [[ $EUID -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

mkdir -p "$APP_DIR"
rsync -a --delete "$(dirname "$0")/../solana/token2022-nontransferable/webhook/" "$APP_DIR/"

if [[ ! -f "$ENV_FILE" ]]; then
  cat > "$ENV_FILE" <<ENVVARS
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
SOLANA_SBT_MINT=
SOLANA_MINT_AUTHORITY_PATH=
SOLANA_SBT_WEBHOOK_SECRET=
ENVVARS
  chmod 600 "$ENV_FILE"
fi

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<UNIT
[Unit]
Description=Sitebuilder Solana SBT Webhook
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/node ${APP_DIR}/server.js
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

cd "$APP_DIR"
/usr/bin/npm install --omit=dev
systemctl daemon-reload
systemctl enable --now "${SERVICE_NAME}.service"

echo "Solana webhook running. Edit ${ENV_FILE} and restart if needed."
