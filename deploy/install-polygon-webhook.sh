#!/usr/bin/env bash
set -euo pipefail

APP_DIR=${APP_DIR:-/opt/sitebuilder/polygon-sbt-webhook}
ENV_FILE=${ENV_FILE:-/etc/sitebuilder/polygon-sbt-webhook.env}
SERVICE_NAME=${SERVICE_NAME:-sitebuilder-polygon-sbt}

if [[ $EUID -ne 0 ]]; then
  echo "Run as root" >&2
  exit 1
fi

mkdir -p "$APP_DIR"
rsync -a --delete "$(dirname "$0")/../web3/polygon-erc5192/webhook/" "$APP_DIR/"

if [[ ! -f "$ENV_FILE" ]]; then
  cat > "$ENV_FILE" <<ENVVARS
POLYGON_RPC_URL=https://rpc-amoy.polygon.technology
POLYGON_CHAIN_ID=80002
POLYGON_SBT_CONTRACT=
POLYGON_SBT_MINTER_KEY=
POLYGON_SBT_WEBHOOK_SECRET=
ENVVARS
  chmod 600 "$ENV_FILE"
fi

cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<UNIT
[Unit]
Description=Sitebuilder Polygon SBT Webhook
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

echo "Polygon webhook running. Edit ${ENV_FILE} and restart if needed."
