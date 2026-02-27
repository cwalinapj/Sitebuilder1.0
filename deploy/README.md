# Webhook Deployment (Systemd)

These scripts install the Polygon + Solana mint webhooks as systemd services.

## Requirements
- Ubuntu/Debian VPS
- Node 18+ in `/usr/bin/node`
- `rsync` installed

## Install Polygon webhook
```bash
sudo ./deploy/install-polygon-webhook.sh
```
Edit `/etc/sitebuilder/polygon-sbt-webhook.env` and restart:
```bash
sudo systemctl restart sitebuilder-polygon-sbt
```

## Install Solana webhook
```bash
sudo ./deploy/install-solana-webhook.sh
```
Edit `/etc/sitebuilder/solana-sbt-webhook.env` and restart:
```bash
sudo systemctl restart sitebuilder-solana-sbt
```

## Logs
```bash
sudo journalctl -u sitebuilder-polygon-sbt -f
sudo journalctl -u sitebuilder-solana-sbt -f
```
