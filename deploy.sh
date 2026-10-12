#!/usr/bin/env bash
# Deploy (or redeploy) the app on a single Linux server, e.g. an AWS EC2
# instance running Amazon Linux 2023. Run from the repo root on the server:
#
#   ./deploy.sh                      # HTTPS at <public-ip>.sslip.io
#   DOMAIN=login.example.com ./deploy.sh   # your own domain (DNS A record -> server)
#
# Safe to re-run: it installs what's missing, pulls the latest code and
# rebuilds. Accounts (./data) and uploads (./uploads) are kept.
set -euo pipefail
cd "$(dirname "$0")"

log() { printf '\n==> %s\n' "$*"; }

# --- Docker, Compose and Buildx --------------------------------------------
if ! command -v docker >/dev/null 2>&1; then
  log "Installing Docker"
  if command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y docker git
  else
    curl -fsSL https://get.docker.com | sudo sh
  fi
  sudo systemctl enable --now docker
fi

ARCH=$(uname -m)
case "$ARCH" in
  x86_64) BIN_ARCH=amd64 ;;
  aarch64) BIN_ARCH=arm64 ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac
PLUGIN_DIR=/usr/local/lib/docker/cli-plugins

if ! sudo docker compose version >/dev/null 2>&1; then
  log "Installing Docker Compose plugin"
  sudo mkdir -p "$PLUGIN_DIR"
  sudo curl -fsSL -o "$PLUGIN_DIR/docker-compose" \
    "https://github.com/docker/compose/releases/latest/download/docker-compose-linux-$ARCH"
  sudo chmod +x "$PLUGIN_DIR/docker-compose"
fi

# Compose needs Buildx >= 0.17; distro Docker packages often ship older ones.
# Plugins in $PLUGIN_DIR take precedence over the distro's copy.
BUILDX_CURRENT=$(sudo docker buildx version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 | tr -d v || true)
if [ -z "$BUILDX_CURRENT" ] || \
   [ "$(printf '%s\n' 0.17.0 "$BUILDX_CURRENT" | sort -V | head -1)" != 0.17.0 ]; then
  log "Installing Docker Buildx plugin (found: ${BUILDX_CURRENT:-none})"
  # /releases/latest redirects to /releases/tag/<version>; take the tag from it.
  BUILDX_URL=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    https://github.com/docker/buildx/releases/latest)
  BUILDX_VERSION=${BUILDX_URL##*/}
  sudo mkdir -p "$PLUGIN_DIR"
  sudo curl -fsSL -o "$PLUGIN_DIR/docker-buildx" \
    "https://github.com/docker/buildx/releases/download/${BUILDX_VERSION}/buildx-${BUILDX_VERSION}.linux-${BIN_ARCH}"
  sudo chmod +x "$PLUGIN_DIR/docker-buildx"
fi

# --- Swap: 1 GB RAM instances can run out of memory while building ---------
if [ "$(swapon --show | wc -l)" -eq 0 ] && [ ! -f /swapfile ]; then
  log "Adding 1 GB swap file"
  sudo fallocate -l 1G /swapfile
  sudo chmod 600 /swapfile
  sudo mkswap /swapfile
  sudo swapon /swapfile
  echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab >/dev/null
fi

# --- App configuration -------------------------------------------------------
if [ ! -f .env ]; then
  echo "Missing .env. Create it first: cp .env.example .env && nano .env" >&2
  exit 1
fi
if ! grep -qE '^SECRET_KEY=.{32,}' .env || grep -q '^SECRET_KEY=change-me' .env; then
  log "Generating a random SECRET_KEY in .env"
  sed -i '/^SECRET_KEY=/d' .env
  echo "SECRET_KEY=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" >> .env
fi
mkdir -p data uploads

if [ -z "${DOMAIN:-}" ]; then
  # EC2 metadata (IMDSv2) first, then a public lookup for other hosts.
  TOKEN=$(curl -fsS -m 2 -X PUT http://169.254.169.254/latest/api/token \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)
  PUBLIC_IP=$(curl -fsS -m 2 -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || true)
  [ -n "$PUBLIC_IP" ] || PUBLIC_IP=$(curl -fsS -m 5 https://checkip.amazonaws.com | tr -d '[:space:]')
  DOMAIN="${PUBLIC_IP//./-}.sslip.io"
fi
export DOMAIN

# --- Deploy -----------------------------------------------------------------
if [ -d .git ]; then
  log "Pulling latest code"
  git pull --ff-only
fi

log "Building and starting containers for https://$DOMAIN"
sudo -E docker compose up -d --build --remove-orphans
sudo docker image prune -f >/dev/null

log "Done. App: https://$DOMAIN  (first certificate can take ~30s)"
echo "Logs: sudo docker compose logs -f app"
