#!/usr/bin/env bash
# One-time setup of a plain Ubuntu 24.04 VM as the DIFME runtime (replaces the Codespace; 2026-11-20).
# Target: a free-tier arm64 cloud VM (arm64, 4 OCPU / 24 GB RAM, boot volume up to 200 GB), but any
# amd64/arm64 Ubuntu 24.04 host works. Run as the default sudo user (ubuntu):
#   curl -fsSL https://raw.githubusercontent.com/pratikmohanty1994-ui/difme/main/ci/vm-bootstrap.sh | bash
# Afterwards drive it from anywhere with:  DIFME_VM=ubuntu@<ip> DIFME_VM_KEY=~/.ssh/<key> bash ci/cs.sh '<cmd>'
# Idempotent: safe to re-run.
set -euo pipefail
ARCH=$(dpkg --print-architecture)    # amd64 | arm64
UARCH=$(uname -m)                    # x86_64 | aarch64
ME=$(id -un)
DATA=/var/lib/difme                  # persistent disk (the Codespace used ephemeral /tmp)
export DEBIAN_FRONTEND=noninteractive

echo "== packages"
sudo apt-get update -qq
sudo apt-get install -y -qq ca-certificates curl gnupg git jq unzip zip acl make python3 python3-pip python3-yaml pipx \
  docker.io docker-buildx docker-compose-v2 >/dev/null
sudo usermod -aG docker "$ME"
sudo systemctl enable --now docker >/dev/null

echo "== JDK 25 + 21 (Temurin) and Maven"
if ! command -v java >/dev/null || ! java -version 2>&1 | grep -q '"25'; then
  curl -fsSL https://packages.adoptium.net/artifactory/api/gpg/key/public | sudo gpg --dearmor --yes -o /etc/apt/keyrings/adoptium.gpg
  echo "deb [signed-by=/etc/apt/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb noble main" | sudo tee /etc/apt/sources.list.d/adoptium.list >/dev/null
  sudo apt-get update -qq && sudo apt-get install -y -qq temurin-25-jdk temurin-21-jdk >/dev/null
  sudo update-alternatives --set java "$(update-alternatives --list java | grep temurin-25 | head -1)" || true
fi
MVN=3.9.11
if ! mvn -v 2>/dev/null | grep -q "$MVN"; then
  curl -fsSL "https://archive.apache.org/dist/maven/maven-3/$MVN/binaries/apache-maven-$MVN-bin.tar.gz" | sudo tar xz -C /opt
  sudo ln -sf "/opt/apache-maven-$MVN/bin/mvn" /usr/local/bin/mvn
fi

echo "== Node 22, kubectl, helm, gh"
NODE=22.21.1; NARCH=$([ "$ARCH" = amd64 ] && echo x64 || echo arm64)
node -v 2>/dev/null | grep -q "v$NODE" || { curl -fsSL "https://nodejs.org/dist/v$NODE/node-v$NODE-linux-$NARCH.tar.xz" | sudo tar xJ -C /usr/local --strip-components=1; sudo npm i -g -s pnpm@9 >/dev/null; }
KUBECTL=v1.32.3
command -v kubectl >/dev/null || { curl -fsSL -o /tmp/kubectl "https://dl.k8s.io/release/$KUBECTL/bin/linux/$ARCH/kubectl" && sudo install /tmp/kubectl /usr/local/bin/kubectl; }
HELM=v3.17.3
command -v helm >/dev/null || curl -fsSL "https://get.helm.sh/helm-$HELM-linux-$ARCH.tar.gz" | sudo tar xz -C /usr/local/bin --strip-components=1 "linux-$ARCH/helm"
if ! command -v gh >/dev/null; then
  curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | sudo dd of=/etc/apt/keyrings/githubcli.gpg status=none
  echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/githubcli.gpg] https://cli.github.com/packages stable main" | sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null
  sudo apt-get update -qq && sudo apt-get install -y -qq gh >/dev/null
fi
command -v rustup >/dev/null || curl -fsSL https://sh.rustup.rs | sh -s -- -y -q --profile minimal >/dev/null

echo "== repo at /workspaces/difme (same path as the Codespace, so every script works unchanged)"
sudo mkdir -p /workspaces "$DATA"; sudo chown "$ME" /workspaces
[ -d /workspaces/difme/.git ] || git clone -q https://github.com/pratikmohanty1994-ui/difme.git /workspaces/difme
git -C /workspaces/difme pull -q --ff-only || true

echo "== image store and swap on the persistent disk"
sudo tee /etc/profile.d/difme.sh >/dev/null <<EOF
export DIFME_IMAGE_DIR=$DATA/containerd
export DIFME_SWAP_FILE=$DATA/swap
EOF
# shellcheck disable=SC1091
. /etc/profile.d/difme.sh
# Non-interactive SSH (ci/cs.sh) skips profile.d; ~/.bashrc returns early for non-interactive shells, so prepend.
grep -q difme.sh ~/.bashrc || sed -i '1i . /etc/profile.d/difme.sh' ~/.bashrc

echo "== heal at every boot (swap/zswap, image-store ACL, Cilium refresh)"
sudo tee /etc/systemd/system/difme-heal.service >/dev/null <<EOF
[Unit]
Description=DIFME runtime heal (swap, zswap, image store, Cilium refresh)
After=docker.service network-online.target
Wants=network-online.target
[Service]
Type=oneshot
User=$ME
Environment=DIFME_IMAGE_DIR=$DATA/containerd DIFME_SWAP_FILE=$DATA/swap HOME=/home/$ME
WorkingDirectory=/workspaces/difme
ExecStart=/bin/bash ci/image-disk.sh heal
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload && sudo systemctl enable difme-heal.service >/dev/null

echo "== platform CLIs (k3d, argocd, cilium, ...) from the devcontainer script"
sg docker -c "bash /workspaces/difme/.devcontainer/post-create.sh" || true

echo
echo "DIFME VM ready ($UARCH, $(free -g | awk '/Mem:/ {print $2}') GB RAM, $(df -h / | awk 'NR==2 {print $4}') free)."
echo "Next: log out and back in (docker group), then: cd /workspaces/difme && make cluster && make up PROFILE=core"
