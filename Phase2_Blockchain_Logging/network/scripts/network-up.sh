#!/usr/bin/env bash
# Brings up the two-organisation Fabric network described in
# ../docker-compose.yaml. Run from Phase2_Blockchain_Logging/network/.
#
# Prerequisites (NOT available in the Perplexity Computer sandbox this
# repository was scaffolded in — run this on a host with them installed):
#   - Docker Engine + Docker Compose v2
#   - Fabric binaries on PATH: cryptogen, configtxgen
#   - Go 1.21+ (only needed later, for chaincode packaging)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$(dirname "$HERE")"
cd "$NETWORK_DIR"

for bin in docker cryptogen configtxgen; do
  if ! command -v "$bin" >/dev/null 2>&1; then
    echo "[!] Required tool not found on PATH: $bin" >&2
    echo "    Install the Fabric binaries (https://hyperledger-fabric.readthedocs.io) and retry." >&2
    exit 1
  fi
done

echo "[*] Generating cryptographic material (cryptogen) ..."
rm -rf crypto-config
cryptogen generate --config=./crypto-config.yaml --output="crypto-config"

echo "[*] Generating orderer genesis block and channel transaction (configtxgen) ..."
mkdir -p network-artifacts/channel-artifacts
export FABRIC_CFG_PATH="$NETWORK_DIR"
configtxgen -profile Phase2OrdererGenesis -channelID system-channel \
  -outputBlock network-artifacts/channel-artifacts/phase2-genesis.block
configtxgen -profile SecurityLogChannel -channelID securitylogchannel \
  -outputCreateChannelTx network-artifacts/channel-artifacts/securitylogchannel.tx
configtxgen -profile SecurityLogChannel -channelID securitylogchannel \
  -outputAnchorPeersUpdate network-artifacts/channel-artifacts/SecurityOrgMSPanchors.tx -asOrg SecurityOrgMSP
configtxgen -profile SecurityLogChannel -channelID securitylogchannel \
  -outputAnchorPeersUpdate network-artifacts/channel-artifacts/AuditOrgMSPanchors.tx -asOrg AuditOrgMSP

echo "[*] Starting containers (docker compose) ..."
docker compose -f docker-compose.yaml up -d

echo "[*] Waiting for orderer1 and peers to accept connections ..."
sleep 10

echo "[*] Creating and joining channel 'securitylogchannel' ..."
./scripts/create-channel.sh

echo "[*] Provisioning detection-agent and auditor CA identities/attributes ..."
./scripts/enroll-identities.sh

echo "[ok] Network is up. Next: ./scripts/deploy-chaincode.sh"
