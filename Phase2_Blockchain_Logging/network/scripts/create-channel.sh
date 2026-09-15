#!/usr/bin/env bash
# Creates 'securitylogchannel' and joins every peer to it.
# Run from Phase2_Blockchain_Logging/network/ (invoked by network-up.sh).
set -euo pipefail

CHANNEL_NAME="securitylogchannel"
ORDERER_ADDR="orderer1.orderer.phase2.local:7050"

peer_cli() {
  local msp="$1" mspconfig="$2" address="$3"
  shift 3
  docker run --rm --network phase2_network \
    -e CORE_PEER_LOCALMSPID="$msp" \
    -e CORE_PEER_MSPCONFIGPATH="$mspconfig" \
    -e CORE_PEER_ADDRESS="$address" \
    -e CORE_PEER_TLS_ENABLED=true \
    -v "$(pwd)/crypto-config:/crypto-config" \
    hyperledger/fabric-tools:2.5 peer "$@"
}

echo "[*] Creating channel $CHANNEL_NAME via orderer $ORDERER_ADDR ..."
peer_cli SecurityOrgMSP /crypto-config/peerOrganizations/security.phase2.local/users/Admin@security.phase2.local/msp \
  peer0.security.phase2.local:7051 \
  channel create -o "$ORDERER_ADDR" -c "$CHANNEL_NAME" \
  -f "/crypto-config/../network-artifacts/channel-artifacts/${CHANNEL_NAME}.tx" \
  --outputBlock "/crypto-config/../network-artifacts/channel-artifacts/${CHANNEL_NAME}.block"

for org_peer in \
  "SecurityOrgMSP:/crypto-config/peerOrganizations/security.phase2.local/users/Admin@security.phase2.local/msp:peer0.security.phase2.local:7051" \
  "SecurityOrgMSP:/crypto-config/peerOrganizations/security.phase2.local/users/Admin@security.phase2.local/msp:peer1.security.phase2.local:7151" \
  "AuditOrgMSP:/crypto-config/peerOrganizations/audit.phase2.local/users/Admin@audit.phase2.local/msp:peer0.audit.phase2.local:9051" \
  "AuditOrgMSP:/crypto-config/peerOrganizations/audit.phase2.local/users/Admin@audit.phase2.local/msp:peer1.audit.phase2.local:9151"; do
  IFS=":" read -r msp mspconfig host port <<< "$org_peer"
  echo "[*] Joining $host:$port to $CHANNEL_NAME ..."
  peer_cli "$msp" "$mspconfig" "$host:$port" channel join \
    -b "/crypto-config/../network-artifacts/channel-artifacts/${CHANNEL_NAME}.block"
done

echo "[ok] Channel $CHANNEL_NAME created and all peers joined."
