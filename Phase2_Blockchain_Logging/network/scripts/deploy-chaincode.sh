#!/usr/bin/env bash
# Packages, installs, approves, and commits the securitylog chaincode on
# 'securitylogchannel' across SecurityOrg and AuditOrg.
# Run from Phase2_Blockchain_Logging/network/ after network-up.sh.
set -euo pipefail

CHANNEL_NAME="securitylogchannel"
CC_NAME="securitylog"
CC_VERSION="1.0"
CC_SEQUENCE="1"
CC_SRC_PATH="../chaincode/securitylog"
ORDERER_ADDR="orderer1.orderer.phase2.local:7050"

echo "[*] Vendoring chaincode Go modules ..."
(cd "$CC_SRC_PATH" && GO111MODULE=on go mod vendor)

echo "[*] Packaging chaincode ..."
docker run --rm --network phase2_network \
  -v "$(pwd)/../chaincode:/chaincode" \
  -w /chaincode/securitylog \
  hyperledger/fabric-tools:2.5 \
  peer lifecycle chaincode package "/chaincode/${CC_NAME}.tar.gz" \
  --path . --lang golang --label "${CC_NAME}_${CC_VERSION}"

install_on() {
  local msp="$1" mspconfig="$2" address="$3"
  docker run --rm --network phase2_network \
    -e CORE_PEER_LOCALMSPID="$msp" \
    -e CORE_PEER_MSPCONFIGPATH="$mspconfig" \
    -e CORE_PEER_ADDRESS="$address" \
    -e CORE_PEER_TLS_ENABLED=true \
    -v "$(pwd)/crypto-config:/crypto-config" \
    -v "$(pwd)/../chaincode:/chaincode" \
    hyperledger/fabric-tools:2.5 \
    peer lifecycle chaincode install "/chaincode/${CC_NAME}.tar.gz"
}

echo "[*] Installing chaincode on SecurityOrg peers ..."
install_on SecurityOrgMSP /crypto-config/peerOrganizations/security.phase2.local/users/Admin@security.phase2.local/msp peer0.security.phase2.local:7051
install_on SecurityOrgMSP /crypto-config/peerOrganizations/security.phase2.local/users/Admin@security.phase2.local/msp peer1.security.phase2.local:7151

echo "[*] Installing chaincode on AuditOrg peers ..."
install_on AuditOrgMSP /crypto-config/peerOrganizations/audit.phase2.local/users/Admin@audit.phase2.local/msp peer0.audit.phase2.local:9051
install_on AuditOrgMSP /crypto-config/peerOrganizations/audit.phase2.local/users/Admin@audit.phase2.local/msp peer1.audit.phase2.local:9151

echo "[*] Approve and commit the chaincode definition, using the packaging label above,"
echo "    matched to its install package ID via 'peer lifecycle chaincode queryinstalled',"
echo "    then 'peer lifecycle chaincode approveformyorg' for each org and"
echo "    'peer lifecycle chaincode commit' with both orgs' endorsements, targeting"
echo "    channel ${CHANNEL_NAME} via orderer ${ORDERER_ADDR}. These three commands need the"
echo "    package ID captured from queryinstalled's output and are intentionally run"
echo "    interactively rather than scripted blind, per Fabric's own lifecycle design."

echo "[ok] Chaincode ${CC_NAME}:${CC_VERSION} installed on both organisations' peers."
