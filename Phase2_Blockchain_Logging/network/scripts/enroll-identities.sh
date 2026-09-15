#!/usr/bin/env bash
# Enrolls a detection-agent identity (SecurityOrg) and an auditor identity
# (AuditOrg) with the attributes chaincode/securitylog/securitylog.go
# checks for access control: phase2.detectionAgent=true:ecert and
# phase2.auditor=true:ecert respectively.
#
# Run from Phase2_Blockchain_Logging/network/ (invoked by network-up.sh).
set -euo pipefail

export FABRIC_CA_CLIENT_HOME="$(pwd)/network-artifacts/ca-client"
mkdir -p "$FABRIC_CA_CLIENT_HOME"

echo "[*] Registering and enrolling detection-agent-001 with ca.security.phase2.local ..."
fabric-ca-client register \
  --caname ca-security \
  --id.name detection-agent-001 \
  --id.secret detectionpw \
  --id.attrs "phase2.detectionAgent=true:ecert" \
  --url https://admin:adminpw@localhost:7054 --tls.certfiles crypto-config/peerOrganizations/security.phase2.local/ca/ca.security.phase2.local-cert.pem

fabric-ca-client enroll \
  -u https://detection-agent-001:detectionpw@localhost:7054 \
  --caname ca-security \
  --enrollment.attrs "phase2.detectionAgent" \
  -M "$FABRIC_CA_CLIENT_HOME/detection-agent-001-msp" \
  --tls.certfiles crypto-config/peerOrganizations/security.phase2.local/ca/ca.security.phase2.local-cert.pem

echo "[*] Registering and enrolling auditor-001 with ca.audit.phase2.local ..."
fabric-ca-client register \
  --caname ca-audit \
  --id.name auditor-001 \
  --id.secret auditorpw \
  --id.attrs "phase2.auditor=true:ecert" \
  --url https://admin:adminpw@localhost:8054 --tls.certfiles crypto-config/peerOrganizations/audit.phase2.local/ca/ca.audit.phase2.local-cert.pem

fabric-ca-client enroll \
  -u https://auditor-001:auditorpw@localhost:8054 \
  --caname ca-audit \
  --enrollment.attrs "phase2.auditor" \
  -M "$FABRIC_CA_CLIENT_HOME/auditor-001-msp" \
  --tls.certfiles crypto-config/peerOrganizations/audit.phase2.local/ca/ca.audit.phase2.local-cert.pem

echo "[ok] Identities enrolled under $FABRIC_CA_CLIENT_HOME"
echo "    Point src/ledger/fabric_gateway.py's gateway_config at a wallet built from these MSP directories."
