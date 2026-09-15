"""Ed25519 event signing for non-repudiation.

Objective 2: "Each event is digitally signed by the emitting detection
agent prior to submission, binding its origin cryptographically and
preventing any party from falsely claiming or denying responsibility for a
record." In production the agent identity and signing key are issued by
the Hyperledger Fabric Certificate Authority (see network/); this module
provides the local Ed25519 signing primitive used either standalone
(local verification, Commit 3) or wrapped inside a Fabric MSP identity
(Commit 6).

Ed25519 (RFC 8032) is chosen over ECDSA/RSA for this layer because it has
no per-signature randomness requirement (eliminating a class of nonce-reuse
key-recovery bugs), fixed small signature/key sizes suited to a >1000
events/sec pipeline, and constant-time reference implementations in the
`cryptography` package used here.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass(frozen=True)
class AgentIdentity:
    """A detection agent's signing identity.

    ``agent_id`` corresponds to the ``agent.id`` field of
    config/phase2.example.yaml and is the identity referenced by every
    signature this agent produces, enabling the Fabric CA to bind a
    certificate to the same logical identity in production.
    """

    agent_id: str
    private_key: Ed25519PrivateKey

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def public_key_hex(self) -> str:
        raw = self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()


def generate_agent_identity(agent_id: str) -> AgentIdentity:
    return AgentIdentity(agent_id=agent_id, private_key=Ed25519PrivateKey.generate())


def save_private_key(identity: AgentIdentity, key_path: Path) -> None:
    key_path.parent.mkdir(parents=True, exist_ok=True)
    pem = identity.private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(pem)
    try:
        key_path.chmod(0o600)
    except OSError:
        pass  # best-effort on filesystems that don't support POSIX perms


def load_agent_identity(agent_id: str, key_path: Path) -> AgentIdentity:
    pem = key_path.read_bytes()
    private_key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError(f"{key_path} does not contain an Ed25519 private key")
    return AgentIdentity(agent_id=agent_id, private_key=private_key)


def load_or_create_agent_identity(agent_id: str, key_path: Path) -> AgentIdentity:
    """Load the identity at ``key_path`` if present, else generate and persist one.

    This is a local-development convenience. Production deployments should
    provision agent keys via the Fabric CA (network/scripts) rather than
    relying on first-run key generation.
    """
    if key_path.is_file():
        return load_agent_identity(agent_id, key_path)
    identity = generate_agent_identity(agent_id)
    save_private_key(identity, key_path)
    return identity


def sign_digest(identity: AgentIdentity, payload_digest_hex: str) -> str:
    """Sign the hex-encoded payload digest; return the hex-encoded signature.

    Signing the digest (not the full payload) keeps the signature
    computation constant-cost regardless of triggering_features size and
    keeps the signed message identical to the value committed on-chain,
    so verification never needs the full payload in hand.
    """
    signature = identity.private_key.sign(bytes.fromhex(payload_digest_hex))
    return signature.hex()


def verify_signature(public_key_hex: str, payload_digest_hex: str, signature_hex: str) -> bool:
    try:
        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(bytes.fromhex(signature_hex), bytes.fromhex(payload_digest_hex))
        return True
    except (InvalidSignature, ValueError):
        return False
