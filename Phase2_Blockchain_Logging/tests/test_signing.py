from src.digest import digest_bytes
from src.signing import generate_agent_identity, sign_digest, verify_signature


def test_sign_and_verify_roundtrip():
    identity = generate_agent_identity("agent-001")
    digest = digest_bytes(b"hello world")
    signature = sign_digest(identity, digest)
    assert verify_signature(identity.public_key_hex(), digest, signature)


def test_verify_fails_for_wrong_key():
    identity_a = generate_agent_identity("agent-a")
    identity_b = generate_agent_identity("agent-b")
    digest = digest_bytes(b"hello world")
    signature = sign_digest(identity_a, digest)
    assert not verify_signature(identity_b.public_key_hex(), digest, signature)


def test_verify_fails_for_tampered_digest():
    identity = generate_agent_identity("agent-001")
    digest = digest_bytes(b"hello world")
    signature = sign_digest(identity, digest)
    other_digest = digest_bytes(b"goodbye world")
    assert not verify_signature(identity.public_key_hex(), other_digest, signature)


def test_save_and_load_identity_roundtrip(tmp_path):
    from src.signing import load_agent_identity, save_private_key

    identity = generate_agent_identity("agent-001")
    key_path = tmp_path / "agent.pem"
    save_private_key(identity, key_path)
    loaded = load_agent_identity("agent-001", key_path)
    assert loaded.public_key_hex() == identity.public_key_hex()
