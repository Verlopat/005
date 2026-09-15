import pytest

from src.evidence_store import ContentAddressError, LocalContentAddressedStore, get_json, put_json


def test_put_get_roundtrip(tmp_path):
    store = LocalContentAddressedStore(tmp_path / "evidence")
    address = store.put(b"hello world")
    assert store.get(address.content_address) == b"hello world"
    assert store.exists(address.content_address)


def test_content_address_is_deterministic(tmp_path):
    store = LocalContentAddressedStore(tmp_path / "evidence")
    a1 = store.put(b"same content")
    a2 = store.put(b"same content")
    assert a1.content_address == a2.content_address


def test_get_missing_raises(tmp_path):
    store = LocalContentAddressedStore(tmp_path / "evidence")
    with pytest.raises(ContentAddressError):
        store.get("sha256:" + "0" * 64)


def test_put_get_json_roundtrip(tmp_path):
    store = LocalContentAddressedStore(tmp_path / "evidence")
    obj = {"b": 2, "a": 1, "nested": {"x": [1, 2, 3]}}
    address = put_json(store, obj)
    assert get_json(store, address.content_address) == obj


def test_tampering_off_chain_payload_changes_its_address(tmp_path):
    """A modified payload gets a different content address entirely,
    rather than silently overwriting the original — this is the property
    that makes off-chain content addressing tamper-evident by
    construction (docs/architecture.md)."""
    store = LocalContentAddressedStore(tmp_path / "evidence")
    original = store.put(b"original payload")
    modified = store.put(b"modified payload")
    assert original.content_address != modified.content_address
    assert store.get(original.content_address) == b"original payload"
