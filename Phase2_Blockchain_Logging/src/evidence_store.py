"""Content-addressed off-chain evidence storage.

Objective 2: "To reconcile immutability with storage efficiency the system
implements a hybrid architecture. The complete event payload ... is placed
in content-addressed storage. Only the SHA-256 digest of that payload
together with essential metadata ... is committed on-chain."

This module implements the local-filesystem content-addressed backend used
by default (`storage.backend: local_content_addressed` in
config/phase2.example.yaml) and a thin adapter interface so an IPFS backend
(directed by the Phase 1 handoff document for the 10.9 MB STAHN model
artifact) can be swapped in without changing callers.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path

from .digest import digest_bytes


@dataclass(frozen=True)
class StoredEvidence:
    content_address: str  # e.g. "sha256:<hex>" or an IPFS CID
    size_bytes: int


class EvidenceStore(ABC):
    """Interface every off-chain storage backend implements."""

    @abstractmethod
    def put(self, payload: bytes) -> StoredEvidence:
        """Persist ``payload``; return its content address."""

    @abstractmethod
    def get(self, content_address: str) -> bytes:
        """Retrieve the payload previously stored at ``content_address``."""

    @abstractmethod
    def exists(self, content_address: str) -> bool:
        ...


class ContentAddressError(LookupError):
    pass


class LocalContentAddressedStore(EvidenceStore):
    """Filesystem-backed content-addressed store: key = sha256(payload).

    Directory layout mirrors the classic git/IPFS-style fan-out
    (``<root>/<first 2 hex chars>/<remaining 62 hex chars>``) so a single
    directory never accumulates millions of entries under high anchoring
    volume.
    """

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path_for(self, digest_hex: str) -> Path:
        return self.root / digest_hex[:2] / digest_hex[2:]

    def put(self, payload: bytes) -> StoredEvidence:
        digest_hex = digest_bytes(payload)
        path = self._path_for(digest_hex)
        if not path.is_file():
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = path.with_suffix(".tmp")
            tmp_path.write_bytes(payload)
            tmp_path.replace(path)  # atomic on POSIX; avoids partial-write corruption
        return StoredEvidence(content_address=f"sha256:{digest_hex}", size_bytes=len(payload))

    def get(self, content_address: str) -> bytes:
        digest_hex = _strip_sha256_prefix(content_address)
        path = self._path_for(digest_hex)
        if not path.is_file():
            raise ContentAddressError(f"no evidence stored at {content_address}")
        return path.read_bytes()

    def exists(self, content_address: str) -> bool:
        try:
            digest_hex = _strip_sha256_prefix(content_address)
        except ValueError:
            return False
        return self._path_for(digest_hex).is_file()


class IPFSStore(EvidenceStore):
    """IPFS-backed content-addressed store, per the Phase 1 handoff directive
    to place the large model artifact off-chain via IPFS and embed only the
    CID on-chain. Requires a reachable IPFS HTTP API (default
    ``http://127.0.0.1:5001``) and the optional ``ipfshttpclient`` package;
    this dependency is intentionally NOT in requirements.txt so that the
    default local demo path never needs a running IPFS daemon.
    """

    def __init__(self, api_addr: str = "/ip4/127.0.0.1/tcp/5001"):
        try:
            import ipfshttpclient  # type: ignore
        except ImportError as exc:
            raise ImportError(
                "IPFSStore requires 'pip install ipfshttpclient' and a running "
                "IPFS daemon; the default demo path uses LocalContentAddressedStore "
                "and does not need this."
            ) from exc
        self._client = ipfshttpclient.connect(api_addr)

    def put(self, payload: bytes) -> StoredEvidence:
        result = self._client.add_bytes(payload)
        cid = result if isinstance(result, str) else result["Hash"]
        return StoredEvidence(content_address=cid, size_bytes=len(payload))

    def get(self, content_address: str) -> bytes:
        return self._client.cat(content_address)

    def exists(self, content_address: str) -> bool:
        try:
            self._client.cat(content_address)
            return True
        except Exception:
            return False


def _strip_sha256_prefix(content_address: str) -> str:
    if content_address.startswith("sha256:"):
        digest_hex = content_address[len("sha256:"):]
    else:
        digest_hex = content_address
    if len(digest_hex) != 64 or any(c not in "0123456789abcdef" for c in digest_hex.lower()):
        raise ValueError(f"not a well-formed sha256 content address: {content_address!r}")
    return digest_hex.lower()


def put_json(store: EvidenceStore, obj: dict) -> StoredEvidence:
    """Convenience: persist a JSON-serialisable object (e.g. the full alert
    payload including triggering_features and feature_attributions) and
    return its content address."""
    payload = json.dumps(obj, sort_keys=True, ensure_ascii=False).encode("utf-8")
    return store.put(payload)


def get_json(store: EvidenceStore, content_address: str) -> dict:
    return json.loads(store.get(content_address).decode("utf-8"))
