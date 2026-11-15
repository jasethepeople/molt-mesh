"""molt-key-management — Ed25519 identities for mesh nodes.

Keys live in a private per-node store (0600). Only public keys travel in
envelopes and in the genesis anchor. The bootstrap node's key is the root
of identity for the mesh seed, but holds no ongoing administrative power —
the mesh is governed by signed events after genesis.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .core import keygen, priv_from_hex


class Identity:
    def __init__(self, name: str, priv_hex: str):
        self.name = name
        self._priv = priv_from_hex(priv_hex)
        self.pub_hex = self._priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.fingerprint = hashlib.sha256(bytes.fromhex(self.pub_hex)).hexdigest()[:16]

    def sign_hex(self, message: bytes) -> str:
        return self._priv.sign(message).hex()

    def node_id(self) -> str:
        return f"node:{self.name}@{self.fingerprint}"


def verify_hex(pub_hex: str, sig_hex: str, message: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)).verify(
            bytes.fromhex(sig_hex), message)
        return True
    except Exception:
        return False


class KeyStore:
    """Load-or-create named identities in a 0600 JSON store."""

    def __init__(self, path: str | Path | None):
        self.path = Path(path) if path is not None else None
        self._data: dict = {}
        if self.path is not None and self.path.exists():
            self._data = json.loads(self.path.read_text())
        self._cache: dict[str, Identity] = {}

    def get(self, name: str) -> Identity:
        if name in self._cache:
            return self._cache[name]
        if name not in self._data:
            self._data[name] = dict(zip(("priv", "pub"), keygen(name)))
            self._save()
        ident = Identity(name, self._data[name]["priv"])
        self._cache[name] = ident
        return ident

    def add(self, name: str, priv_hex: str) -> Identity:
        if name not in self._data:
            self._data[name] = {"priv": priv_hex,
                                "pub": priv_from_hex(priv_hex).public_key()
                                .public_bytes(serialization.Encoding.Raw,
                                              serialization.PublicFormat.Raw).hex()}
            self._save()
        return Identity(name, self._data[name]["priv"])

    def _save(self):
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._data, indent=2))
            os.chmod(self.path, 0o600)

    def public_keys(self) -> dict:
        return {name: d["pub"] for name, d in self._data.items()}