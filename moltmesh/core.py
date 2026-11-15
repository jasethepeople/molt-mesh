"""molt-core — canonical JSON, Ed25519-signed event envelopes, local ledger.

The unit of mesh communication is the *envelope*:

    env  = {mesh_id, epoch, protocol, author, seq, vc, type, payload, pub}
    sig  = ed25519_sign(canonical(env))          by key `pub`
    id   = sha256(canonical(env))                the event's immutable name

`author/seq` is strictly monotonic per author — that is the replay guard.
`vc` is the author's vector clock — that is the causality guard.
`epoch` isolates protocol generations — old-epoch envelopes are dead letters.

Each node also keeps a *local ledger*: a hash-chained, append-only record of
everything it accepted, decided, or observed. The ledger is tamper-evident
and offline-verifiable; peers never need to trust it.
"""
from __future__ import annotations

import hashlib
import json
import os
import copy
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

GENESIS_HASH = "0" * 64
ENVELOPE_FIELDS = ("mesh_id", "epoch", "protocol", "author", "seq", "vc", "type", "payload", "pub")


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def envelope_id(env: dict) -> str:
    return hashlib.sha256(canonical(env).encode("utf-8")).hexdigest()


def sign_envelope(identity, env: dict) -> dict:
    body = {k: env[k] for k in ENVELOPE_FIELDS}
    return {**body, "sig": identity.sign_hex(canonical(body).encode("utf-8"))}


def verify_envelope(env: dict, pub_hex: str | None = None) -> bool:
    pub = pub_hex or env.get("pub")
    if not pub or any(k not in env for k in ENVELOPE_FIELDS) or "sig" not in env:
        return False
    body = {k: env[k] for k in ENVELOPE_FIELDS}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub)).verify(
            bytes.fromhex(env["sig"]), canonical(body).encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


def vc_dominates(new: dict, seen: dict) -> bool:
    """True when every component of `seen` is <= the same component of `new`."""
    return all(new.get(k, 0) >= v for k, v in seen.items())

class ChainError(Exception):
    pass


class Ledger:
    """A node's local, hash-chained record of everything it accepted.

    Each line: {seq, ts, kind, env, detail, prev_hash, hash}
    `env` carries the signed envelope (or None for purely local events,
    in which case `local_sig` signs the detail). The chain binds the node's
    own observation history; it is not a trust root — envelopes carry trust.
    """

    def __init__(self, path):
        self.path = None if path in (None, ":memory:") else Path(path)
        self.events: list[dict] = []
        self.mute = False   # replay/rebuild mode: append nothing
        if self.path is not None and self.path.exists():
            self._load()

    def _load(self):
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    self.events.append(json.loads(line))

    @property
    def last_hash(self) -> str:
        return self.events[-1]["hash"] if self.events else GENESIS_HASH

    def append(self, kind: str, env: dict | None = None, detail: dict | None = None,
               ts: float | None = None) -> dict:
        if self.mute:
            return {}
        entry = {
            "seq": len(self.events),
            "ts": ts if ts is not None else time.time(),
            "kind": kind,
            "env": copy.deepcopy(env) if env is not None else None,
            "detail": copy.deepcopy(detail or {}),
            "prev_hash": self.last_hash,
        }
        entry["hash"] = hashlib.sha256(
            entry["prev_hash"].encode("ascii") + canonical(
                {k: entry[k] for k in ("seq", "ts", "kind", "env", "detail")}).encode("utf-8")
        ).hexdigest()
        self.events.append(entry)
        if self.path is not None:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def head_after(self, n: int) -> str:
        """The chain head after the first n events (prefix attestation)."""
        if n < 0 or n > len(self.events):
            return ""
        if n == 0:
            return GENESIS_HASH
        return self.events[n - 1]["hash"]

    def verify_chain(self) -> list[str]:
        errors = []
        prev = GENESIS_HASH
        for i, e in enumerate(self.events):
            if e["seq"] != i:
                errors.append(f"seq break at {i}")
            h = hashlib.sha256(
                e["prev_hash"].encode("ascii") + canonical(
                    {k: e[k] for k in ("seq", "ts", "kind", "env", "detail")}).encode("utf-8")
            ).hexdigest()
            if e["prev_hash"] != prev:
                errors.append(f"prev_hash break at {i}")
            if e["hash"] != h:
                errors.append(f"hash mismatch at {i}")
            prev = e["hash"]
        return errors

    def env_ids(self) -> set:
        return {e["env"]["__id"] for e in self.events
                if e.get("env") and "__id" in e["env"]}

    def envelopes(self) -> list[dict]:
        return [e["env"] for e in self.events if e.get("env") and "__id" in e["env"]]


def keygen(name: str) -> tuple[str, str]:
    """Returns (priv_hex, pub_hex)."""
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes(serialization.Encoding.Raw,
                             serialization.PrivateFormat.Raw,
                             serialization.NoEncryption())
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)
    return raw.hex(), pub.hex()


def priv_from_hex(priv_hex: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))

def cosign_envelope(env: dict, identity) -> dict:
    """A second validator's signature over the exact same envelope body.
    Governance envelopes (upgrades, admissions) carry co_signers: lists of
    these structures; a node counts 1 for the author plus each verifiable
    co-signature when deciding quorum."""
    body = {k: env[k] for k in ENVELOPE_FIELDS}
    body["co_signer"] = identity.name
    return {"name": identity.name, "pub": identity.pub_hex,
            "sig": identity.sign_hex(canonical(body).encode("utf-8"))}
