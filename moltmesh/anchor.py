"""molt-anchor — the mesh's root of trust and its permanent audit trail.

The genesis anchor is a signed document binding:

  mesh_id           the swarm's name and namespace
  protocol_version  the starting ruleset every validator booted with
  validators        {node_name: {pub, stake}} — the initial validator set
  genesis_hash      the hash of the seed event every node bases on

It is signed by the bootstrap node. Every consequential governance event —
checkpoint acceptance, slashing, ejection, protocol upgrade, fork — is
*inscribed* into the anchor's audit trail: an append-only, hash-chained
list carried alongside the anchor document. The anchor is the one artifact
a newcomer needs to join, and the one artifact an auditor needs to judge.
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from .core import canonical, GENESIS_HASH


def anchor_hash(anchor: dict) -> str:
    return hashlib.sha256(canonical(anchor).encode("utf-8")).hexdigest()


def create_genesis_anchor(bootstrap_identity, mesh_id: str, validators: dict,
                          protocol_version: int = 1, seed_event_hash: str | None = None
                          ) -> dict:
    anchor = {
        "kind": "molt-anchor/genesis",
        "mesh_id": mesh_id,
        "protocol_version": protocol_version,
        "validators": validators,
        "genesis_hash": seed_event_hash or GENESIS_HASH,
        "created_ts": time.time(),
        "bootstrap": bootstrap_identity.node_id(),
        "audit_trail": [],
    }
    anchor["hash"] = anchor_hash({k: v for k, v in anchor.items() if k != "hash"})
    anchor["sig"] = bootstrap_identity.sign_hex(anchor["hash"].encode("ascii"))
    return anchor


def verify_anchor(anchor: dict, bootstrap_pub: str) -> bool:
    body = {k: v for k, v in anchor.items() if k not in ("hash", "sig")}
    from .identity import verify_hex
    return (anchor_hash(body) == anchor.get("hash")
            and verify_hex(bootstrap_pub, anchor.get("sig", ""), anchor["hash"].encode("ascii")))


def inscribe(anchor: dict, entry_kind: str, detail: dict, signer) -> dict:
    """Append a hash-chained entry to the anchor's audit trail (in place)."""
    trail = anchor["audit_trail"]
    prev = trail[-1]["hash"] if trail else anchor["hash"]
    entry = {"n": len(trail), "ts": time.time(), "kind": entry_kind,
             "detail": detail, "prev": prev}
    entry["hash"] = hashlib.sha256(
        prev.encode("ascii") + canonical(entry).encode("utf-8")).hexdigest()
    entry["sig"] = signer.sign_hex(entry["hash"].encode("ascii"))
    entry["signer"] = signer.node_id()
    trail.append(entry)
    return entry


def verify_trail(anchor: dict, bootstrap_pub: str | None = None) -> list[str]:
    """Verify the audit trail's hash chain and every entry's signature.
    `bootstrap_pub` optionally admits bootstrap-signed trail entries."""
    from .identity import verify_hex
    errors, prev = [], anchor["hash"]
    pubs = {name.split("@")[0]: v["pub"] for name, v in anchor["validators"].items()}
    if bootstrap_pub:
        pubs["bootstrap"] = bootstrap_pub
    for e in anchor["audit_trail"]:
        body = {k: e[k] for k in ("n", "ts", "kind", "detail", "prev")}
        h = hashlib.sha256(prev.encode("ascii") + canonical(body).encode("utf-8")).hexdigest()
        if e["prev"] != prev:
            errors.append(f"trail prev break at #{e['n']}")
        if e["hash"] != h:
            errors.append(f"trail hash mismatch at #{e['n']}")
        who = e.get("signer", "").split("@")[0].replace("node:", "")
        if who not in pubs or not verify_hex(pubs[who], e["sig"], e["hash"].encode("ascii")):
            errors.append(f"trail signature invalid at #{e['n']}")
        prev = e["hash"]
    return errors


def save(anchor: dict, path: str | Path):
    Path(path).write_text(json.dumps(anchor, indent=2) + "\n")


def load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())