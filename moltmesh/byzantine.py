"""The Byzantine adversary: epsilon, the malicious validator.

Three attack vectors, exactly as the mission specifies:

  equivocation   two validly-signed envelopes at the same (epoch, seq) with
                 different payloads, delivered to different peers so no two
                 observers immediately hold the full proof;
  replay         captured, perfectly-signed old envelopes re-injected — both
                 the byte-identical form and (after the protocol upgrade)
                 the cross-epoch form, which is the dangerous one;
  withholding    sponge mode: accept every inbound envelope, relay nothing,
                 hoping to starve the mesh into partition.

Every attack function returns a structured record for the attack transcript.
"""
from __future__ import annotations

import json
import urllib.request

from .core import ENVELOPE_FIELDS, canonical, sign_envelope


def _post(url: str, obj: dict, timeout: float = 15.0) -> tuple[int, dict]:
    """Post and capture the status even on rejection — the attack report needs
    the node's verdict, not an exception."""
    req = urllib.request.Request(
        url, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read() or b"{}")
        except Exception:
            body = {}
        return e.code, body


def attack_equivocation(eps, alpha_url: str, beta_url: str, tag: str) -> dict:
    """Two conflicting envelopes, same author seq, different payloads:
    payload A -> alpha only, payload B -> beta only."""
    seq = eps._next_seq(eps.name)
    payloads = {
        "A": {"kind": "trade.offer", "tag": tag, "offer": "SELL 100 CR for 10 MSH",
              "to": "alpha"},
        "B": {"kind": "trade.offer", "tag": tag, "offer": "SELL 100 CR for 1 MSH",
              "to": "beta"},
    }
    envs, results = {}, {}
    for side, url in (("A", alpha_url), ("B", beta_url)):
        env = eps.author("mesh.event", payloads[side], seq=seq)
        status, resp = _post(url + "/ingest", {"envelope": env})
        envs[side] = env
        results[side] = {"url": url, "verdict": resp.get("verdict"),
                         "why": resp.get("why")}
    return {"attack": "equivocation", "seq": seq, "envelopes": envs,
            "deliveries": results,
            "claim": ("two valid signatures by the same key over conflicting "
                      "bodies at the same sequence — mathematical proof of "
                      "Byzantine behavior, held the moment any two peers "
                      "compare notes")}


def attack_replay(eps, target_urls: list[str], captured: list[dict],
                  tag: str = "replay") -> dict:
    """Re-inject captured, correctly-signed old envelopes at every target."""
    results = []
    for url in target_urls:
        for env in captured:
            status, resp = _post(url + "/ingest", {"envelope": env})
            results.append({"url": url, "author": env["author"],
                            "seq": env["seq"], "epoch": env["epoch"],
                            "verdict": resp.get("verdict"),
                            "why": resp.get("why")})
    return {"attack": f"replay ({tag})", "count": len(results),
            "deliveries": results}


def attack_monotonicity(eps, target_url: str, tag: str = "monotonicity") -> dict:
    """A freshly-signed envelope whose vector clock REWINDS: it claims not to
    have seen events its author demonstrably saw. Causality violation."""
    seq = eps._next_seq(eps.name)
    body = {"mesh_id": eps.mesh_id, "epoch": eps.epoch,
            "protocol": eps.protocol_version, "author": eps.name,
            "seq": seq,
            "vc": {a: 0 for a in list(eps.by_author) + [eps.name]},
            "type": "mesh.event",
            "payload": {"kind": "rewound", "note": "vc claims amnesia"},
            "pub": eps.ident.pub_hex}
    env = sign_envelope(eps.ident, body)
    status, resp = _post(target_url + "/ingest", {"envelope": env})
    return {"attack": "causal-monotonicity-violation", "seq": seq,
            "verdict": resp.get("verdict"), "why": resp.get("why")}


def attack_withhold(eps, on: bool = True) -> dict:
    """Sponge mode: epsilon ingests everything, relays nothing."""
    status, resp = _post(eps.url + "/control", {"op": "withhold", "on": on})
    return {"attack": "withholding", "applied": resp.get("ok"), "on": on,
            "claim": "epsilon becomes a gossip sink — it can no longer be a "
                     "relay, only a dead end"}


def attack_fabricated_checkpoint(eps, alpha_url: str, beta_url: str,
                                 rnd: int) -> dict:
    """Conflicting checkpoint proposals: a fake root to alpha, a different
    fake root to beta — an attempt to split the mesh's view of history."""
    seq = eps._next_seq(eps.name)
    results = []
    for i, url in enumerate((alpha_url, beta_url)):
        env = eps.author("checkpoint.proposal",
                         {"round": rnd, "root": f"fabricated-{i}-" + "f" * 48,
                          "height": 10_000 + i}, seq=seq)
        status, resp = _post(url + "/ingest", {"envelope": env})
        results.append({"url": url, "seq": env["seq"],
                        "verdict": resp.get("verdict"),
                        "why": resp.get("why")})
    return {"attack": "fabricated-checkpoint-proposals", "round": rnd,
            "deliveries": results}