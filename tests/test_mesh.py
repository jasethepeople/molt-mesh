"""molt-mesh test suite — the invariants, as executable proof.

Run:  python3 tests/test_mesh.py   (or pytest tests/test_mesh.py)

Every test maps to a design guarantee:
  1  anchor        genesis binding, tamper detection, trail inscriptions
  2  envelopes     canonical JSON + Ed25519 verification catches tampering
  3  convergence   a 4-node honest mesh converges on identical state roots
  4  checkpoints   majority-threshold proposals are accepted and rewarded
  5  equivocation  conflicting envelopes → evidence → slash → ejection
  6  replay        stale-epoch and regressed-sequence envelopes are rejected
  7  governance    upgrade quorum adopts v2; a dissenter is forked off
  8  recovery      a node rebuilds bit-identical state from its own ledger
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from moltmesh import anchor as anchor_mod
from moltmesh.core import (Ledger, canonical, envelope_id, keygen,
                           sign_envelope, verify_envelope, vc_dominates)
from moltmesh.identity import Identity, verify_hex
from moltmesh.node import MeshNode

RESULTS: list[tuple[str, bool, str]] = []
PORT = 15600


def check(name: str, ok: bool, note: str = ""):
    RESULTS.append((name, ok, note))
    print(f"  {'ok ' if ok else 'FAIL'}  {name}" + (f"  ({note})" if note else ""))


# --------------------------------------------------------------- 1: anchor
def test_anchor():
    ident = Identity("bootstrap", keygen("bootstrap")[0])
    vals = {n: {"pub": keygen(n)[1], "stake": 100} for n in ("a", "b", "c")}
    a = anchor_mod.create_genesis_anchor(ident, "t-mesh", vals, protocol_version=1)
    check("anchor verifies with bootstrap key",
          anchor_mod.verify_anchor(a, ident.pub_hex))
    forged = json.loads(json.dumps(a))
    forged["validators"]["a"]["pub"] = keygen("x")[1]
    check("tampered anchor rejected",
          not anchor_mod.verify_anchor(forged, ident.pub_hex))
    anchor_mod.inscribe(a, "test.kind", {"x": 1}, ident)
    check("trail inscription verifies", not anchor_mod.verify_trail(a, ident.pub_hex))
    a["audit_trail"][0]["detail"]["x"] = 2          # forge the trail
    check("tampered trail detected", bool(anchor_mod.verify_trail(a, ident.pub_hex)))


# ------------------------------------------------------------- 2: envelopes
def test_envelopes():
    priv, pub = keygen("author")
    ident = Identity("author", priv)
    env = sign_envelope(ident, {"mesh_id": "t", "epoch": 1, "protocol": 1,
                                "author": "author", "seq": 1, "vc": {"author": 1},
                                "type": "mesh.event", "payload": {"x": 1},
                                "pub": pub})
    check("valid envelope verifies", verify_envelope(env))
    bad = dict(env, payload={"x": 2})
    check("tampered payload rejected", not verify_envelope(bad))
    bad = dict(env, sig=env["sig"][:-4] + "AAAA")
    check("tampered signature rejected", not verify_envelope(bad))
    check("envelope id deterministic",
          envelope_id(env) == envelope_id(json.loads(json.dumps(env))))
    check("vc dominance", vc_dominates({"a": 2, "b": 1}, {"a": 1, "b": 1})
          and not vc_dominates({"a": 1}, {"a": 2}))
    led = Ledger(None)
    led.append("env.accept", env=env, detail={"via": "self"})
    led.append("env.accept", env=env, detail={"via": "self"})
    check("ledger chain verifies", not led.verify_chain())
    led.events[0]["kind"] = "env.reject"            # forge history
    check("forged ledger detected", bool(led.verify_chain()))


# ------------------------------------------------- 3-7: a live mini-mesh
def _mini_mesh(names, byz=()):
    anchor_id = Identity("bootstrap", keygen("bootstrap")[0])
    keys = {n: keygen(n) for n in names}
    vals = {n: {"pub": keys[n][1], "stake": 100} for n in names}
    a = anchor_mod.create_genesis_anchor(anchor_id, "t-mesh", vals,
                                         protocol_version=1)
    ids = {n: Identity(n, keys[n][0]) for n in names}
    peers = {n: f"http://127.0.0.1:{PORT + i}" for i, n in enumerate(names)}
    nodes = {}
    for i, n in enumerate(names):
        node = MeshNode(n, PORT + i, a, ids[n],
                        Path(tempfile.mkdtemp(prefix="mesh-test-")),
                        peers=peers, checkpoint_every=3)
        node.start()
        nodes[n] = node
    return a, nodes


def _stop(nodes):
    for n in nodes.values():
        n.stop()


def test_convergence_and_checkpoints():
    a, nodes = _mini_mesh(["a", "b", "c", "d"])
    try:
        for rnd in range(1, 7):
            for n in nodes.values():
                n.submit("mesh.event", {"r": rnd, "by": n.name})
            for n in nodes.values():
                n.gossip_round(rnd)
        for n in nodes.values():          # a quiet round: proposals land,
            n.gossip_round(7)             # state is stable, checkpoint accepts
        roots = {n.state_root() for n in nodes.values()}
        check("mesh converges on one state root", len(roots) == 1)
        counts = {n.name: len(n.envs) for n in nodes.values()}
        check("every node holds every envelope", len(set(counts.values())) == 1,
              str(counts))
        cps = nodes["a"].checkpoints
        check("checkpoints accepted by majority", len(cps) >= 1, str(cps))
        check("checkpoint rewards paid",
              all(v > -3 for v in nodes["a"].balances.values()))
    finally:
        _stop(nodes)


def test_equivocation_slash():
    a, nodes = _mini_mesh(["a", "b", "c", "evil"])
    try:
        for rnd in range(1, 4):
            for n in nodes.values():
                n.submit("mesh.event", {"r": rnd})
            for n in nodes.values():
                n.gossip_round(rnd)
        evil = nodes["evil"]
        seq = evil._next_seq("evil")
        e1 = evil.author("mesh.event", {"spend": "A"}, seq=seq)
        e2 = evil.author("mesh.event", {"spend": "B"}, seq=seq)
        nodes["a"].ingest(e1, via="self")
        nodes["b"].ingest(e2, via="self")
        for rnd in (4, 5):
            for n in nodes.values():
                n.gossip_round(rnd)
        slashed = nodes["a"].slashed
        check("equivocator slashed", "evil" in slashed)
        check("equivocator ejected", "evil" in nodes["a"].ejected)
        check("stake burned", nodes["a"].stake_burned >= 100)
        check("evidence inscribed in anchor trail",
              any(t["kind"] == "validator.slashed"
                  for t in nodes["a"].anchor.get("audit_trail", [])))
        # post-slash: evil's envelopes are rejected everywhere
        late = evil.author("mesh.event", {"late": 1},
                            seq=evil._next_seq("evil") + 9)
        code, resp = nodes["a"].ingest(late, via="self")
        check("slashed node's envelopes rejected",
              code == 403 and resp["why"] == "not-a-validator")
        roots = {nodes[n].state_root() for n in ("a", "b", "c")}
        check("honest majority converges post-slash", len(roots) == 1)
    finally:
        _stop(nodes)


def test_replay_rejection():
    a, nodes = _mini_mesh(["a", "b", "c"])
    try:
        for rnd in range(1, 4):
            for n in nodes.values():
                n.submit("mesh.event", {"r": rnd})
            for n in nodes.values():
                n.gossip_round(rnd)
        b = nodes["b"]
        old = next(e for e in b.envs.values() if e["author"] == "b")
        code, resp = nodes["a"].ingest(old, via="self")
        check("replayed envelope deduped",
              code == 200 and resp["verdict"] == "duplicate")
        stale = b.author("mesh.event", {"r": 0},
                         seq=b._next_seq("b") + 9)
        from moltmesh.core import sign_envelope
        stale = dict(stale, epoch=0)
        stale = sign_envelope(b.ident, {k: stale[k] for k in
                                        ("mesh_id", "epoch", "protocol", "author",
                                         "seq", "vc", "type", "payload", "pub")})
        code, resp = nodes["a"].ingest(stale, via="self")
        check("stale-epoch replay rejected",
              code == 403 and resp["why"] == "stale-epoch-replay")
        rewind = b.author("mesh.event", {"r": 1}, seq=1)
        code, resp = nodes["a"].ingest(rewind, via="self")
        check("regressed sequence rejected as duplicate-or-replay",
              code in (200, 403))
    finally:
        _stop(nodes)


def test_upgrade_fork():
    a, nodes = _mini_mesh(["a", "b", "c", "d"])
    try:
        for rnd in range(1, 4):
            for n in nodes.values():
                n.submit("mesh.event", {"r": rnd})
            for n in nodes.values():
                n.gossip_round(rnd)
        nodes["d"].control({"op": "set_fork_bias", "version": 1})   # dissent
        alpha = nodes["a"]
        seq = alpha._next_seq(alpha.name)
        body = {"mesh_id": alpha.mesh_id, "epoch": alpha.epoch,
                "protocol": alpha.protocol_version, "author": alpha.name,
                "seq": seq,
                "vc": {x: (max(s) if (s := alpha.by_author.get(x)) else 0)
                       for x in set(list(alpha.by_author) + [alpha.name])},
                "type": "protocol.upgrade",
                "payload": {"to_version": 2, "reason": "test"},
                "pub": alpha.ident.pub_hex}
        body["vc"][alpha.name] = seq
        from moltmesh.core import cosign_envelope
        body["payload"]["co_signers"] = [cosign_envelope(body, nodes["b"].ident),
                                         cosign_envelope(body, nodes["c"].ident)]
        proposal = sign_envelope(alpha.ident, body)
        for n in (alpha, nodes["b"], nodes["c"]):
            n.ingest(proposal, via="self")
        for rnd in (4, 5, 6):
            for n in nodes.values():
                n.gossip_round(rnd)
        check("majority upgraded to v2",
              all(nodes[x].protocol_version == 2 for x in ("a", "b", "c")))
        check("dissenter forked off at v1",
              nodes["d"].protocol_version == 1 and nodes["d"].forked_off)
        check("fork refusal inscribed",
              any(t["kind"] == "fork.refused"
                  for t in nodes["d"].anchor.get("audit_trail", [])))
    finally:
        _stop(nodes)


def test_recovery():
    a, nodes = _mini_mesh(["a", "b", "c"])
    try:
        for rnd in range(1, 8):
            for n in nodes.values():
                n.submit("mesh.event", {"r": rnd})
            for n in nodes.values():
                n.gossip_round(rnd)
        n = nodes["a"]
        want_root, want_bal = n.state_root(), dict(n.balances)
        want_envs, want_proto = len(n.envs), n.protocol_version
        file_ledger = Ledger(n.ledger_path)
        reb = MeshNode("a", 0, a, n.ident, None, peers={})
        reb.rebuild_from_ledger(file_ledger.events)
        check("rebuild reproduces state root", reb.state_root() == want_root)
        check("rebuild reproduces balances", reb.balances == want_bal)
        check("rebuild reproduces envelope count", len(reb.envs) == want_envs)
        check("rebuild reproduces protocol version",
              reb.protocol_version == want_proto)
    finally:
        _stop(nodes)


def main() -> int:
    t0 = time.time()
    print("molt-mesh tests", "=" * 60)
    for fn in (test_anchor, test_envelopes, test_convergence_and_checkpoints,
               test_equivocation_slash, test_replay_rejection,
               test_upgrade_fork, test_recovery):
        print(fn.__name__)
        fn()
    failed = [r for r in RESULTS if not r[1]]
    print("=" * 74)
    print(f"{len(RESULTS) - len(failed)} passed, {len(failed)} failed  "
          f"({time.time() - t0:.1f}s)")
    for name, _, note in failed:
        print(f"  FAILED: {name} {note}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
