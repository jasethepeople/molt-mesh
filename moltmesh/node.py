"""A mesh node: molt-core event store + Ed25519 identity + HTTP gossip.

Trust model: a node trusts only (a) the genesis anchor it was seeded with
and (b) cryptographic signatures. Everything else — another node's event
log, its word about what it relayed, its checkpoint proposals — is untrusted
input that must earn acceptance through the validation pipeline.

Validation pipeline for an inbound envelope:
  1. structural  — required fields, size bounds
  2. signature   — Ed25519 over canonical body, pub in current validator set
  3. membership  — mesh_id matches, author is (still) a validator
  4. epoch       — current epoch only; anything older is a dead-letter replay
  5. monotonic   — author seq strictly greater than the highest accepted
  6. causal      — envelope vector clock dominates the author's previous one
  7. equivocation — same (author, epoch, seq), different content ⇒ keep both
                    envelopes as cryptographic evidence, emit a signed
                    equivocation-evidence event, and start the slash clock
Accept ⇒ append to the local ledger, fold into derived state, rebroadcast.
"""
from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import anchor as anchor_mod
from .core import (canonical, envelope_id, sign_envelope, verify_envelope,
                   vc_dominates, GENESIS_HASH)
from .identity import Identity
from .reactor import V1_RULES, V2_RULES, rule_summary

MAX_BODY = 256 * 1024
DEFAULT_EPOCH = 1


def merkle_root(leaves: list[str]) -> str:
    if not leaves:
        return GENESIS_HASH
    layer = sorted(leaves)
    while len(layer) > 1:
        if len(layer) % 2:
            layer.append(layer[-1])
        layer = [hashlib.sha256((layer[i] + layer[i + 1]).encode("ascii")).hexdigest()
                 for i in range(0, len(layer), 2)]
    return layer[0]


class MeshNode:
    def __init__(self, name: str, port: int, anchor: dict, identity: Identity,
                 run_dir, peers: dict[str, str] | None = None,
                 checkpoint_every: int = 4):
        self.name = name
        self.port = port
        self.url = f"http://127.0.0.1:{port}"
        self.anchor = anchor
        self.ident = identity
        self.mesh_id = anchor["mesh_id"]
        from .core import Ledger
        if run_dir is None:            # pure replay node: no files, no server
            self.ledger_path = None
            self.ledger = Ledger(":memory:")
        else:
            run_dir.mkdir(parents=True, exist_ok=True)
            self.ledger_path = run_dir / f"{name}-ledger.jsonl"
            self.ledger = Ledger(self.ledger_path)
        self.peers: dict[str, str] = dict(peers or {})
        self.checkpoint_every = checkpoint_every

        # ---- derived state (all rebuildable from ledger + anchor) ----------
        self.envs: dict[str, dict] = {}            # id -> envelope
        self.by_author: dict[str, dict[int, str]] = {}   # author -> seq -> id
        self.last_vc: dict[str, dict] = {}         # author -> last accepted vc
        self.relayed: dict[str, int] = {}          # peer -> envelopes served
        self.suspicion: dict[str, dict] = {}       # peer -> {unverified_proposals, reasons}
        self.equivocations: dict[str, list] = {}   # author -> [conflicting ids]
        self.slashed: set[str] = set()
        self.ejected: set[str] = set()
        self.validators: dict = json.loads(json.dumps(anchor["validators"]))
        self.balances: dict[str, int] = {v: 0 for v in self.validators}
        self.stake_burned = 0
        self.treasury = 0
        self._last_serve_round = -1
        self.served_by: dict[str, int] = {}     # peer -> envelopes they served us
        self.fork_bias: int | None = None       # refuse protocol upgrades above this
        self.rules_by_epoch: dict[int, dict] = {1: dict(V1_RULES), 2: dict(V2_RULES)}
        self.epoch = DEFAULT_EPOCH
        self.protocol_version = anchor["protocol_version"]
        self.rejects: list[dict] = []
        self.duplicates = 0
        self._evidence_seen: set = set()
        self.checkpoints: list[dict] = []
        self.divergences: list[dict] = []
        self.forked_off = False
        self.suspended: set[str] = set()   # validators voted offline by the mesh
        self.partitioned = False
        self.withholding = False       # sponge mode: accept all, relay none
        self._round = 0
        self._pushed_upto: dict[str, dict[str, int]] = {}   # peer -> author -> seq
        self._proposal_buf: dict[int, list] = {}
        self._lock = threading.RLock()
        self._server = None

    # ------------------------------------------------------------------ api
    def start(self):
        node = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):   # silence
                pass

            def _send(self, code, obj):
                try:
                    body = json.dumps(obj).encode()
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def _read(self):
                n = int(self.headers.get("Content-Length") or 0)
                if n > MAX_BODY:
                    raise ValueError("body too large")
                return json.loads(self.rfile.read(n) or b"{}")

            def do_GET(self):
                if self.path == "/status":
                    self._send(200, node.status())
                elif self.path == "/digest":
                    self._send(200, node.digest())
                elif self.path == "/healthz":
                    self._send(200, {"ok": True, "node": node.name})
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                try:
                    req = self._read()
                except Exception:
                    return self._send(400, {"error": "bad json"})
                if self.path == "/ingest":
                    self._send(*node.ingest(req.get("envelope"), via="direct"))
                elif self.path == "/gossip":
                    self._send(200, node.receive_gossip(req, via=self.client_address[0]))
                elif self.path == "/pull":
                    self._send(200, node.serve_pull(req))
                elif self.path == "/control":
                    self._send(200, node.control(req))
                else:
                    self._send(404, {"error": "not found"})

        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def stop(self):
        if self._server:
            self._server.shutdown()
            self._server = None

    def control(self, req: dict) -> dict:
        op = req.get("op")
        if op == "partition":
            self.partitioned = bool(req.get("on"))
            self.ledger.append("control.partition", detail={"on": self.partitioned})
            return {"ok": True, "partitioned": self.partitioned}
        if op == "withhold":
            self.withholding = bool(req.get("on"))
            self.ledger.append("control.withhold", detail={"on": self.withholding})
            return {"ok": True, "withholding": self.withholding}
        if op == "set_fork_bias":
            self.fork_bias = req.get("version")   # node refuses upgrades above this
            return {"ok": True}
        return {"ok": False}

    # ------------------------------------------------------------- authoring
    def author(self, etype: str, payload: dict, seq: int | None = None) -> dict:
        with self._lock:
            seq = seq if seq is not None else self._next_seq(self.name)
            vc = {a: (max(s.keys()) if (s := self.by_author.get(a)) else 0)
                  for a in set(list(self.by_author) + [self.name])}
            vc[self.name] = seq
            env = sign_envelope(self.ident, {
                "mesh_id": self.mesh_id, "epoch": self.epoch,
                "protocol": self.protocol_version, "author": self.name,
                "seq": seq, "vc": vc, "type": etype,
                "payload": payload, "pub": self.ident.pub_hex,
            })
            return env

    def _next_seq(self, author: str) -> int:
        slots = self.by_author.get(author)
        return (max(slots) + 1) if slots else 0

    def propose_upgrade(self, to_version: int, reason: str,
                        co_signers: list) -> dict:
        """Author a signed protocol.upgrade carrying collected co-signatures.
        The co-signers sign the body WITHOUT the co_signers list (the same
        rule the verifier applies), so quorum is unforgeable."""
        with self._lock:
            seq = self._next_seq(self.name)
            vc = {a: (max(s) if (s := self.by_author.get(a)) else 0)
                  for a in set(list(self.by_author) + [self.name])}
            vc[self.name] = seq
            body = {"mesh_id": self.mesh_id, "epoch": self.epoch,
                    "protocol": self.protocol_version, "author": self.name,
                    "seq": seq, "vc": vc, "type": "protocol.upgrade",
                    "payload": {"to_version": to_version, "reason": reason},
                    "pub": self.ident.pub_hex}
            body["payload"]["co_signers"] = co_signers
            env = sign_envelope(self.ident, body)
            self.ingest(env, via="self")
            self.push_new()
            return env

    def submit(self, etype: str, payload: dict) -> dict:
        """Author an event, apply it locally, gossip it."""
        env = self.author(etype, payload)
        self.ingest(env, via="self")
        self.push_new()
        return env

    # ------------------------------------------------------------ validation
    def ingest(self, env: dict | None, via: str = "gossip") -> tuple[int, dict]:
        """The pipeline. Returns (http_status, detail)."""
        if env is None or not isinstance(env, dict):
            return 400, {"verdict": "reject", "why": "malformed"}
        if self.partitioned and via not in ("self", "reconcile"):
            return 503, {"verdict": "reject", "why": "partitioned"}

        with self._lock:
            eid = envelope_id({k: env[k] for k in
                               ("mesh_id", "epoch", "protocol", "author", "seq",
                                "vc", "type", "payload", "pub")}) \
                if all(k in env for k in ("mesh_id", "epoch", "protocol", "author",
                                          "seq", "vc", "type", "payload", "pub")) else None
            if eid is None:
                return self._reject(env, via, "malformed")
            if eid in self.envs:
                self.duplicates += 1
                return 200, {"verdict": "duplicate"}

            # ---- equivocation BEFORE monotonicity: a conflicting envelope at
            # an occupied slot is cryptographic proof of Byzantine behavior,
            # not a stale copy of it.
            slot = self.by_author.setdefault(env["author"], {})
            if env["seq"] in slot and slot[env["seq"]] != eid:
                return self._on_conflict(env, eid, slot[env["seq"]], via)

            verdict = self._validate(env, eid, via)
            if verdict:
                return self._reject(env, via, verdict)

            env["__id"] = eid
            env["__via"] = via
            self.envs[eid] = env
            slot[env["seq"]] = eid
            self.last_vc[env["author"]] = dict(env["vc"])
            self._apply_credits(env)
            self._maybe_apply_governance(env)
            self.ledger.append("env.accept", env=env, detail={"via": via})
            return 200, {"verdict": "accept"}

    def _on_conflict(self, env: dict, eid: str, held: str, via: str):
        """Two validly-signed envelopes claim one (author, seq) slot.

        Every honest node applies the SAME deterministic rule — the smaller
        envelope id holds the slot, the loser stays in the log but is
        quarantined (excluded from the application state root). Convergence
        is guaranteed without any coordinator: whichever copy arrived first,
        once both copies have gossiped everywhere the state roots agree."""
        conflict = self.envs[held]
        winner, loser = (held, eid) if held < eid else (eid, held)
        loser_env = conflict if loser == held else env
        if winner != held:
            # the true winner arrived second — the slot must adopt it, or
            # nodes that saw the copies in opposite orders diverge forever
            self.by_author[env["author"]][env["seq"]] = eid
        self.ingest_raw(env, eid, via)
        if eid not in self.envs:          # forgery — never store, never evidence
            return 400, {"verdict": "reject", "why": "bad-signature"}
        key = (env["author"], env["seq"], held, eid)
        if key not in self._evidence_seen:
            self._evidence_seen.add(key)
            self.equivocations.setdefault(env["author"], []).append(
                {"a": held, "b": eid})
            self.ledger.append("equivocation.evidence", env=env,
                               detail={"witness": self.name,
                                       "against": env["author"],
                                       "a": held[:16], "b": eid[:16],
                                       "quarantined": loser[:16],
                                       "round": self._round})
            def _copy(eid_):
                return json.loads(json.dumps(
                    {k: v for k, v in self.envs[eid_].items()
                     if not k.startswith("__")}))
            self.submit("equivocation.evidence",
                        {"conflict_a": _copy(held),
                         "conflict_b": _copy(eid),
                         "author": env["author"], "seq": env["seq"]})
        if loser_env.get("__id") == loser:
            loser_env["__quarantined"] = True
        return 200, {"verdict": "equivocation-evidence",
                     "quarantined": loser[:16]}

    def ingest_raw(self, env: dict, eid: str, via: str) -> None:
        """Store a conflicting envelope in the log (bypassing monotonicity —
        its slot is already occupied by definition). Signature, mesh, and
        membership are still enforced: forgeries are rejected outright."""
        if not verify_envelope(env):
            return
        if env["mesh_id"] != self.mesh_id or env["author"] not in self.validators:
            return
        env["__id"] = eid
        env["__via"] = via
        if eid not in self.envs:
            self.envs[eid] = env
        self.ledger.append("env.conflict-stored", env=env, detail={"via": via})

    def _validate(self, env: dict, eid: str, via: str) -> str | None:
        if not verify_envelope(env):
            return "bad-signature"
        if env["mesh_id"] != self.mesh_id:
            return "foreign-mesh"
        if env["author"] not in self.validators or env["author"] in self.ejected:
            return "not-a-validator"
        if env["epoch"] < self.epoch:
            return "stale-epoch-replay"
        if env["epoch"] > self.epoch:
            return "future-epoch"
        if env["epoch"] not in self.rules_by_epoch:
            return "unknown-ruleset"
        if env["protocol"] > self.protocol_version and not self.fork_willing(env):
            return "unsupported-protocol"
        highest = self._next_seq(env["author"]) - 1 if self.by_author.get(env["author"]) else -1
        if env["seq"] < highest:
            return "replay"
        prev_vc = self.last_vc.get(env["author"])
        if prev_vc and not vc_dominates(env["vc"], prev_vc):
            return "causal-violation"
        if env["vc"].get(env["author"]) != env["seq"]:
            return "vc-self-mismatch"
        return None

    def fork_willing(self, env: dict) -> bool:
        return getattr(self, "fork_bias", None) is not None and env["protocol"] <= self.fork_bias

    def _reject(self, env, via, why) -> tuple[int, dict]:
        self.rejects.append({"ts": time.time(), "why": why, "via": via,
                             "author": (env or {}).get("author"),
                             "seq": (env or {}).get("seq"),
                             "id": (env or {}).get("__id", "")[:16]})
        self.ledger.append("env.reject", env=env if isinstance(env, dict) else None,
                           detail={"why": why, "via": via})
        code = 403 if why in ("bad-signature", "foreign-mesh", "not-a-validator",
                              "stale-epoch-replay", "replay", "causal-violation") else 400
        return code, {"verdict": "reject", "why": why}

    def _apply_credits(self, env: dict):
        """Balances are derived state: a pure function of accepted envelopes.
        mesh.event pays a submit fee to the treasury; checkpoint.accepted
        pays each matching proposer; credit.serve receipts pay relays."""
        rules = self.rules_by_epoch[env["epoch"]]
        t = env["type"]
        if t == "mesh.event":
            fee = rules["submit_fee"]
            self.balances[env["author"]] = self.balances.get(env["author"], 0) - fee
            self.treasury += fee
        elif t == "checkpoint.accepted":
            reward = rules["checkpoint_reward"]
            for w in env["payload"].get("signers", []):
                if w in self.validators:
                    self.balances[w] = self.balances.get(w, 0) + reward
        elif t == "credit.serve":
            who = env["payload"].get("beneficiary")
            amount = int(env["payload"].get("amount", 0))
            if who in self.validators and amount > 0:
                self.balances[who] = self.balances.get(who, 0) + amount

    def _maybe_apply_governance(self, env: dict):
        t, p = env["type"], env["payload"]
        if t == "equivocation.evidence":
            against = p.get("author")
            if self._verify_evidence(p) and against not in self.slashed:
                self._slash(against, env)
        elif t == "validator.admit":
            who = p.get("node")
            if who and who not in self.validators and env["author"] in self.validators \
                    and self._quorum(self.validators.keys(), env):
                self.validators[who] = {"pub": p["pub"], "stake": p.get("stake", 50)}
                self.ledger.append("validator.admitted", detail={"who": who})
                if not self.ledger.mute:
                    anchor_mod.inscribe(self.anchor, "validator.admitted",
                                    {"who": who, "by": self.name}, self.ident)
        elif t == "validator.suspend":
            who = p.get("node")
            # quorum is computed EXCLUDING the node being suspended — the
            # mesh must be able to vote a dead peer out of the threshold
            # without the dead peer's cooperation.
            names = [n for n in self.validators
                     if n not in self.ejected and n != who]
            if who and who in self.validators and who not in self.suspended \
                    and names and self._quorum(names, env):
                self.suspended.add(who)
                self.ledger.append("validator.suspended", detail={"who": who})
                if not self.ledger.mute:
                    anchor_mod.inscribe(self.anchor, "validator.suspended",
                                        {"who": who, "by": self.name}, self.ident)
        elif t == "validator.resume":
            who = p.get("node")
            if who and who in self.suspended and self._quorum(
                    [n for n in self.validators if n not in self.ejected], env):
                self.suspended.discard(who)
                self.ledger.append("validator.resumed", detail={"who": who})
                if not self.ledger.mute:
                    anchor_mod.inscribe(self.anchor, "validator.resumed",
                                        {"who": who, "by": self.name}, self.ident)
        elif t == "protocol.upgrade":
            ver = p.get("to_version")
            if self.fork_bias is not None and ver > self.fork_bias:
                # dissent: this node refuses the upgrade and is forked off —
                # the majority continues without it. Logged, never forced.
                self.forked_off = True
                self.ledger.append("fork.refused",
                                   detail={"version": ver, "bias": self.fork_bias})
                if not self.ledger.mute:
                    anchor_mod.inscribe(self.anchor, "fork.refused",
                                    {"version": ver, "by": self.name}, self.ident)
                return
            if ver in self.rules_by_epoch and ver > self.protocol_version \
                    and self._quorum(self.validators.keys(), env):
                self._apply_upgrade(ver, env)

    def _verify_evidence(self, p: dict) -> bool:
        a, b = p.get("conflict_a"), p.get("conflict_b")
        if not a or not b or a == b:
            return False
        if (a["author"], a["epoch"], a["seq"]) != (b["author"], b["epoch"], b["seq"]):
            return False
        return verify_envelope(a, a["pub"]) and verify_envelope(b, b["pub"]) \
            and a["pub"] == b["pub"] and envelope_id(
                {k: a[k] for k in ("mesh_id", "epoch", "protocol", "author", "seq",
                                   "vc", "type", "payload", "pub")}) != envelope_id(
                {k: b[k] for k in ("mesh_id", "epoch", "protocol", "author", "seq",
                                   "vc", "type", "payload", "pub")})

    def _slash(self, who: str, evidence_env: dict):
        self.slashed.add(who)
        self.ejected.add(who)
        stake = self.validators.get(who, {}).get("stake", 0)
        self.stake_burned = self.stake_burned + stake if hasattr(self, "stake_burned") else stake
        if who in self.validators:
            self.validators[who]["stake"] = 0
        self.balances[who] = 0          # forfeited stake + burned credits
        self.ledger.append("validator.slashed", detail={"who": who, "burned": stake,
                                                        "round": self._round})
        if not self.ledger.mute:
            anchor_mod.inscribe(self.anchor, "validator.slashed",
                            {"who": who, "burned": stake,
                             "evidence_seq": evidence_env["seq"],
                             "round": self._round, "by": self.name}, self.ident)
        self.ledger.append("validator.ejected", detail={"who": who,
                                                        "round": self._round})
        if not self.ledger.mute:
            anchor_mod.inscribe(self.anchor, "validator.ejected",
                            {"who": who, "round": self._round}, self.ident)
        self.peers.pop(who, None)      # isolation: no more gossip routes
        self.isolated_rounds = getattr(self, "isolated_rounds", None) or self._round

    def _required_quorum(self, env: dict) -> int:
        """The 2-of-3 Byzantine rule generalized: floor from the ruleset,
        but never below a strict majority of the currently active validators.
        This keeps quorum intersection (any two accepting sets share an honest
        node) as validators are slashed and ejected."""
        names = [n for n in self.validators if n not in self.ejected
                 and n not in self.suspended]
        floor = self.rules_by_epoch[env["epoch"]]["checkpoint_threshold"]
        return max(floor, len(names) // 2 + 1)

    def _quorum(self, validator_names, env) -> bool:
        """The author counts as one yes-vote; require >= threshold of the
        current validator set. For simplicity, governance envelopes carry
        co_signers: additional validator signatures over the same body."""
        names = [n for n in validator_names if n not in self.ejected]
        threshold = self._required_quorum(env)
        cos = env["payload"].get("co_signers", [])
        sig_ok = 1 + sum(1 for c in cos if c.get("name") in names
                         and c.get("pub") == self.validators.get(c["name"], {}).get("pub")
                         and _verify_cosig(env, c))
        return sig_ok >= threshold

    def _apply_upgrade(self, ver: int, env: dict):
        self.protocol_version = ver
        self.epoch = ver
        self.ledger.append("protocol.upgraded", detail={"version": ver})
        if not self.ledger.mute:
            anchor_mod.inscribe(self.anchor, "protocol.upgraded",
                                {"version": ver}, self.ident)


    def digest(self) -> dict:
        with self._lock:
            return {
                "node": self.name,
                "mesh_id": self.mesh_id,
                "epoch": self.epoch,
                "protocol": self.protocol_version,
                "have": {a: sorted(s) for a, s in self.by_author.items() if s},
                "root": self.state_root(),
                "height": len(self.envs),
                "isolated": sorted(self.ejected),
            }

    def state_root(self) -> str:
        """Merkle root of the APPLICATION state: accepted mesh.event
        envelopes only. Governance metadata (proposals, reconciliations,
        evidence) is excluded — otherwise proposal timing would leak into
        the root and honest nodes could never agree on a checkpoint."""
        with self._lock:
            leaves = [self.envs[i]["__id"]
                      for a, s in sorted(self.by_author.items())
                      for q, i in sorted(s.items())
                      if i in self.envs and self.envs[i]["type"] == "mesh.event"
                      and not self.envs[i].get("__quarantined")
                      and a not in self.slashed]
            return merkle_root(leaves)

    def receive_gossip(self, req: dict, via: str) -> dict:
        results = []
        for env in req.get("envelopes", []):
            code, detail = self.ingest(env, via=req.get("from", via))
            results.append(detail.get("verdict", "?"))
        frm = req.get("from", via)
        served = sum(1 for v in results if v in ("accept", "equivocation-evidence"))
        if served:
            self.served_by[frm] = self.served_by.get(frm, 0) + served
        # anti-entropy: tell the sender what we have; they pull the diff
        d = self.digest()
        return {"verdicts": results, "digest": d}

    def push_new(self):
        """Push every envelope past each peer's watermark to every live peer."""
        if self.partitioned or self.withholding:
            return
        with self._lock:
            slots = {a: dict(s) for a, s in self.by_author.items()}
        for peer, url in list(self.peers.items()):
            if peer in self.ejected or peer == self.name:
                continue
            upto = self._pushed_upto.setdefault(peer, {})
            batch = [self._clean(self.envs[i])
                     for a, s in slots.items()
                     for seq, i in s.items() if seq > upto.get(a, -1) and i in self.envs]
            try:
                resp = _post(url + "/gossip", {"from": self.name,
                                               "envelopes": batch})
                served = len([v for v in resp.get("verdicts", [])
                              if v in ("accept", "equivocation-evidence")])
                self.relayed[peer] = self.relayed.get(peer, 0) + len(batch)
                for a, s in slots.items():
                    if s:
                        upto[a] = max(upto.get(a, -1), max(s))
                peer_digest = resp.get("digest", {})
                missing = self._missing_from(peer_digest)
                want = [{"author": a, "seq": q} for a, seqs in missing.items()
                        for q in seqs]
                if want:
                    resp2 = _post(url + "/pull", {"from": self.name, "want": want})
                    for env in resp2.get("envelopes", []):
                        self.ingest(env, via="pull")
            except Exception:
                pass

    @staticmethod
    def _clean(e: dict) -> dict:
        return {k: v for k, v in e.items() if not k.startswith("__")}

    def _missing_from(self, peer_digest: dict) -> dict[str, list[int]]:
        """Seqs the peer holds that I lack, from its digest."""
        out = {}
        for author, their_seqs in peer_digest.get("have", {}).items():
            mine = set(self.by_author.get(author, {}))
            gap = [s for s in their_seqs if s not in mine]
            if gap:
                out[author] = gap
        return out

    def serve_pull(self, req: dict) -> dict:
        out = []
        for want in req.get("want", []):
            eid = self.by_author.get(want["author"], {}).get(want["seq"])
            if eid and eid in self.envs:
                e = self.envs[eid]
                out.append({k: v for k, v in e.items() if k in
                            ("mesh_id", "epoch", "protocol", "author", "seq", "vc",
                             "type", "payload", "pub", "sig")})
        if out:
            frm = req.get("from", "pull")
            self.served_by[frm] = self.served_by.get(frm, 0) + len(out)
        return {"envelopes": out}

    # ------------------------------------------------------------ checkpoints
    def gossip_round(self, rnd: int):
        self._round = rnd
        if self.partitioned:
            self.ledger.append("gossip.round.skipped", detail={"round": rnd,
                                                               "why": "partitioned"})
            return
        self.push_new()
        if rnd % self.checkpoint_every == 0:
            self.emit_checkpoint_proposal(rnd)
        self.resolve_checkpoint(rnd - 1)

    def emit_checkpoint_proposal(self, rnd: int):
        root = self.state_root()
        env = self.author("checkpoint.proposal", {"round": rnd, "root": root,
                                                  "height": len(self.envs)})
        self.ingest(env, via="self")
        self.push_new()

    def resolve_checkpoint(self, rnd: int):
        with self._lock:
            props = [e for e in self.envs.values()
                     if e["type"] == "checkpoint.proposal" and e["payload"]["round"] == rnd
                     and e["author"] in self.validators and e["author"] not in self.ejected]
        if len(props) < self._required_quorum({"epoch": self.epoch}):
            return
        counts: dict[str, list] = {}
        for p in props:
            counts.setdefault(p["payload"]["root"], []).append(p)
        # deterministic tie-break: count, then lexicographic root
        root, group = max(counts.items(), key=lambda kv: (len(kv[1]), kv[0]))
        for p in props:
            if p["payload"]["root"] != root:
                sus = self.suspicion.setdefault(p["author"],
                                                {"divergent_proposals": 0})
                sus["divergent_proposals"] += 1
                self.ledger.append("proposal.divergent",
                                   detail={"against": p["author"], "round": rnd,
                                           "their_root": p["payload"]["root"][:16],
                                           "my_root": self.state_root()[:16]})
        threshold = self._required_quorum({"epoch": self.epoch})
        if len(group) < threshold:
            return
        my_root = self.state_root()
        if my_root != root:
            # Am I merely AHEAD of the proposers (their checkpoint predates
            # my newest events)? Then this is staleness, not divergence.
            my_vc = {a: max(s) for a, s in self.by_author.items() if s}
            ahead = all(all(my_vc.get(a, 0) >= q for a, q in p["vc"].items())
                        for p in group)
            if ahead:
                return
            self.diverge_at(rnd, root)
            return
        # NOTE: payload must be arrival-order independent or honest nodes
        # would sign different envelopes and diverge forever.
        names = sorted({p["author"] for p in group})
        env = self.author("checkpoint.accepted",
                          {"round": rnd, "root": root, "signers": names})
        self.ingest(env, via="self")
        self.push_new()
        self._issue_serve_receipts(rnd)
        self.checkpoints.append({"round": rnd, "root": root, "signers": names})
        self.ledger.append("checkpoint.accepted", detail={"round": rnd, "root": root})
        anchor_mod.inscribe(self.anchor, "checkpoint.accepted",
                            {"round": rnd, "root": root, "signers": names}, self.ident)

    def rebuild_from_ledger(self, entries: list[dict] | None = None) -> dict:
        """Crash recovery AND the deterministic replay engine: rebuild every
        piece of derived state from this node's own ledger, in ledger order.
        A node that dies mid-run can be respawned with nothing but its ledger
        file and the genesis anchor — no peer help, no manual intervention.
        An explicit `entries` stream overrides the node's own file (used by
        the audit to replay a recorded ledger into a fresh node)."""
        from .core import envelope_id
        if isinstance(entries, (str, Path)):
            entries = [json.loads(l) for l in Path(entries).read_text().splitlines()
                       if l.strip()]
        FIELDS = ("mesh_id", "epoch", "protocol", "author", "seq",
                  "vc", "type", "payload", "pub")
        with self._lock:
            self.ledger.mute = True
            self.checkpoints = []
            self.divergences = []
            for e in (entries if entries is not None else self.ledger.events):
                k, env, d = e["kind"], e.get("env"), e.get("detail") or {}
                eid = envelope_id({f: env[f] for f in FIELDS}) if env and all(f in env for f in FIELDS) else None
                if k == "env.accept" and eid:
                    env = dict(env)
                    env["__id"] = eid
                    self.envs[eid] = env
                    self.by_author.setdefault(env["author"], {})[env["seq"]] = eid
                    self.last_vc[env["author"]] = dict(env["vc"])
                    self._apply_credits(env)
                    # NOTE: governance is NOT re-decided here — decisions that
                    # depended on transient node state (fork_bias, withholding,
                    # arrival order) are already materialized in the stream as
                    # protocol.upgraded / fork.refused / validator.slashed
                    # entries, applied by their own branches below.
                elif k == "env.conflict-stored" and eid and eid not in self.envs:
                    self.envs[eid] = {**env, "__id": eid}
                elif k == "equivocation.evidence" and env:
                    self._evidence_seen.add((env["payload"].get("author"),
                                             env["payload"].get("seq"),
                                             d.get("a"), d.get("b")))
                elif k == "validator.slashed":
                    who = d["who"]
                    self.slashed.add(who)
                    self.stake_burned += d.get("burned", 0)
                    if who in self.validators:
                        self.validators[who]["stake"] = 0
                    self.balances[who] = 0
                elif k == "validator.ejected":
                    self.ejected.add(d["who"])
                    self.peers.pop(d["who"], None)
                elif k == "protocol.upgraded":
                    self.protocol_version = d["version"]
                    self.epoch = d["version"]
                elif k == "fork.refused":
                    self.forked_off = True
                elif k == "checkpoint.accepted":
                    self.checkpoints.append({"round": d.get("round"),
                                             "root": d.get("root")})
                if k == "env.accept" and env and env.get("type") == "credit.serve":
                    self._last_serve_round = max(self._last_serve_round,
                                                 int(env["payload"].get("round", -1)))
                elif k == "state.divergence":
                    self.divergences.append({"round": d.get("round"),
                                             "replayed": True})
                # quarantine: apply the deterministic loser rule pairwise
                if k in ("env.accept", "env.conflict-stored") and eid and env:
                    slot = self.by_author.get(env["author"], {})
                    held = slot.get(env["seq"])
                    if held and held != eid:
                        winner, loser = (held, eid) if held < eid else (eid, held)
                        self.envs[loser]["__quarantined"] = True
                        if winner != held:
                            self.by_author[env["author"]][env["seq"]] = eid
            rounds = [(e.get("detail") or {}).get("round")
                      for e in self.ledger.events]
            rounds = [r for r in rounds if isinstance(r, int)]
            self._round = max([self._round] + rounds) if rounds else self._round
            self.ledger.mute = False
            return {"replayed": len(entries if entries is not None
                                    else self.ledger.events),
                    "envs": len(self.envs), "root": self.state_root(),
                    "balances": dict(self.balances),
                    "protocol": self.protocol_version}

    def diverge_at(self, rnd: int, their_root: str):
        self.divergences.append({"round": rnd, "theirs": their_root[:16],
                                 "mine": self.state_root()[:16]})
        self.ledger.append("state.divergence", detail={"round": rnd})
        healed = self.self_heal()
        rec = {"round": rnd, "theirs": their_root[:16], "mine_before": self.divergences[-1]["mine"],
               "fetched": healed["fetched"], "verified": healed["verified"],
               "root_after": self.state_root()[:16]}
        env = self.author("reconciliation", rec)
        self.ingest(env, via="self")
        self.push_new()
        self.ledger.append("reconciliation", detail=rec)

    def self_heal(self) -> dict:
        """Fetch missing events from peers, re-verify the entire chain."""
        fetched, verified = 0, 0
        if self.partitioned:
            return {"fetched": 0, "verified": 0, "still_partitioned": True}
        for peer, url in list(self.peers.items()):
            if peer in self.ejected:
                continue
            try:
                d = _get(url + "/digest")
                missing = self._missing_from(d)
                want = [{"author": a, "seq": q} for a, seqs in missing.items()
                        for q in seqs]
                if want:
                    resp = _post(url + "/pull", {"from": self.name, "want": want})
                    for env in resp.get("envelopes", []):
                        code, detail = self.ingest(env, via="reconcile")
                        if detail.get("verdict") == "accept":
                            fetched += 1
            except Exception:
                pass
        verified = self.verify_full()
        return {"fetched": fetched, "verified": verified}

    def verify_full(self) -> dict:
        """molt-verify-go: re-verify every envelope and re-derive all state."""
        problems = []
        order = sorted(self.envs.values(),
                       key=lambda e: (e["epoch"], e["author"], e["seq"]))
        seen_vc: dict[str, dict] = {}
        for env in order:
            if not verify_envelope(env):
                problems.append(env["__id"][:16])
            if env["vc"].get(env["author"]) != env["seq"]:
                problems.append(env["__id"][:16])
        chain_errors = self.ledger.verify_chain()
        return {"envelopes": len(self.envs), "sig_problems": problems,
                "ledger_errors": chain_errors, "ok": not problems and not chain_errors}

    # --------------------------------------------------------------- credits
    def _issue_serve_receipts(self, rnd: int):
        """The reactor's gossip_serve rule: at each accepted checkpoint this
        node signs a receipt for every peer that served it envelopes since
        the last checkpoint. Receipts are envelopes too, so every balance
        stays a pure function of the envelope stream."""
        if self._last_serve_round >= rnd:
            return
        self._last_serve_round = rnd
        rules = self.rules_by_epoch[self.epoch]
        for peer, n in self.served_by.items():
            amount = (n // rules["gossip_serve_divisor"]) * rules["gossip_serve_reward"]
            if amount > 0 and peer in self.validators and peer not in self.ejected:
                self.submit("credit.serve", {"beneficiary": peer, "amount": amount,
                                             "round": rnd, "served": n})
        self.served_by.clear()

    def stake_of(self, who: str) -> int:
        return self.validators.get(who, {}).get("stake", 0)

    def balance_of(self, who: str) -> int:
        return self.balances.get(who, 0) + self.stake_of(who)

    # ------------------------------------------------------------------ show
    def status(self) -> dict:
        with self._lock:
            return {
                "node": self.name, "node_id": self.ident.node_id(),
                "url": self.url, "mesh_id": self.mesh_id,
                "protocol_version": self.protocol_version, "epoch": self.epoch,
                "rules": rule_summary(self.rules_by_epoch[self.epoch]),
                "envelopes": len(self.envs),
                "ledger_entries": len(self.ledger.events),
                "ledger_ok": not self.ledger.verify_chain(),
                "state_root": self.state_root(),
                "validators": {k: v.get("stake") for k, v in self.validators.items()
                               if k not in self.ejected},
                "ejected": sorted(self.ejected),
                "balances": {k: self.balance_of(k) for k in self.validators},
                "checkpoints": len(self.checkpoints),
                "divergences": self.divergences,
                "equivocations_seen": {k: len(v) for k, v in self.equivocations.items()},
                "rejects": len(self.rejects),
                "duplicates": self.duplicates,
                "treasury": self.treasury,
                "reject_reasons": _tally(r["why"] for r in self.rejects),
                "partitioned": self.partitioned,
                "forked_off": self.forked_off,
                "last_round": self._round,
            }

    def observatory_line(self) -> str:
        s = self.status()
        return (f"{s['node']:8s} v{s['protocol_version']} epoch={s['epoch']} "
                f"env={s['envelopes']:4d} ledger={'ok' if s['ledger_ok'] else 'BROKEN'} "
                f"root={s['state_root'][:12]} ckpts={s['checkpoints']} "
                f"rejects={s['rejects']:3d} bal={s['balances']}")


def _tally(iterable) -> dict:
    out: dict = {}
    for x in iterable:
        out[x] = out.get(x, 0) + 1
    return out


def _verify_cosig(env: dict, cosigner: dict) -> bool:
    """A co-signature covers the envelope body with the co_signers list itself
    removed (it must not sign a structure containing its own signature) and
    the co-signer's name bound in as `co_signer`."""
    from .core import canonical
    from .identity import verify_hex
    body = {k: env[k] for k in ("mesh_id", "epoch", "protocol", "author", "seq",
                                "vc", "type", "payload", "pub")}
    body["payload"] = {k: v for k, v in body["payload"].items() if k != "co_signers"}
    body["co_signer"] = cosigner["name"]
    return verify_hex(cosigner["pub"], cosigner.get("sig", ""),
                      canonical(body).encode("utf-8"))


def _post(url: str, obj: dict, timeout: float = 15.0) -> dict:
    data = json.dumps(obj).encode()
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _get(url: str, timeout: float = 15.0) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read())