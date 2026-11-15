"""The Byzantium Swarm scenario — the mesh's entire scripted life.

Five acts:
  1. seed      genesis anchor, keys, spawn of the founding observatories
  2. attacks   epsilon and zeta, two colluding Byzantine validators
  3. heal      partition a node, let the mesh move on, cut it back in
  4. fork      a hot-swap protocol upgrade with a live dissenter fork
  4b. crash    a validator dies; it resurrects from its own ledger alone
  5. proof     molt-audit report + deterministic replay + signed chronicle
"""
from __future__ import annotations

import json
import shutil
import sys
import time
from pathlib import Path

from . import anchor as anchor_mod
from . import byzantine
from .audit import audit_node, render_report, replay_report
from .core import canonical, cosign_envelope, sign_envelope
from .identity import Identity, keygen, verify_hex
from .node import MeshNode
from . import show

RUN = Path(__file__).resolve().parent.parent / "runs" / "byzantium"
HONEST = ["alpha", "beta", "gamma", "delta"]          # delta joins mid-run
BYZ = ["epsilon", "zeta"]                             # colluding adversaries
ALL = HONEST + BYZ
INITIAL = ["alpha", "beta", "gamma", "epsilon", "zeta"]   # delta comes later
CHECKPOINT_EVERY = 4
BASE_PORT = 15100


def log(msg: str):
    print(f"  {msg}", flush=True)


class Scenario:
    def __init__(self, run_dir: Path = RUN, quiet: bool = False):
        self.run_dir = run_dir
        self.quiet = quiet
        self.started_ts = time.time()
        self.attack_log: list[dict] = []
        self.rounds: list[int] = []
        self.late_joiners: list[dict] = []
        self.crash_recoveries: list[dict] = []

    def say(self, msg):
        if not self.quiet:
            log(msg)

    def _keys(self) -> dict:
        return json.loads((self.run_dir / "keys" / "keys.json").read_text())

    def _peers(self, exclude: str = "") -> dict[str, str]:
        return {n: f"http://127.0.0.1:{BASE_PORT + i}" for i, n in enumerate(ALL)
                if n != exclude}

    def close(self):
        for node in self.nodes.values():
            node.stop()

    # ------------------------------------------------------------ phase 1
    def seed(self):
        if self.run_dir.exists():
            shutil.rmtree(self.run_dir)
        self.run_dir.mkdir(parents=True)
        (self.run_dir / "keys").mkdir(mode=0o700)
        keys = {}
        for name in ALL + ["bootstrap"]:
            priv, pub = keygen(name)
            keys[name] = {"pub": pub, "priv": priv}
        (self.run_dir / "keys" / "keys.json").write_text(json.dumps(keys, indent=2))

        self.bootstrap = Identity("bootstrap", keys["bootstrap"]["priv"])
        validators = {n: {"pub": keys[n]["pub"], "stake": 100} for n in ALL}
        self.anchor = anchor_mod.create_genesis_anchor(
            self.bootstrap, "byzantium-swarm", validators,
            protocol_version=1, seed_event_hash=keys["alpha"]["pub"][:16])
        anchor_mod.save(self.anchor, self.run_dir / "genesis-anchor.json")
        assert anchor_mod.verify_anchor(self.anchor, self.bootstrap.pub_hex)
        self.say(f"genesis anchor forged  mesh=byzantium-swarm  "
                 f"validators={len(ALL)}  hash={self.anchor['hash'][:20]}…")

    def spawn(self):
        self.nodes: dict[str, MeshNode] = {}
        keys = self._keys()
        for name in INITIAL:
            ident = Identity(name, keys[name]["priv"])
            node = MeshNode(name, BASE_PORT + ALL.index(name),
                            anchor_mod.load(self.run_dir / "genesis-anchor.json"),
                            ident, self.run_dir / f"node-{name}",
                            peers=self._peers(exclude=name),
                            checkpoint_every=CHECKPOINT_EVERY)
            node.start()
            self.nodes[name] = node
        self.say("colony online: " + ", ".join(
            f"{n}@{node.url.split(':')[-1]}" for n, node in self.nodes.items()))
        (self.run_dir / "mesh.json").write_text(json.dumps(
            [{"name": n, "url": node.url, "port": node.port}
             for n, node in self.nodes.items()], indent=2) + "\n")

    def tick(self, rnd: int):
        self.rounds.append(rnd)
        for node in self.nodes.values():
            node.gossip_round(rnd)

    # ------------------------------------------------------------ phase 2
    def phase2_gossip_and_attacks(self):
        self.say("— phase 2: gossip protocol + colluding byzantine pressure —")
        for rnd in range(1, 4):
            for node in self.nodes.values():
                node.submit("mesh.event", {"n": rnd, "by": node.name,
                                           "note": f"round-{rnd}"})
            self.tick(rnd)
        eps, zeta = self.nodes["epsilon"], self.nodes["zeta"]

        # attack 1: replay of captured old envelopes — stale epoch/seq,
        # rejected by the monotonicity + epoch gates, no slash needed
        captured = [e for e in eps.envs.values() if e["author"] == "epsilon"]
        self.attack_log.append(
            {"round": 4, **byzantine.attack_replay(
                eps, [self.nodes[n].url for n in ("alpha", "beta", "gamma")],
                captured, tag="epoch-replay")})
        self.tick(4)

        # attack 2: monotonicity violation — regressed sequence number
        self.attack_log.append(
            {"round": 5, **byzantine.attack_monotonicity(
                eps, self.nodes["gamma"].url)})
        self.tick(5)

        # attack 3: THE crime — epsilon equivocates (double spend), two
        # validly signed conflicting envelopes at the same (author, seq)
        self.attack_log.append(
            {"round": 6, **byzantine.attack_equivocation(
                eps, self.nodes["alpha"].url, self.nodes["beta"].url,
                tag="double-spend")})
        self.tick(6)
        self.tick(7)          # evidence propagates; epsilon slashed + ejected

        # attack 4: zeta equivocates on checkpoint proposals — two different
        # fabricated roots sent to two different peers
        self.attack_log.append(
            {"round": 8, **byzantine.attack_fabricated_checkpoint(
                zeta, self.nodes["alpha"].url, self.nodes["beta"].url, rnd=8)})
        self.tick(8)
        self.tick(9)          # proposal conflict discovered; zeta slashed

        # attack 5: zeta, now ejected, tries sponge mode — a gossip sink.
        # Nobody relays to an ejected node; isolation is total.
        self.attack_log.append({"round": 10, **byzantine.attack_withhold(zeta)})
        self.tick(10)
        self.tick(11)
        byzantine.attack_withhold(zeta, on=False)

        rejected = {n.name: n.status()["rejects"] for n in self.nodes.values()}
        slashed = {n.name: sorted(n.slashed) for n in self.nodes.values()
                   if n.name in HONEST}
        self.say(f"attack phase done  total rejects={sum(rejected.values())} "
                 f"slashed={slashed.get('alpha', [])}")

    # -------------------------------------------------- phase 2b: late join
    def late_join(self, name: str, rnd: int):
        """Phase 2b: dynamic membership. delta starts with NOTHING but the
        genesis anchor and its keypair, pulls the full history, re-verifies
        every envelope, and only then starts participating."""
        self.say(f"— dynamic membership: {name} joins at round {rnd} —")
        keys = self._keys()
        ident = Identity(name, keys[name]["priv"])
        node = MeshNode(name, BASE_PORT + ALL.index(name),
                        anchor_mod.load(self.run_dir / "genesis-anchor.json"),
                        ident, self.run_dir / f"node-{name}",
                        peers=self._peers(exclude=name),
                        checkpoint_every=CHECKPOINT_EVERY)
        synced = node.self_heal()
        node.start()
        self.nodes[name] = node
        self.late_joiners.append({"node": name, "round": rnd,
                                  "fetched": synced["fetched"],
                                  "verify_ok": synced["verified"].get("ok")})
        self.say(f"  {name} bootstrapped from anchor alone: fetched="
                 f"{synced['fetched']} verify={synced['verified'].get('ok')}")
        self.tick(rnd)
        self.tick(rnd + 1)
        alphas_root = self.nodes["alpha"].state_root()
        self.say(f"  {name} converged with the mesh: "
                 f"{node.state_root() == alphas_root}")

    # ------------------------------------------------------------ phase 3
    def phase3_convergence_check(self):
        self.say("— phase 3: verifiable state convergence —")
        # the catch, demonstrated: partition alpha, let the mesh advance
        # without it, then cut it back in — it must heal with no restart.
        alpha = self.nodes["alpha"]
        dark = 17
        alpha.control({"op": "partition", "on": True})
        self.tick(dark)
        for node in self.nodes.values():
            if node is not alpha:
                node.submit("mesh.event", {"demo": "while-alpha-dark", "r": dark})
        self.tick(dark + 1)
        before_root, before_n = alpha.state_root(), alpha.status()["envelopes"]
        mesh_root = self.nodes["beta"].state_root()
        self.say(f"  alpha dark: {before_n} envelopes root={before_root[:16]}… "
                 f"vs mesh root={mesh_root[:16]}… diverged={before_root != mesh_root}")
        alpha.control({"op": "partition", "on": False})
        healed = alpha.self_heal()
        self.tick(dark + 2)
        after_root, after_n = alpha.state_root(), alpha.status()["envelopes"]
        self.say(f"  alpha healed: {before_n} -> {after_n} envelopes, "
                 f"fetched={healed['fetched']} "
                 f"verify={healed['verified'].get('ok')} "
                 f"root={after_root[:16]}…")
        recon = [e for e in alpha.envs.values()
                 if e["type"] == "reconciliation" and e["author"] == "alpha"]
        self.say(f"  reconciliation-event signed by alpha: "
                 f"{'seq ' + str(recon[-1]['seq']) if recon else 'MISSING'}")
        live = [self.nodes[n] for n in HONEST]
        roots = {n.state_root() for n in live}
        self.say(f"honest roots converged: {len(roots) == 1} "
                 f"root={sorted(roots)[0][:24]}…")
        a = self.nodes["alpha"]
        self.say("byzantine slashed: " +
                 ", ".join(f"{n}={n in a.slashed}" for n in BYZ) +
                 f"  stake_burned={a.stake_burned} ejected={sorted(a.ejected)}")

    # ------------------------------------------------ phase 4: live fork
    def phase4_live_fork(self):
        self.say("— phase 4: hot-swap upgrade + live fork —")
        # dissent: delta refuses to ever cross version 2
        self.nodes["delta"].control({"op": "set_fork_bias", "version": 1})
        # alpha drafts the upgrade; beta AND gamma co-sign the body BEFORE
        # alpha signs the final envelope (a co-signature must not cover its
        # own entry). Quorum at this point: 4 active validators -> 3 signatures.
        alpha = self.nodes["alpha"]
        seq = alpha._next_seq(alpha.name)
        body = {"mesh_id": alpha.mesh_id, "epoch": alpha.epoch,
                "protocol": alpha.protocol_version, "author": alpha.name,
                "seq": seq,
                "vc": {a: (max(s) if (s := alpha.by_author.get(a)) else 0)
                       for a in set(list(alpha.by_author) + [alpha.name])},
                "type": "protocol.upgrade",
                "payload": {"to_version": 2,
                            "reason": "v2: gossip-credit hardening, cheaper submits"},
                "pub": alpha.ident.pub_hex}
        body["vc"][alpha.name] = seq
        cos = [cosign_envelope(body, self.nodes[c].ident)
               for c in ("beta", "gamma")]
        body["payload"]["co_signers"] = cos
        proposal = sign_envelope(alpha.ident, body)
        for node in (alpha, self.nodes["beta"], self.nodes["gamma"]):
            node.ingest(proposal, via="self")
        for rnd in range(20, 24):
            self.tick(rnd)
        versions = {n.name: n.protocol_version for n in self.nodes.values()}
        forked = [n for n, v in versions.items() if v == 1]
        majority = [n for n, v in versions.items() if v == 2]
        self.say(f"upgrade v2 adopted by {majority}  forked off: {forked}")
        # the majority keeps operating on v2 — delta is forked off by the
        # protocol gate: it rejects every epoch-2 envelope as unsupported
        for rnd in range(24, 28):
            for n in majority:
                self.nodes[n].submit("mesh.event", {"fork-proof": rnd})
            self.tick(rnd)
        roots = {self.nodes[n].state_root() for n in majority}
        self.say(f"majority mesh converged post-fork: {len(roots) == 1}  "
                 f"delta frozen at v{self.nodes['delta'].protocol_version}")
        self.fork_info = {"proposal_seq": proposal["seq"],
                          "fork_round": 20, "adopted": majority,
                          "forked_off": forked, "versions": versions}

    # ------------------------------------------- phase 4b: crash + recovery
    def phase4b_crash_recovery(self):
        self.say("— phase 4b: crash + deterministic recovery —")
        ok = self.crash_and_recover("gamma")
        for rnd in range(28, 31):
            for n in ("alpha", "beta"):
                self.nodes[n].submit("mesh.event", {"post-crash": rnd})
            self.tick(rnd)
        # gamma rejoined; gossip fills the gap it missed while dead
        self.tick(31)
        gamma = self.nodes["gamma"]
        majority_roots = {self.nodes[n].state_root() for n in ("alpha", "beta")}
        self.say(f"gamma rejoined and re-converged: "
                 f"{gamma.state_root() in majority_roots} "
                 f"(missed events fetched via gossip, no restart)")
        self.tick(32)
        self.tick(33)
        return ok

    def crash_and_recover(self, name: str) -> bool:
        """Phase 4b: kill a validator mid-flight, respawn it from nothing but
        its own ledger + the genesis anchor, and let gossip fill the gap."""
        victim = self.nodes[name]
        pre_root, pre_envs = victim.state_root(), victim.status()["envelopes"]
        self.crash_recoveries.append({"node": name, "crash_round": self.rounds[-1],
                                      "envs_before": pre_envs,
                                      "root_before": pre_root})
        victim.stop()                      # hard crash: process gone
        self.say(f"  {name} CRASHED at round {self.rounds[-1]} "
                 f"({pre_envs} envelopes, root={pre_root[:16]}…)")
        keys = self._keys()
        ident = Identity(name, keys[name]["priv"])
        node = MeshNode(name, BASE_PORT + ALL.index(name),
                        anchor_mod.load(self.run_dir / "genesis-anchor.json"),
                        ident, self.run_dir / f"node-{name}",
                        peers=self._peers(exclude=name),
                        checkpoint_every=CHECKPOINT_EVERY)
        reb = node.rebuild_from_ledger()
        post_root = node.state_root()
        ok = post_root == pre_root and reb["envs"] >= pre_envs
        self.say(f"  respawned from ledger: {reb['envs']} envelopes "
                 f"replay={reb['replayed']} state-identical={ok}")
        node.start()
        self.nodes[name] = node
        self.crash_recoveries[-1].update({"respawned": True,
                                          "state_identical": ok,
                                          "replayed": reb["replayed"]})
        return ok

    # ------------------------------------------------------------ phase 5
    def phase5_proof(self) -> dict:
        self.say("— phase 5: adversarial replay report + chronicle —")
        out = self.run_dir / "audit-replay-report.json"
        report = replay_report(self, self.attack_log, self.rounds, out,
                               byz=BYZ, late_joiners=self.late_joiners,
                               crash_recoveries=self.crash_recoveries)
        if not self.quiet:
            print(render_report(report))
        statuses = [n.status() for n in self.nodes.values()]
        # persist the fullest anchor trail (alpha's in-memory copy carries
        # every inscription it observed) — the mesh's permanent record
        anchor_mod.save(self.nodes["alpha"].anchor,
                        self.run_dir / "genesis-anchor.json")
        chr_ = show.chronicle(self.anchor["mesh_id"], self.anchor, statuses,
                              self.attack_log, [self.fork_info],
                              self.started_ts, self.bootstrap,
                              self.run_dir / "chronicle.json",
                              extra={"late_joiners": self.late_joiners,
                                     "crash_recoveries": self.crash_recoveries,
                                     "byzantine_names": BYZ,
                                     "replay": report["deterministic_replay"],
                                     "replay_proved": report["deterministic_replay"]["deterministic"]})
        # the chronicle must verify against the bootstrap key it claims
        # the bootstrap node's final anchor: genesis + the complete audit trail
        anchor_mod.save(self.nodes["alpha"].anchor, self.run_dir / "final-anchor.json")
        body = {k: v for k, v in chr_.items() if k != "sig"}
        assert verify_hex(self.bootstrap.pub_hex, chr_["sig"],
                          canonical(body).encode("utf-8")), "chronicle sig broken"
        (self.run_dir / "chronicle.md").write_text(show.render_chronicle(chr_))
        self.say(f"chronicle sealed  {self.run_dir / 'chronicle.json'} "
                 f"+ chronicle.md")
        return report


def main():
    t0 = time.time()
    print("MOLT MESH — THE BYZANTIUM SWARM", "=" * 58)
    s = Scenario()
    s.seed()
    s.spawn()
    s.phase2_gossip_and_attacks()
    s.late_join("delta", rnd=12)
    s.phase3_convergence_check()
    s.phase4_live_fork()
    s.phase4b_crash_recovery()
    report = s.phase5_proof()
    for node in s.nodes.values():
        node.stop()
    print(f"completed in {time.time() - t0:.1f}s — artifacts in {s.run_dir}")
    return 0 if report["verdict"].startswith("PASS") else 1


if __name__ == "__main__":
    sys.exit(main())
