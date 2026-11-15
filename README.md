# Molt Mesh — The Byzantium Swarm

A colony of sovereign agents coordinating over a partially adversarial network.
Every node runs its own molt-core event store with its own Ed25519 identity,
trusts no other node's log, and speaks only signed molt-event envelopes over
HTTP. Consensus is reached via molt-verify (full-chain re-verification) and
molt-anchor (2-of-3 checkpoint proposals against Merkle roots).

Part of the molt-stack lineage: `Projects/sovereign-agent-zero` (molt-show,
molt-reactor, molt-audit conventions) extended to a networked, Byzantine-tolerant
mesh.

## Quick start

```bash
cd Projects/molt-mesh
python3 -m moltmesh mesh                    # full six-phase gauntlet (~60-120s)
python3 -m moltmesh audit runs/byzantium    # verify anchor trail + every ledger chain
python3 -m moltmesh show   runs/byzantium   # mesh summary + sealed chronicle
python3 -m moltmesh serve  runs/byzantium   # web observatory at http://127.0.0.1:8799
python3 tests/test_mesh.py                  # 31-test invariant suite (~6s)
cat runs/byzantium/chronicle.md             # the sealed narrative of the mesh's life
```

Exit code 0 means the adversarial replay report verdict is PASS.

## The phases

1. **Seed** — `molt-anchor` forges a signed genesis anchor (mesh id, validator
   set, protocol version, permanent audit trail). `molt-key-management` mints
   one Ed25519 identity per node (keys in `runs/<run>/keys/`, 0600).
2. **Gossip + attacks** — each node exposes HTTP endpoints (`/ingest`,
   `/gossip`, `/pull`, `/digest`, `/control`). Push carries watermarks; pull is
   anti-entropy driven by digests; every envelope is signature-verified,
   epoch-checked, monotonicity-checked and causality-checked (vector clocks)
   before acceptance. Two colluding Byzantine validators attack while the mesh
   runs (see below).
3. **Dynamic membership** — delta joins mid-run holding NOTHING but the genesis
   anchor and its keypair: it pulls the entire event chain from the bootstrap,
   re-verifies every envelope, and only then participates.
4. **Convergence** — every `checkpoint_every` rounds each node signs a
   `checkpoint.proposal` carrying its state Merkle root. A checkpoint is
   accepted at a strict-majority threshold (`max(ruleset floor, active/2+1)`);
   a node whose root disagrees — or is genuinely behind — runs `self_heal()`
   (pull missing envelopes, `verify_full()` re-verification, signed
   `reconciliation` event). A node that is merely *ahead* of the proposers
   skips the round quietly instead of crying divergence. No restart, no human.
5. **Fork + crash** — the majority votes (author + co-signatures, quorum
   3-of-4) to hot-swap the protocol to v2. Delta refuses (fork bias) and is
   forked off alive at v1. Then gamma is hard-crashed mid-flight and respawned
   from nothing but its own ledger file + the anchor: the deterministic ledger
   rebuild reproduces its exact state, gossip fills the gap, consensus resumes.
6. **Proof** — `audit.py` re-verifies every envelope per node, re-derives
   credits, re-resolves checkpoints, and replays each ledger into a fresh
   in-memory node: all derived state must match the live node bit-for-bit
   (`deterministic_replay`). `show.py` seals the chronicle with the bootstrap
   key. Verdict PASS requires convergence, isolation, zero loss, clean audits
   and deterministic replay — all at once.

## The Byzantine validators and their fate

Two colluding adversaries, both Ed25519-valid members of the genesis validator
set:

- **epsilon** replays captured old envelopes (rejected as stale-epoch/duplicate),
  rewinds a causal vector clock (rejected as causal-violation), then
  equivocates — two valid signatures over conflicting bodies at the same
  (epoch, seq).
- **zeta** fabricates conflicting checkpoint proposals (two different Merkle
  roots to two different peers — proposal equivocation), then goes dark as a
  gossip sink.

Every honest node applies the same deterministic rule: the lexicographically
smaller envelope id holds the (author, seq) slot, the loser is quarantined
(excluded from the state root), and the conflict itself becomes cryptographic
evidence that gossips mesh-wide. First honest witness to accumulate the
evidence slashes the equivocator: stake burned, credits forfeited, ejected
from the validator set, written into the anchor audit trail forever. Both
Byzantine validators are isolated within the same gossip round their evidence
lands — no coordinator, just signatures.

## The live fork

At round 20 the majority votes (author + co-signatures, quorum-checked) to
upgrade the protocol to v2. Beta refuses (fork bias) and is forked off: it
rejects every epoch-2 envelope and the majority rejects its stale-epoch ones.
Both sides keep running without downtime; the majority converges on the v2
state, beta lives on its own v1 fork. Rules are hot-swappable because they are
data: `rules_by_epoch` is derived from signed upgrade envelopes, never code.

## Project layout

```
moltmesh/
  core.py       molt-core: canonical JSON, Ed25519 envelopes, hash-chained ledger
  identity.py   molt-key-management: Ed25519 identities, private key store
  anchor.py     molt-anchor: genesis anchor + permanent audit trail
  reactor.py    molt-reactor: V1/V2 rulesets, credit engine
  node.py       the mesh node: gossip engine, validation pipeline, checkpoints,
                self-healing, slashing, fork semantics
  byzantine.py  the attack script (epsilon + zeta)
  audit.py      molt-audit: per-node audits, adversarial replay report,
                deterministic replay engine
  show.py       molt-show: observatory views + the sealed chronicle
  observatory.py molt-show web observatory (`python3 -m moltmesh serve`)
  scenario.py   the six-phase orchestrator
  __main__.py   CLI: mesh / show / audit / chronicle / serve
tests/test_mesh.py  31 invariant tests: anchors, envelopes, convergence,
                checkpoints, slashing, replay gates, fork, crash recovery
runs/byzantium/ artifacts: genesis-anchor.json (with its 10-inscription
                audit trail), mesh.json roster, per-node ledgers,
                audit-replay-report.json, chronicle.json + chronicle.md
```

## Design guarantees

- No node trusts another node's log — only signatures and its own genesis anchor.
- Determinism: identical envelope content produces identical state roots on
  every honest node; ties break by envelope-id ordering, never arrival order.
- Crash recovery is ledger replay: a respawned node re-derives its exact state
  from its own log (the same engine the audit uses for deterministic replay).
- Zero valid-event loss across the majority, proven by set intersection in the
  replay report (envelopes from proven-equivocators and post-fork dissenters
  are excluded by construction, not by fiat).
- The replay report verdict is PASS only when convergence, isolation, zero
  loss, per-node audits AND deterministic replay are all clean.

Private keys under `runs/<run>/keys/` are 0600 — never commit, move, or publish.
