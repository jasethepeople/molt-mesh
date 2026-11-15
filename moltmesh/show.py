"""molt-show — the observatory: human-readable views of a mesh node.

Commands render either live node status (via its HTTP endpoint) or the
chronicle: the mesh's entire life as a narrative, from genesis anchor to
Byzantine recovery, written by the bootstrap node and sealed with its
Ed25519 signature.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .core import canonical


# --------------------------------------------------------------------- views
def render_status(node: dict) -> str:
    rules = node.get("rules", {})
    lines = [
        f"node        {node['node']} ({node['node_id']})",
        f"endpoint    {node['url']}",
        f"mesh        {node['mesh_id']}  protocol v{node['protocol_version']} "
        f"(epoch {node['epoch']})",
        f"rules       threshold={rules.get('checkpoint_threshold')} "
        f"fee={rules.get('submit_fee')} reward={rules.get('checkpoint_reward')}",
        f"envelopes   {node['envelopes']}   state-root {node.get('state_root', '')[:24]}…",
        f"peers       {', '.join(sorted(node.get('peers', []))) or '—'}",
        f"ejected     {', '.join(sorted(node.get('ejected', []))) or '—'}",
        f"credits     " + " ".join(f"{k}={v}" for k, v in sorted(node.get("credits", {}).items())),
        f"stake       " + " ".join(f"{k}={v}" for k, v in sorted(node.get("stake", {}).items())),
        f"checkpoints {len(node.get('checkpoints', []))} accepted   "
        f"divergences {len(node.get('divergences', []))} healed",
    ]
    if node.get("withholding"):
        lines.append("!!          sponge mode (withholding gossip)")
    if node.get("partitioned"):
        lines.append("!!          partitioned")
    if node.get("forked_off"):
        lines.append(f"!!          forked off at v{node['forked_off']}")
    return "\n".join(lines)


def render_ledger(ledger_path: Path, limit: int = 200) -> str:
    lines = []
    entries = [json.loads(l) for l in ledger_path.read_text().splitlines() if l.strip()]
    for e in entries[-limit:]:
        env = e.get("env")
        head = f"[{e['seq']:>4}] {e['kind']:<28}"
        if env:
            head += f" {env['author']}/{env['seq']} e{env['epoch']} via={e.get('via', '?')}"
        detail = e.get("detail")
        if detail:
            head += f"  {json.dumps(detail, sort_keys=True)[:90]}"
        lines.append(head)
    return "\n".join(lines) if lines else "(empty ledger)"


# ----------------------------------------------------------------- chronicle
def chronicle(mesh_id: str, anchor: dict, nodes: list[dict],
              attack_log: list[dict], upgrades: list[dict],
              started_ts: float, signer, out_path: Path,
              extra: dict | None = None) -> dict:
    """The mesh's entire life as a signed narrative. Written by the bootstrap
    node; the signature covers the canonical body."""
    extra = extra or {}
    byz = set(extra.get("byzantine_names", ["epsilon"]))
    honest = [n for n in nodes if n["node"] not in byz]
    # convergence is judged over the majority that stayed on the upgraded
    # protocol; the forked-off dissenter diverging IS the fork working.
    forked = {n["node"] for n in nodes if n.get("forked_off")}
    majority = [n for n in honest if n["node"] not in forked]
    roots = sorted({n.get("state_root", "") for n in majority})
    slashed = sorted({w for n in nodes for w in n.get("ejected", [])} & byz)

    body = {
        "kind": "molt-show/chronicle",
        "mesh_id": mesh_id,
        "protocol_version": max(n["protocol_version"] for n in nodes),
        "started_ts": started_ts,
        "sealed_ts": time.time(),
        "genesis_anchor_hash": anchor["hash"],
        "genesis_validators": sorted(anchor["validators"]),
        "final_state_root": roots[0] if len(roots) == 1 else "DIVERGENT",
        "nodes": [{"node": n["node"], "node_id": n["node_id"], "url": n["url"],
                   "envelopes": n["envelopes"], "credits": n.get("balances", {}),
                   "stake": n.get("stake", {}),
                   "checkpoints": n.get("checkpoints", 0) if isinstance(n.get("checkpoints"), int) else len(n["checkpoints"]),
                   "divergences_healed": n.get("divergences", 0) if isinstance(n.get("divergences"), int) else len(n["divergences"])}
                  for n in sorted(nodes, key=lambda x: x["node"])],
        "attacks": attack_log,
        "upgrades": upgrades,
        "byzantine_nodes_slashed": sorted(slashed),
        "converged": len(roots) == 1,
        "forked_off": sorted(forked),
        "majority": sorted(n["node"] for n in majority),
        "late_joiners": sorted(extra.get("late_joiners", [])),
        "crash_recoveries": extra.get("crash_recoveries", []),
        "replay_proved": bool(extra.get("replay_proved", False)),
    }
    body["sig"] = signer.sign_hex(canonical(body).encode())
    out_path.write_text(json.dumps(body, indent=2) + "\n")
    return body


def render_chronicle(c: dict) -> str:
    lines = [
        "=" * 74,
        f"  THE CHRONICLE OF MESH {c['mesh_id']}",
        "  from seed to Byzantine recovery, as recorded by the bootstrap node",
        "=" * 74,
        "",
        f"Genesis anchor {c['genesis_anchor_hash'][:24]}… bound the swarm at "
        f"protocol v1 with validators {', '.join(c['genesis_validators'])}.",
        "",
        "— THE COLONY —",
    ]
    for n in c["nodes"]:
        lines.append(f"  {n['node']:<8} {n['node_id']}  {n['envelopes']:>3} envelopes, "
                     f"{n['checkpoints']} checkpoints, {n['divergences_healed']} healings, "
                     f"credits {json.dumps(n['credits'])}")
    lines += ["", "— THE ATTACKS —"]
    for a in c["attacks"]:
        if "deliveries" in a:
            dels = list(a["deliveries"].values()) if isinstance(
                a["deliveries"], dict) else a["deliveries"]
            verdicts = sorted({str(d.get("verdict") or d.get("ok"))
                               for d in dels if isinstance(d, dict)})
            outcome = f"{len(dels)} deliveries → {', '.join(verdicts) or 'rejected'}"
        else:
            outcome = str(a.get("verdict") or a.get("why") or a.get("applied") or "")
        lines.append(f"  [{a['attack']}] {outcome}"
                     f"{(' — ' + a['why']) if a.get('why') else ''}")
    if c["byzantine_nodes_slashed"]:
        lines += ["",
                  "— THE JUDGMENT —",
                  f"  Slashed and ejected: {', '.join(c['byzantine_nodes_slashed'])}. "
                  "Cryptographic equivocation evidence is inscribed permanently "
                  "in the molt-anchor audit trail."]
    for u in c["upgrades"]:
        lines += ["", "— THE ASCENSION —",
                  f"  Protocol v{u.get('to_version', 2)} adopted by quorum at "
                  f"round {u.get('fork_round', u.get('round', '?'))}; "
                  f"majority: {', '.join(u.get('adopted', u.get('majority', [])))}; "
                  f"forked off: {', '.join(u.get('forked_off', [])) or 'none'}."]
    lines += ["", "— THE CONVERGENCE —"]
    if c["converged"]:
        lines.append(f"  Majority mesh ({', '.join(c['majority'])}) converged on "
                     f"state root {c['final_state_root'][:32]}…")
    else:
        lines.append("  THE MESH DIVERGED — chronicle refuses to lie.")
    if c.get("forked_off"):
        lines.append(f"  Dissenters {', '.join(c['forked_off'])} run the old protocol on "
                     "their own fork — alive, isolated, unmourned. That is not "
                     "divergence; that is the fork working as designed.")
    lines += ["", f"sealed by {c['sig'][:32]}… (Ed25519, bootstrap key)"]
    return "\n".join(lines)

def render_mesh(anchor: dict, nodes: list[dict]) -> str:
    """A run-level view: the anchor, the colony roster, per-node health."""
    lines = ["=" * 74, f"  MOLT MESH — {anchor['mesh_id']}   "
             f"anchor {anchor['hash'][:24]}…", "=" * 74]
    v = anchor["validators"]
    lines.append(f"validators  {len(v)}: " +
                 ", ".join(f"{n}(stake {d.get('stake', '?')})"
                           for n, d in sorted(v.items())))
    trail = anchor.get("audit_trail", [])
    lines.append(f"anchor trail: {len(trail)} inscriptions")
    lines += ["", "colony:"]
    for n in nodes:
        lines.append(f"  {n['name']:9s} {n.get('url') or 'archived'}")
    return "\n".join(lines)
