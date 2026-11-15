"""molt-reactor — the mesh's reflex engine: credits, fees, slashing, upgrades.

A ruleset is a plain JSON document. It is *hot-swappable*: the active
ruleset is derived from the highest-round signed `protocol.upgrade` event
accepted by the mesh — never read from disk. Two ruleset versions shipped:

  v1 (Byzantium base)
    checkpoint_reward: +5 credits to each validator whose proposal matched
                       the accepted checkpoint root
    gossip_serve:      +1 credit per 10 unique envelopes relayed
    submit_fee:        -1 credit per mesh event the node authors
    stake:             50 credits bonded at genesis; slashed on equivocation
    checkpoint_threshold: 2 of 3 validators
    gossip_fanout:     all peers (full mesh of honest nodes)

  v2 (The Concord patch — demonstrated live upgrade)
    checkpoint_reward raised to +8, submit_fee lowered to 0 — an economic
    soft-fork. A node that refuses the upgrade is forked off: it keeps
    speaking v1 while the majority speaks v2, and the two meshes diverge.

Balances are *derived state*: a pure function of the accepted event stream,
recomputed by replay. No ledger is authoritative; every node computes the
same balances from the same events or the checkpoint will catch the drift.
"""
from __future__ import annotations

V1_RULES = {
    "version": 1,
    "checkpoint_reward": 5,
    "gossip_serve_divisor": 10,
    "gossip_serve_reward": 1,
    "submit_fee": 1,
    "stake": 50,
    "checkpoint_threshold": 2,
    "gossip_fanout": 0,   # 0 = all known peers
}

V2_RULES = {
    **V1_RULES,
    "version": 2,
    "checkpoint_reward": 8,
    "submit_fee": 0,
}


def rule_summary(rules: dict) -> str:
    return (f"v{rules['version']} | checkpoint_reward=+{rules['checkpoint_reward']} "
            f"| serve=+{rules['gossip_serve_reward']}/{rules['gossip_serve_divisor']} "
            f"| fee={rules['submit_fee']} | threshold={rules['checkpoint_threshold']}"
            f"-of-N | fanout={'all' if rules['gossip_fanout'] == 0 else rules['gossip_fanout']}")


class CreditEngine:
    """Derives balances purely from an ordered stream of accepted envelopes.

    This is the replay-side implementation used by molt-audit; the live node
    applies the same deltas incrementally in node.py. Both must agree.
    """

    def __init__(self, rules_by_epoch: dict[int, dict], validators: dict):
        self.rules_by_epoch = rules_by_epoch
        self.validators = dict(validators)   # name -> {pub, stake}
        self.balances: dict[str, int] = {}
        self.treasury = 0

    def balance(self, node: str) -> int:
        stake = self.validators.get(node, {}).get("stake", 0)
        return self.balances.get(node, 0) + (stake if node in self.validators else 0)

    def apply(self, env: dict, relayed_count: dict[str, int],
              accepted_proposals: list[dict]):
        """Fold one envelope into derived balances. `relayed_count` maps
        node -> envelopes it served to this node; `accepted_proposals` is the
        set of matching proposals at the current checkpoint round."""
        rules = self.rules_by_epoch.get(env["epoch"], self.rules_by_epoch[max(self.rules_by_epoch)])
        t = env["type"]
        author = env["author"]
        if t == "mesh.event" and author in self.validators:
            self.balances[author] = self.balances.get(author, 0) - rules["submit_fee"]
            self.treasury += rules["submit_fee"]
        elif t == "checkpoint.accepted":
            for p in accepted_proposals:
                who = p["author"]
                if who in self.validators:
                    self.balances[who] = self.balances.get(who, 0) + rules["checkpoint_reward"]
            for who, n in relayed_count.items():
                if who in self.validators:
                    self.balances[who] = self.balances.get(who, 0) + \
                        (n // rules["gossip_serve_divisor"]) * rules["gossip_serve_reward"]
        elif t == "validator.slashed" and author in self.validators:
            burned = self.validators[author].get("stake", 0)
            self.treasury += burned
            self.validators[author]["stake"] = 0