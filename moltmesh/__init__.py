"""molt-mesh — The Byzantium Swarm.

A colony of sovereign agents coordinating over a partially adversarial
network. Every node runs its own molt-core event store, signs with its own
Ed25519 identity, and trusts no other node's log. Coordination happens
exclusively through signed molt-event envelopes exchanged over HTTP;
consensus is reached via molt-verify and molt-anchor checkpoints.
"""
