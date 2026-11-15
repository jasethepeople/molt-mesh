==========================================================================
  THE CHRONICLE OF MESH byzantium-swarm
  from seed to Byzantine recovery, as recorded by the bootstrap node
==========================================================================

Genesis anchor ea98e45a03e50c60b454598c… bound the swarm at protocol v1 with validators alpha, beta, delta, epsilon, gamma, zeta.

— THE COLONY —
  alpha    node:alpha@bd258d03c98e4bf3  101 envelopes, 5 checkpoints, 0 healings, credits {"alpha": 206, "beta": 205, "gamma": 204, "delta": 305, "epsilon": 0, "zeta": 0}
  beta     node:beta@2af640ade6dcb36e  101 envelopes, 5 checkpoints, 0 healings, credits {"alpha": 206, "beta": 205, "gamma": 204, "delta": 305, "epsilon": 0, "zeta": 0}
  delta    node:delta@862ef0a9898d0594   46 envelopes, 1 checkpoints, 0 healings, credits {"alpha": 147, "beta": 146, "gamma": 146, "delta": 133, "epsilon": 10, "zeta": 10}
  epsilon  node:epsilon@fc62384b69f32639   97 envelopes, 5 checkpoints, 2 healings, credits {"alpha": 206, "beta": 205, "gamma": 204, "delta": 305, "epsilon": 0, "zeta": 0}
  gamma    node:gamma@110b2cbe20dfa841  101 envelopes, 5 checkpoints, 0 healings, credits {"alpha": 206, "beta": 205, "gamma": 204, "delta": 305, "epsilon": 0, "zeta": 0}
  zeta     node:zeta@6a9667fc9075f15a   99 envelopes, 5 checkpoints, 2 healings, credits {"alpha": 206, "beta": 205, "gamma": 204, "delta": 305, "epsilon": 0, "zeta": 0}

— THE ATTACKS —
  [replay (epoch-replay)] 9 deliveries → duplicate
  [causal-monotonicity-violation] reject — causal-violation
  [equivocation] 2 deliveries → accept
  [fabricated-checkpoint-proposals] 2 deliveries → accept
  [withholding] True

— THE JUDGMENT —
  Slashed and ejected: epsilon, zeta. Cryptographic equivocation evidence is inscribed permanently in the molt-anchor audit trail.

— THE ASCENSION —
  Protocol v2 adopted by quorum at round 20; majority: alpha, beta, gamma, epsilon, zeta; forked off: delta.

— THE CONVERGENCE —
  Majority mesh (alpha, beta, gamma) converged on state root 6bb05fa673a3a402da9be2e3e9fbdc60…
  Dissenters delta run the old protocol on their own fork — alive, isolated, unmourned. That is not divergence; that is the fork working as designed.

sealed by 1b468daf3ddf184609bb27927f83715c… (Ed25519, bootstrap key)