#!/usr/bin/env bash
# Molt Mesh — The Byzantium Swarm: one-command full run.
set -euo pipefail
cd "$(dirname "$0")"
python3 -m moltmesh.scenario
echo
echo "Artifacts:"
ls -1 runs/byzantium/
