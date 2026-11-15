"""molt-mesh command line.

    python3 -m moltmesh mesh                 run the full Byzantium scenario
    python3 -m moltmesh show  runs/byzantium render a run: mesh + chronicle
    python3 -m moltmesh audit runs/byzantium verify anchor trail + all ledgers
    python3 -m moltmesh chronicle runs/...   re-render chronicle.md
    python3 -m moltmesh serve  runs/byzantium live web observatory (port 8799)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from . import anchor as anchor_mod
from .core import Ledger
from .show import render_chronicle, render_mesh


def _load_run(run: Path) -> tuple[dict, dict]:
    genesis = run / "genesis-anchor.json"
    final = run / "final-anchor.json"
    anchor = anchor_mod.load(final if final.exists() else genesis)
    nodes = []
    if (run / "mesh.json").exists():
        nodes = json.loads((run / "mesh.json").read_text())
    else:                                   # archived runs predating mesh.json
        for d in sorted(run.glob("node-*")):
            nodes.append({"name": d.name.removeprefix("node-"), "url": "",
                          "port": 0})
    return anchor, nodes


def _audit(run: Path) -> int:
    anchor, nodes = _load_run(run)
    print(f"anchor {anchor['mesh_id']}  {anchor['hash'][:24]}…")
    keys_file = run / "keys" / "keys.json"
    boot_pub = (json.loads(keys_file.read_text())
                .get("bootstrap", {}).get("pub", "")) if keys_file.exists() else ""
    errs = anchor_mod.verify_anchor(anchor, boot_pub)
    trail = anchor_mod.verify_trail(anchor)
    trail_bad = bool(trail)
    print(f"audit trail   {'ok' if not trail else trail}")
    bad = trail_bad
    for n in nodes:
        p = run / f"node-{n['name']}" / f"{n['name']}-ledger.jsonl"
        led = Ledger(p) if p.exists() else None
        chain = led.verify_chain() if led else ["missing ledger"]
        print(f"{n['name']:9s} {len(led.events) if led else 0:4d} events  "
              f"chain {'ok' if not chain else chain}")
        bad += bool(chain)
    return 1 if bad else 0


def _chronicle(run: Path) -> int:
    c = json.loads((run / "chronicle.json").read_text())
    md = run / "chronicle.md"
    md.write_text(render_chronicle(c) + "\n")
    print(f"chronicle rendered -> {md}")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "mesh"
    if cmd == "mesh":
        from .scenario import main as scenario_main
        return scenario_main()
    if cmd == "show":
        run = Path(argv[1]) if len(argv) > 1 else Path("runs/byzantium")
        anchor, nodes = _load_run(run)
        print(render_mesh(anchor, nodes))
        if (run / "chronicle.json").exists():
            print(render_chronicle(json.loads(
                (run / "chronicle.json").read_text())))
        return 0
    if cmd == "audit":
        return _audit(Path(argv[1] if len(argv) > 1 else "runs/byzantium"))
    if cmd == "chronicle":
        return _chronicle(Path(argv[1] if len(argv) > 1 else "runs/byzantium"))
    if cmd == "serve":
        from .observatory import serve
        return serve(Path(argv[1] if len(argv) > 1 else "runs/byzantium"))
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main())
