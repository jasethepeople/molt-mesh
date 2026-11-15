"""molt-show serve — the live mesh observatory.

A local HTTP dashboard (default 127.0.0.1:8799) that reads a run directory
(genesis anchor, roster, per-node ledgers) and renders:

  - the mesh at a glance: validators, slashes, forks, credits, checkpoints
  - per-node panels with a live probe of each node's /status endpoint
  - the tail of each node's ledger chain

The page is served server-side from the recorded ledgers, so it works for
archived runs too; live node probes are best-effort and degrade gracefully.
"""
from __future__ import annotations

import json
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .core import Ledger
from .anchor import load as load_anchor, verify_trail

DEFAULT_PORT = 8799

_CSS = """
:root { color-scheme: dark; }
* { box-sizing: border-box; }
body { margin: 0; background: #0d0f12; color: #d7dce3;
       font: 14px/1.55 ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
header { padding: 22px 26px 14px; border-bottom: 1px solid #22262c; }
h1 { margin: 0 0 4px; font-size: 17px; letter-spacing: 0.4px; color: #e8ecf1; }
h1 .peg { color: #7fd4a8; }
.sub { color: #79818d; font-size: 12px; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(340px, 1fr)); gap: 14px; padding: 18px 26px; }
.card { background: #14171c; border: 1px solid #232830; border-radius: 10px; padding: 14px 16px; }
.card h2 { margin: 0 0 8px; font-size: 13px; color: #9fd8b4; display: flex; justify-content: space-between; }
.live { font-size: 10px; padding: 1px 7px; border-radius: 9px; background: #1d3524; color: #7fd4a8; }
.dead { background: #351d1d; color: #d47f7f; }
.kv { display: grid; grid-template-columns: 130px 1fr; gap: 2px 10px; font-size: 12px; }
.kv b { color: #79818d; font-weight: 500; }
.ejected { color: #d47f7f; }
.ok { color: #7fd4a8; }
pre.tail { margin: 10px 0 0; padding: 8px 10px; background: #0f1216; border: 1px solid #1e2329;
           border-radius: 6px; max-height: 150px; overflow: auto; font-size: 11px; color: #9aa2ad; }
footer { padding: 12px 26px 26px; color: #565d66; font-size: 11px; }
.summary { padding: 14px 26px 0; }
.badge { display: inline-block; margin-right: 8px; padding: 3px 10px; border-radius: 8px;
         font-size: 12px; background: #14171c; border: 1px solid #232830; }
"""


class Observatory:
    """One observatory instance bound to a run directory."""

    def __init__(self, run_dir: Path, port: int = DEFAULT_PORT):
        self.run_dir = Path(run_dir)
        self.port = port
        genesis = self.run_dir / "genesis-anchor.json"
        final = self.run_dir / "final-anchor.json"
        self.anchor = load_anchor(final if final.exists() else genesis)
        roster_path = self.run_dir / "mesh.json"
        self.roster = (json.loads(roster_path.read_text())
                       if roster_path.exists()
                       else [{"name": d.name.removeprefix("node-"), "url": ""}
                             for d in sorted(self.run_dir.glob("node-*"))])

    # ---------------------------------------------------------------- views
    def _probe(self, url: str, timeout: float = 0.6) -> dict | None:
        try:
            with urllib.request.urlopen(url + "/status", timeout=timeout) as r:
                return json.loads(r.read())
        except Exception:
            return None

    def _ledger_tail(self, name: str, n: int = 6) -> str:
        path = self.run_dir / f"node-{name}" / f"{name}-ledger.jsonl"
        if not path.exists():
            return "(no ledger)"
        led = Ledger(path)
        lines = []
        for e in led.events[-n:]:
            kind = e["kind"]
            who = (e.get("env") or {}).get("author") or \
                  (e.get("detail") or {}).get("who") or ""
            lines.append(f"#{e['seq']:<4} {kind:<26} {who}")
        return "\n".join(lines) or "(empty)"

    def _node_card(self, entry: dict) -> str:
        name = entry["name"]
        url = entry.get("url", "")
        status = self._probe(url) if url else None
        path = self.run_dir / f"node-{name}" / f"{name}-ledger.jsonl"
        led = Ledger(path) if path.exists() else Ledger(None)
        envs = sum(1 for e in led.events if e["kind"] == "env.accept")
        slashed = sorted({(e.get("detail") or {}).get("who")
                          for e in led.events
                          if e["kind"] in ("validator.slashed", "validator.ejected")})
        rejected = sum(1 for e in led.events if e["kind"] == "env.reject")
        protocol = 1
        upgraded = [e["detail"].get("version") for e in led.events
                    if e["kind"] == "protocol.upgraded"]
        if upgraded:
            protocol = max(upgraded)
        accepted = sorted(e["detail"].get("round") for e in led.events
                          if e["kind"] == "checkpoint.accepted")
        badge = f'<span class="badge {"live" if status else "dead"}">' \
                f'{"LIVE" if status else "ARCHIVED"}</span>'
        bal = status.get("balances") if status else None
        bal_html = ""
        if bal:
            bal_html = "<b>credits</b> " + ", ".join(
                f"{k}:{v}" for k, v in sorted(bal.items())) + "<br>"
        rows = [
            ("envelopes", envs), ("rejected", rejected),
            ("protocol", f"v{protocol}"),
            ("checkpoints", ", ".join(map(str, accepted)) or "—"),
            ("slashed/ejected", ("⚠ " if slashed else "") + ", ".join(slashed) or "—"),
        ]
        kv = "".join(f"<b>{k}</b><span>{v}</span>" for k, v in rows)
        live_rows = ""
        if status:
            live_rows = (f'<b>state root</b> <span class="ok">'
                         f"{str(status.get('state_root'))[:24]}…</span><br>"
                         f"{bal_html}")
        return (f'<div class="card"><h2>{name} {badge}'
                f'<span style="color:#565d66">{url}</span></h2>'
                f'{live_rows}<div class="kv">{kv}</div>'
                f"<pre class='tail'>{self._ledger_tail(name)}</pre></div>")

    def page(self) -> str:
        validators = sorted(self.anchor["validators"])
        trail = self.anchor.get("audit_trail", [])
        trail_ok = "ok" if not verify_trail(self.anchor) else "TAMPERED"
        events = sorted(
            ({ "seq": e["seq"], "kind": e["kind"], "who": e.get("detail", {}).get("who")}
             for name in validators
             for e in Ledger(self.run_dir / f"node-{name}" / f"{name}-ledger.jsonl").events
             if e["kind"] in ("validator.slashed", "validator.ejected",
                              "protocol.upgraded", "fork.refused", "state.divergence")),
            key=lambda x: x["seq"])
        cards = "".join(self._node_card(e) for e in self.roster) or \
            "<div class='card'>no roster — regenerate a run with " \
            "<code>python3 -m moltmesh mesh</code></div>"
        events_html = "<br>".join(
            f"#{e['seq']} {e['kind']} {e.get('who') or ''}" for e in events[-14:]) \
            or "—"
        return f"""<!doctype html><html><head><meta charset="utf-8">
<title>byzantium-swarm — molt-mesh observatory</title><style>{_CSS}</style></head>
<body><header><h1><span class="peg">⢕⣿</span> {self.anchor['mesh_id']} — molt-mesh observatory</h1>
<div class="sub">genesis anchor {self.anchor['hash'][:32]}… · audit trail
<span class="{'ok' if trail_ok == 'ok' else 'ejected'}">{trail_ok}</span> ·
{len(trail)} inscriptions ·
validators: {', '.join(validators)}</div></header>
<div class="summary">mesh events: {events_html}</div>
<div class="grid">{cards}</div>
<footer>served from {self.run_dir} — live probes fall back to archived ledgers ·
refresh for new probes</footer></body></html>"""

    # --------------------------------------------------------------- server
    def start(self) -> ThreadingHTTPServer:
        obs = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code: int, body: bytes, ctype: str):
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                if urlparse(self.path).path in ("/", "/index.html"):
                    self._send(200, obs.page().encode("utf-8"), "text/html; charset=utf-8")
                elif self.path == "/api/summary":
                    summary = {"mesh_id": obs.anchor["mesh_id"],
                               "anchor_hash": obs.anchor["hash"],
                               "trail_len": len(obs.anchor.get("audit_trail", [])),
                               "validators": sorted(obs.anchor["validators"]),
                               "nodes": [{"name": e["name"], "url": e.get("url"),
                                          "live": obs._probe(e.get("url", "")) is not None}
                                         for e in obs.roster],
                               "ts": time.time()}
                    self._send(200, json.dumps(summary).encode(), "application/json")
                else:
                    self._send(404, b"not found", "text/plain")

        srv = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        return srv


def serve(run_dir: str | Path, port: int = DEFAULT_PORT, once: bool = False):
    obs = Observatory(Path(run_dir), port)
    srv = obs.start()
    if once:
        html = obs.page()
        srv.shutdown()
        return html
    print(f"molt-show observatory → http://127.0.0.1:{port}  (run: {run_dir})")
    print("Ctrl-C to stop.")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.shutdown()
