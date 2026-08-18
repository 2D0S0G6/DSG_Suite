"""Self-contained HTML dashboard for the agentic engine.

Renders findings, the shaped evidence inventories, the network map and the
agent's reasoning trace into a single ``reports/dashboard.html`` with inline CSS
and no external resources.  Every injected value is HTML-escaped — a security
tool must not become an XSS vector for the very payloads it collects.
"""

from __future__ import annotations

import html
import json
import os
from datetime import datetime
from typing import Dict, List

_SEV_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#d97706",
    "low": "#65a30d",
    "info": "#0891b2",
}


def _esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def _tiles(summary: Dict) -> str:
    order = ["critical", "high", "medium", "low", "info"]
    tiles = [f'<div class="tile total"><div class="n">{_esc(summary.get("total", 0))}</div><div class="l">findings</div></div>']
    for sev in order:
        tiles.append(
            f'<div class="tile" style="border-top:3px solid {_SEV_COLORS[sev]}">'
            f'<div class="n">{_esc(summary.get(sev, 0))}</div><div class="l">{sev}</div></div>'
        )
    return '<div class="tiles">' + "".join(tiles) + "</div>"


def _findings_table(findings: List[Dict]) -> str:
    if not findings:
        return '<p class="empty">No findings.</p>'
    rows = []
    for f in findings:
        sev = f.get("severity", "medium")
        color = _SEV_COLORS.get(sev, "#666")
        meta = f.get("metadata", {})
        sources = ", ".join(meta.get("sources", []) or [f.get("source", "")])
        verified = meta.get("verified")
        vbadge = ""
        if verified is True:
            vbadge = '<span class="badge" style="background:#16a34a">✓ verified</span>'
        elif verified is False:
            vbadge = '<span class="badge" style="background:#475569">unconfirmed</span>'
        rows.append(
            "<tr>"
            f'<td><span class="badge" style="background:{color}">{_esc(sev)}</span></td>'
            f"<td>{_esc(f.get('type'))} {vbadge}</td>"
            f"<td class=mono>{_esc(f.get('url'))}{('?' + _esc(f.get('parameter'))) if f.get('parameter') else ''}</td>"
            f"<td>{_esc(f.get('description'))}</td>"
            f"<td class=mono>{_esc(f.get('evidence'))}</td>"
            f"<td>{_esc(f.get('confidence'))}<br><span class=dim>{_esc(sources)}</span></td>"
            "</tr>"
        )
    return (
        '<table><thead><tr><th>Severity</th><th>Type</th><th>Location</th>'
        "<th>Description</th><th>Evidence</th><th>Confidence</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>"
    )


def _json_block(title: str, obj) -> str:
    if not obj:
        return ""
    return (
        f'<details open><summary>{_esc(title)}</summary>'
        f'<pre class="mono">{_esc(json.dumps(obj, indent=2))}</pre></details>'
    )


def _trace(trace: List[Dict]) -> str:
    if not trace:
        return '<p class="empty">No agent trace (heuristic mode).</p>'
    steps = []
    for i, step in enumerate(trace, 1):
        steps.append(
            f'<div class="step"><span class="stepn">{i}</span>'
            f'<span class="tool">{_esc(step.get("tool"))}</span>'
            f'<span class="args mono">{_esc(json.dumps(step.get("args", {})))}</span>'
            f'<div class="obs mono">{_esc(step.get("observation_preview", ""))}</div></div>'
        )
    return '<div class="trace">' + "".join(steps) + "</div>"


def render_dashboard(payload: Dict) -> str:
    summary = payload.get("summary", {})
    evidence = payload.get("evidence", {}) or {}
    findings = payload.get("normalized_findings", [])
    trace = payload.get("agent_trace", [])

    evidence_sections = "".join(
        _json_block(name.replace("_", " ").title(), evidence.get(name))
        for name in ["dom_sinks", "endpoints", "forms", "network_map", "storage", "security_headers", "secrets", "pages"]
    )

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DSG Agentic Scan — {_esc(payload.get('url'))}</title>
<style>
:root {{ color-scheme: dark; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif; background:#0b1020; color:#e6e9f0; }}
header {{ padding:20px 28px; background:linear-gradient(90deg,#111834,#0b1020); border-bottom:1px solid #22284a; }}
h1 {{ margin:0 0 4px; font-size:18px; }}
.meta {{ color:#98a0bd; font-size:12px; }}
main {{ padding:24px 28px; max-width:1200px; margin:0 auto; }}
h2 {{ font-size:15px; margin:28px 0 12px; color:#c7cce6; border-left:3px solid #4f6bff; padding-left:10px; }}
.tiles {{ display:flex; gap:12px; flex-wrap:wrap; }}
.tile {{ background:#141a33; border:1px solid #232a4d; border-radius:10px; padding:14px 18px; min-width:92px; text-align:center; }}
.tile .n {{ font-size:24px; font-weight:700; }}
.tile .l {{ font-size:11px; text-transform:uppercase; color:#98a0bd; letter-spacing:.5px; }}
.tile.total {{ background:#1a2247; }}
table {{ width:100%; border-collapse:collapse; background:#111834; border-radius:10px; overflow:hidden; }}
th,td {{ padding:9px 12px; text-align:left; vertical-align:top; border-bottom:1px solid #202748; font-size:13px; }}
th {{ background:#161d3d; color:#aeb6da; font-size:11px; text-transform:uppercase; letter-spacing:.4px; }}
td.mono, .mono {{ font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12px; word-break:break-all; }}
.badge {{ color:#fff; padding:2px 8px; border-radius:20px; font-size:11px; text-transform:uppercase; font-weight:600; }}
.dim {{ color:#7b83a6; font-size:11px; }}
.empty {{ color:#7b83a6; font-style:italic; }}
details {{ background:#111834; border:1px solid #232a4d; border-radius:8px; margin:8px 0; padding:6px 12px; }}
summary {{ cursor:pointer; font-weight:600; color:#c7cce6; }}
pre {{ overflow-x:auto; background:#0c1226; padding:12px; border-radius:6px; max-height:340px; }}
.trace .step {{ background:#111834; border:1px solid #232a4d; border-left:3px solid #4f6bff; border-radius:6px; padding:8px 12px; margin:6px 0; }}
.stepn {{ display:inline-block; background:#4f6bff; color:#fff; border-radius:50%; width:20px; height:20px; text-align:center; font-size:11px; line-height:20px; margin-right:8px; }}
.tool {{ font-weight:600; color:#8ea2ff; }}
.args {{ color:#98a0bd; margin-left:8px; }}
.obs {{ color:#aeb6da; margin-top:6px; white-space:pre-wrap; }}
</style></head><body>
<header>
  <h1>🛡️ DSG Agentic Client-Side Scan</h1>
  <div class="meta">Target: <span class="mono">{_esc(payload.get('url'))}</span> ·
   engine: {_esc(payload.get('engine','agentic'))} · collector: {_esc(payload.get('collector','-'))} ·
   status: {_esc(payload.get('status_code'))} · {_esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</div>
</header>
<main>
  <h2>Summary</h2>
  {_tiles(summary)}
  <h2>Findings</h2>
  {_findings_table(findings)}
  <h2>Collected Evidence (deterministic, redacted)</h2>
  {evidence_sections or '<p class="empty">No evidence collected.</p>'}
  <h2>Agent Reasoning Trace</h2>
  {_trace(trace)}
</main></body></html>"""


def write_dashboard(payload: Dict, reports_dir: str = "reports") -> str:
    os.makedirs(reports_dir, exist_ok=True)
    path = os.path.join(reports_dir, "dashboard.html")
    with open(path, "w") as fh:
        fh.write(render_dashboard(payload))
    return path
