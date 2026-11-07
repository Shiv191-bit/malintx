"""Self-contained SVG for the infrastructure map: samples -> referenced hosts -> hosting owner.

No external assets or scripts. Every dynamic string is HTML-escaped and truncated (indicator values come from hostile samples).
Colour is never the only channel: verdict and role are printed on each host row.
"""

from __future__ import annotations

from html import escape
from typing import Any

from malintx import infra
from malintx.dashboard import theme

W, ROW, TOP, PAD = 880, 44, 46, 10
COL = {"sample": (PAD, 215), "host": (290, 330), "owner": (655, 215)}
MAX_SAMPLES, MAX_HOSTS, MAX_OWNERS = 10, 14, 10


def _cut(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def _y(i: int, count: int, rows: int) -> float:
    off = (rows - count) * ROW / 2
    return TOP + off + i * ROW


def render(data: dict[str, Any]) -> str:
    # Draw only hosts worth a look: unusual reference types, anything intel flagged or returned data for. Ordinary domains/URLs
    # (library docs, mail providers, ...) stay in the table; drawing hundreds of them would bury the signal.
    notable_all = [h for h in data["hosts"] if infra.is_notable(h)]
    hosts = notable_all[:MAX_HOSTS]
    used = {j for h in hosts for j in h["samples"]}
    samples = [s for s in data["samples"] if s["job_id"] in used][:MAX_SAMPLES]
    owners_all = {h["owner"] for h in hosts if h.get("owner")}
    owners = [o for o in data["owners"] if o["owner"] in owners_all][:MAX_OWNERS]
    rows = max(len(samples), len(hosts), len(owners), 1)
    height = TOP + rows * ROW + 26
    sy = {s["job_id"]: _y(i, len(samples), rows) + ROW / 2 for i, s in enumerate(samples)}
    hy = {h["value"]: _y(i, len(hosts), rows) + ROW / 2 for i, h in enumerate(hosts)}
    oy = {o["owner"]: _y(i, len(owners), rows) + ROW / 2 for i, o in enumerate(owners)}
    sx_r, hx_l, hx_r, ox_l = COL["sample"][0] + COL["sample"][1], COL["host"][0], COL["host"][0] + COL["host"][1], COL["owner"][0]
    out = [f'<svg viewBox="0 0 {W} {height}" width="100%" role="img" aria-label="Infrastructure map: {len(samples)} samples, {len(hosts)} referenced hosts" '
           f'xmlns="http://www.w3.org/2000/svg" font-family="IBM Plex Sans, system-ui, sans-serif">']
    for key, label in (("sample", "SAMPLES"), ("host", "REFERENCES FOUND IN CODE"), ("owner", "HOSTING (PROVIDER DATA)")):
        x = COL[key][0]
        out.append(f'<text x="{x}" y="22" font-size="11" font-weight="600" letter-spacing="0.8" fill="{theme.MUTED}">{label}</text>')
        out.append(f'<line x1="{x}" y1="30" x2="{x + COL[key][1]}" y2="30" stroke="{theme.BORDER}"/>')
    # edges first so rows draw over them
    for h in hosts:
        shared = len(h["samples"]) > 1
        for j in h["samples"]:
            if j in sy:
                y1, y2 = sy[j], hy[h["value"]]
                mid = (sx_r + hx_l) / 2
                out.append(f'<path d="M{sx_r},{y1:.1f} C{mid},{y1:.1f} {mid},{y2:.1f} {hx_l},{y2:.1f}" fill="none" '
                           f'stroke="{theme.ACCENT if shared else theme.BORDER_STRONG}" stroke-width="{1.6 if shared else 1}"/>')
        if h.get("owner") in oy:
            y1, y2 = hy[h["value"]], oy[h["owner"]]
            mid = (hx_r + ox_l) / 2
            out.append(f'<path d="M{hx_r},{y1:.1f} C{mid},{y1:.1f} {mid},{y2:.1f} {ox_l},{y2:.1f}" fill="none" stroke="{theme.BORDER_STRONG}" stroke-width="1"/>')
    for s in samples:
        c = theme.CLASSIFICATION.get(s["classification"], theme.MUTED)
        y = sy[s["job_id"]] - ROW / 2 + 3
        x, w = COL["sample"]
        score = f' · {s["score"]}' if s.get("score") is not None else ""
        out.append(f'<rect x="{x}" y="{y:.1f}" width="{w}" height="{ROW - 6}" rx="3" fill="{theme.SURFACE}" stroke="{theme.BORDER}"/>'
                   f'<rect x="{x}" y="{y:.1f}" width="4" height="{ROW - 6}" fill="{c}"/>'
                   f'<text x="{x + 12}" y="{y + 16:.1f}" font-size="13" font-weight="600" fill="{theme.TEXT}">{escape(_cut(s["label"], 24))}</text>'
                   f'<text x="{x + 12}" y="{y + 30:.1f}" font-size="11" fill="{c}">{escape(s["classification"].replace("_", " "))}{score}</text>')
    for h in hosts:
        c = theme.VERDICT.get(h["verdict"], theme.MUTED)
        y = hy[h["value"]] - ROW / 2 + 3
        x, w = COL["host"]
        flag = " · shared" if len(h["samples"]) > 1 else ""
        out.append(f'<rect x="{x}" y="{y:.1f}" width="{w}" height="{ROW - 6}" rx="3" fill="{theme.SURFACE}" stroke="{theme.ACCENT if flag else theme.BORDER}"/>'
                   f'<rect x="{x}" y="{y:.1f}" width="4" height="{ROW - 6}" fill="{c}"/>'
                   f'<text x="{x + 12}" y="{y + 16:.1f}" font-size="12.5" class="mx-mono" font-family="IBM Plex Mono, Consolas, monospace" fill="{theme.TEXT}">{escape(_cut(h["value"], 36))}</text>'
                   f'<text x="{x + 12}" y="{y + 30:.1f}" font-size="11" fill="{theme.MUTED}">{escape(h["role_label"])} · '
                   f'<tspan fill="{c}" font-weight="600">{escape(theme.VERDICT_LABEL.get(h["verdict"], h["verdict"]))}</tspan>{flag}</text>')
    for o in owners:
        y = oy[o["owner"]] - ROW / 2 + 3
        x, w = COL["owner"]
        out.append(f'<rect x="{x}" y="{y:.1f}" width="{w}" height="{ROW - 6}" rx="3" fill="{theme.SURFACE}" stroke="{theme.BORDER}"/>'
                   f'<text x="{x + 10}" y="{y + 16:.1f}" font-size="12.5" font-weight="600" fill="{theme.TEXT}">{escape(_cut(o["owner"], 26))}</text>'
                   f'<text x="{x + 10}" y="{y + 30:.1f}" font-size="11" fill="{theme.MUTED}">{escape(o["country"] or "country n/a")} · {o["hosts"]} host(s)</text>')
    if not owners:
        x, w = COL["owner"]
        out.append(f'<text x="{x}" y="{TOP + 18}" font-size="12" fill="{theme.SUBTLE}">No provider returned hosting data.</text>'
                   f'<text x="{x}" y="{TOP + 34}" font-size="11" fill="{theme.SUBTLE}">Enable threat intel to populate this column.</text>')
    hidden = max(0, len(data["hosts"]) - len(hosts))
    if hidden:
        out.append(f'<text x="{COL["host"][0]}" y="{height - 8}" font-size="10" fill="{theme.MUTED}">{hidden} ordinary domain/URL reference(s) not drawn; see the table</text>')
    if not hosts:
        out.append(f'<text x="{COL["host"][0]}" y="{TOP + 18}" font-size="11" fill="{theme.SUBTLE}">No unusual references (IP literals, Telegram bots) and no intel hits.</text>')
    out.append("</svg>")
    return "".join(out)
