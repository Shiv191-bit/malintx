"""Visual system: restrained charcoal/navy palette, muted blue/cyan accents."""

from __future__ import annotations

import re
from html import escape

import streamlit as st

SEVERITY = {"critical": "#f87171", "high": "#fb923c", "medium": "#fbbf24", "low": "#38bdf8", "info": "#94a3b8"}
CLASSIFICATION = {
    "critical": "#f87171", "high": "#fb923c", "medium": "#fbbf24", "low": "#38bdf8", "informational": "#94a3b8",
    "inconclusive": "#a78bfa", "insufficient_evidence": "#a78bfa", "analysis_failed": "#f87171",
}
VERDICT = {"known_malicious": "#f87171", "suspicious": "#fbbf24", "unknown": "#94a3b8", "benign_observed": "#38bdf8"}

CSS = """
<style>
.block-container {padding-top: 1.6rem; max-width: 1400px;}
h1, h2, h3 {letter-spacing: -0.01em; font-weight: 600;}
h1 {font-size: 1.55rem;} h2 {font-size: 1.15rem; color: #cbd5e1;} h3 {font-size: 0.98rem; color: #94a3b8;}
[data-testid="stSidebar"] {border-right: 1px solid #1e293b;}
.mx-card {background:#111a2e; border:1px solid #1e293b; border-radius:8px; padding:14px 16px; margin-bottom:10px;}
.mx-kpi-label {font-size:0.72rem; text-transform:uppercase; letter-spacing:.08em; color:#64748b;}
.mx-kpi-value {font-size:1.7rem; font-weight:600; color:#e2e8f0; line-height:1.2;}
.mx-badge {display:inline-block; padding:1px 9px; border-radius:999px; font-size:0.72rem; font-weight:600;
           border:1px solid currentColor; letter-spacing:.03em; text-transform:uppercase; white-space:nowrap;}
.mx-banner {border-left:4px solid var(--c); background:#111a2e; border-radius:6px; padding:14px 18px; margin-bottom:12px;}
.mx-banner .cls {font-size:1.4rem; font-weight:700; color:var(--c); letter-spacing:.02em;}
.mx-muted {color:#64748b; font-size:0.82rem;}
.mx-note {border:1px solid #164e63; background:#0c2530; color:#a5f3fc; border-radius:6px; padding:8px 12px; font-size:0.85rem;}
.mx-warn {border:1px solid #78350f; background:#2a1a0a; color:#fcd34d; border-radius:6px; padding:8px 12px; font-size:0.85rem;}
.mx-ai {border:1px dashed #6d28d9; background:#1a1530; color:#ddd6fe; border-radius:6px; padding:8px 12px; font-size:0.85rem;}
code {color:#7dd3fc !important;}
</style>
"""


def inject() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def badge(text: str, color: str) -> str:
    return f'<span class="mx-badge" style="color:{color}">{escape(str(text))}</span>'


def sev_badge(sev: str) -> str:
    return badge(sev, SEVERITY.get(sev, "#94a3b8"))


def kpi(label: str, value: object, note: str = "") -> None:
    st.markdown(
        f'<div class="mx-card"><div class="mx-kpi-label">{escape(label)}</div><div class="mx-kpi-value">{escape(str(value))}</div>'
        f'<div class="mx-muted">{escape(note)}</div></div>', unsafe_allow_html=True)


def note(text: str, kind: str = "note") -> None:
    st.markdown(f'<div class="mx-{kind}">{escape(text)}</div>', unsafe_allow_html=True)


def unavailable(what: str, why: str) -> None:
    st.markdown(f'<div class="mx-warn"><b>{escape(what)}: unavailable.</b> {escape(why)}</div>', unsafe_allow_html=True)


_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~$&:@])")


def md(text: object) -> str:
    """Escape Markdown/HTML-significant characters in untrusted text (class names, certificate subjects, AI output,
    provider messages) so a hostile sample cannot inject links, images or formatting into the analyst's page."""
    return _MD_SPECIAL.sub(r"\\\1", str(text if text is not None else ""))
