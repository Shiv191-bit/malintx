"""Visual system: flat, light, low-chroma. One blue accent, semantic colours only where they carry meaning.

Design rules (deliberate): no gradients, no glow, no translucency/blur, no emoji icons, 1px borders instead of shadows,
colour never the only carrier of meaning (every badge has text), body text >= 4.5:1 contrast.
"""

from __future__ import annotations

import re
from html import escape

import streamlit as st

# --- tokens ---------------------------------------------------------------------------------------------------
BG, SURFACE, BORDER, BORDER_STRONG = "#f4f5f7", "#ffffff", "#d9dde4", "#b8c0cc"
TEXT, MUTED, SUBTLE = "#1b2430", "#546174", "#6b7686"
ACCENT, ACCENT_DARK, ACCENT_TINT = "#1f4f99", "#173d78", "#e8eef8"
OK, WARN, ALERT = "#2f6f4f", "#8a6100", "#a61b1b"

# text-safe colours on white (>= 4.5:1) and a matching pale tint for badge/row backgrounds
SEVERITY = {"critical": "#a61b1b", "high": "#b4470b", "medium": "#8a6100", "low": "#2f6f4f", "info": "#546174"}
CLASSIFICATION = {
    "critical": "#a61b1b", "high": "#b4470b", "medium": "#8a6100", "low": "#2f6f4f", "informational": "#546174",
    "inconclusive": "#5b45a0", "insufficient_evidence": "#5b45a0", "analysis_failed": "#a61b1b",
}
VERDICT = {"known_malicious": "#a61b1b", "suspicious": "#b4470b", "unknown": "#546174", "benign_observed": "#2f6f4f"}
VERDICT_LABEL = {"known_malicious": "known malicious", "suspicious": "suspicious", "unknown": "no data", "benign_observed": "benign observed"}
TINT = {"#a61b1b": "#fbeaea", "#b4470b": "#fdeee4", "#8a6100": "#fbf3df", "#2f6f4f": "#e8f3ec", "#546174": "#eceff3", "#5b45a0": "#efecf8",
        ACCENT: ACCENT_TINT}

CSS = f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap');
:root {{ --bg:{BG}; --surface:{SURFACE}; --border:{BORDER}; --text:{TEXT}; --muted:{MUTED}; --accent:{ACCENT}; }}
html, body, [class*="css"], .stApp {{ font-family: 'IBM Plex Sans', system-ui, -apple-system, 'Segoe UI', sans-serif; color:{TEXT}; }}
.stApp {{ background:{BG}; }}
.block-container {{ padding-top:1.4rem; padding-bottom:3rem; max-width:1320px; }}
header[data-testid="stHeader"] {{ background:transparent; }}
h1 {{ font-size:1.5rem !important; font-weight:600 !important; letter-spacing:-0.01em; color:{TEXT}; padding:0 0 .15rem 0 !important; }}
h2 {{ font-size:1.02rem !important; font-weight:600 !important; color:{TEXT}; margin-top:1.1rem !important; }}
h3 {{ font-size:.92rem !important; font-weight:600 !important; color:{MUTED}; }}
code, pre, .mx-mono {{ font-family:'IBM Plex Mono', ui-monospace, Consolas, monospace !important; font-size:.84em; }}
code {{ color:{ACCENT_DARK} !important; background:{ACCENT_TINT}; border-radius:3px; padding:1px 5px; }}
a {{ color:{ACCENT}; }}

/* sidebar */
[data-testid="stSidebar"] {{ background:{SURFACE}; border-right:1px solid {BORDER}; }}
[data-testid="stSidebar"] .block-container, [data-testid="stSidebarContent"] {{ padding-top:1.1rem; }}
[data-testid="stSidebar"] [role="radiogroup"] {{ gap:2px; }}
[data-testid="stSidebar"] [role="radiogroup"] label {{ padding:7px 10px; border-radius:5px; width:100%; border-left:3px solid transparent; }}
[data-testid="stSidebar"] [role="radiogroup"] label:hover {{ background:{BG}; }}
[data-testid="stSidebar"] [data-testid="stRadioOption"] > div > div:first-child {{ display:none; }}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) {{ background:{ACCENT_TINT}; border-left-color:{ACCENT}; }}
[data-testid="stSidebar"] [role="radiogroup"] label:has(input:checked) p {{ color:{ACCENT_DARK}; font-weight:600; }}
[data-testid="stSidebar"] [role="radiogroup"] p {{ font-size:.92rem; }}
.mx-brand {{ font-size:1.12rem; font-weight:600; letter-spacing:.01em; color:{TEXT}; }}
.mx-brand span {{ color:{ACCENT}; }}
.mx-tag {{ font-size:.78rem; color:{MUTED}; margin-bottom:.8rem; }}

/* surfaces */
.mx-card {{ background:{SURFACE}; border:1px solid {BORDER}; border-radius:6px; padding:12px 14px; margin-bottom:10px; }}
.mx-kpi-label {{ font-size:.7rem; text-transform:uppercase; letter-spacing:.07em; color:{MUTED}; font-weight:500; }}
.mx-kpi-value {{ font-size:1.55rem; font-weight:600; color:{TEXT}; line-height:1.25; font-variant-numeric:tabular-nums; }}
.mx-kpi-note {{ color:{SUBTLE}; font-size:.78rem; }}
.mx-badge {{ display:inline-block; padding:1px 8px; border-radius:3px; font-size:.7rem; font-weight:600; border:1px solid currentColor;
            letter-spacing:.04em; text-transform:uppercase; white-space:nowrap; line-height:1.5; }}
.mx-banner {{ border:1px solid {BORDER}; border-left:5px solid var(--c); background:{SURFACE}; border-radius:6px; padding:14px 18px; margin-bottom:12px;
             display:grid; grid-template-columns:minmax(0,1fr) 190px; gap:18px; align-items:center; }}
.mx-banner .cls {{ font-size:1.25rem; font-weight:600; color:var(--c); letter-spacing:.03em; }}
.mx-banner .sub {{ color:{MUTED}; font-size:.8rem; }}
.mx-banner .txt {{ font-size:.92rem; margin-top:4px; color:{TEXT}; }}
.mx-meter {{ height:8px; background:{BG}; border:1px solid {BORDER}; border-radius:2px; position:relative; }}
.mx-meter > i {{ position:absolute; left:0; top:0; bottom:0; background:var(--c); }}
.mx-meter-scale {{ display:flex; justify-content:space-between; font-size:.68rem; color:{SUBTLE}; margin-top:3px; }}
.mx-muted {{ color:{MUTED}; font-size:.82rem; }}
.mx-note, .mx-warn, .mx-ai {{ border:1px solid {BORDER}; border-left-width:4px; background:{SURFACE}; border-radius:4px; padding:8px 12px; font-size:.86rem; margin:4px 0 10px; }}
.mx-note {{ border-left-color:{ACCENT}; }}
.mx-warn {{ border-left-color:{WARN}; background:#fffdf5; }}
.mx-ai {{ border-left-color:#5b45a0; border-style:dashed; border-left-style:solid; }}
.mx-empty {{ border:1px dashed {BORDER_STRONG}; border-radius:6px; padding:22px; text-align:center; color:{MUTED}; background:{SURFACE}; }}
.mx-empty b {{ color:{TEXT}; display:block; margin-bottom:4px; }}
.mx-legend {{ display:flex; flex-wrap:wrap; gap:14px; font-size:.78rem; color:{MUTED}; margin:2px 0 8px; }}
.mx-legend i {{ display:inline-block; width:9px; height:9px; border-radius:2px; margin-right:5px; vertical-align:-1px; }}
.mx-graph {{ background:{SURFACE}; border:1px solid {BORDER}; border-radius:6px; padding:8px 6px; overflow-x:auto; }}

/* controls */
.stButton > button, .stDownloadButton > button {{ border-radius:4px; border:1px solid {BORDER_STRONG}; font-weight:500; box-shadow:none; }}
.stButton > button[kind="primary"], .stDownloadButton > button[kind="primary"] {{ background:{ACCENT}; border-color:{ACCENT}; color:#fff; }}
.stButton > button[kind="primary"]:hover {{ background:{ACCENT_DARK}; border-color:{ACCENT_DARK}; }}
button:focus-visible, input:focus-visible, [role="tab"]:focus-visible {{ outline:2px solid {ACCENT}; outline-offset:2px; }}
[data-baseweb="tab-list"] {{ gap:2px; border-bottom:1px solid {BORDER}; }}
[data-baseweb="tab"] {{ height:40px; padding:0 14px; }}
[data-baseweb="tab"] p {{ font-size:.88rem; font-weight:500; }}
[data-testid="stExpander"] {{ border:1px solid {BORDER}; border-radius:6px; background:{SURFACE}; }}
[data-testid="stDataFrame"] {{ border:1px solid {BORDER}; border-radius:6px; }}
@media (prefers-reduced-motion: reduce) {{ * {{ animation:none !important; transition:none !important; }} }}
@media (max-width: 760px) {{ .mx-banner {{ grid-template-columns:1fr; }} }}
</style>
"""


def inject() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def badge(text: str, color: str) -> str:
    bg = TINT.get(color, SURFACE)
    return f'<span class="mx-badge" style="color:{color};background:{bg}">{escape(str(text))}</span>'


def sev_badge(sev: str) -> str:
    return badge(sev, SEVERITY.get(sev, MUTED))


def verdict_badge(verdict: str) -> str:
    return badge(VERDICT_LABEL.get(verdict, verdict), VERDICT.get(verdict, MUTED))


def kpi(label: str, value: object, note: str = "") -> None:
    st.markdown(
        f'<div class="mx-card"><div class="mx-kpi-label">{escape(label)}</div><div class="mx-kpi-value">{escape(str(value))}</div>'
        f'<div class="mx-kpi-note">{escape(note) or "&nbsp;"}</div></div>', unsafe_allow_html=True)


def page_header(title: str, sub: str = "") -> None:
    st.title(title)
    if sub:
        st.markdown(f'<div class="mx-muted" style="margin:-4px 0 14px">{escape(sub)}</div>', unsafe_allow_html=True)


def empty_state(title: str, body: str) -> None:
    st.markdown(f'<div class="mx-empty"><b>{escape(title)}</b>{escape(body)}</div>', unsafe_allow_html=True)


def legend(items: list[tuple[str, str]]) -> None:
    st.markdown('<div class="mx-legend">' + "".join(f'<span><i style="background:{c}"></i>{escape(t)}</span>' for t, c in items) + "</div>", unsafe_allow_html=True)


def note(text: str, kind: str = "note") -> None:
    st.markdown(f'<div class="mx-{kind}">{escape(text)}</div>', unsafe_allow_html=True)


def unavailable(what: str, why: str) -> None:
    st.markdown(f'<div class="mx-warn"><b>{escape(what)}: unavailable.</b> {escape(why)}</div>', unsafe_allow_html=True)


_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|<>~$&:@])")


def md(text: object) -> str:
    """Escape Markdown/HTML-significant characters in untrusted text (class names, certificate subjects, AI output,
    provider messages) so a hostile sample cannot inject links, images or formatting into the analyst's page."""
    return _MD_SPECIAL.sub(r"\\\1", str(text if text is not None else ""))
