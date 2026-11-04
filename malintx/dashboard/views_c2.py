"""Infrastructure ("C2") views: a cross-sample page and a per-analysis tab.

A referenced host is a lead, not proof of command-and-control. Intel comes only from passive lookups the analyst opted into;
"no data" is never shown as "safe".
"""

from __future__ import annotations

import pandas as pd
import streamlit as st

from malintx import infra
from malintx.dashboard import graph, theme
from malintx.dashboard.client import ApiClient

LEGEND = [("known malicious", theme.VERDICT["known_malicious"]), ("suspicious", theme.VERDICT["suspicious"]),
          ("no provider data", theme.VERDICT["unknown"]), ("benign observed", theme.VERDICT["benign_observed"]), ("shared by 2+ samples", theme.ACCENT)]


def _summary(data: dict) -> None:
    s = data["summary"]
    c = st.columns(5)
    with c[0]:
        theme.kpi("Samples", s["samples"], "with network references")
    with c[1]:
        theme.kpi("Hosts referenced", s["hosts"], "IPs, domains, URLs")
    with c[2]:
        theme.kpi("Shared hosts", s["shared_hosts"], f"unusual, in 2+ samples (+{s['shared_ordinary']} ordinary)")
    with c[3]:
        theme.kpi("Looked up", s["queried_hosts"], "passive, opt-in only")
    with c[4]:
        theme.kpi("Flagged by intel", s["flagged_hosts"], "suspicious or known malicious")


def _table(data: dict, key: str) -> None:
    labels = {s["job_id"]: s["label"] for s in data["samples"]}
    f1, f2 = st.columns([1, 2])
    roles = sorted({h["role_label"] for h in data["hosts"]})
    pick = f1.multiselect("Reference type", roles, key=f"roles_{key}")
    q = f2.text_input("Filter (host, owner, family)", key=f"q_{key}").lower()
    rows = []
    for h in data["hosts"]:
        i = h["intel"]
        hay = " ".join([h["value"], h.get("owner") or "", " ".join(i.get("families", []))]).lower()
        if (pick and h["role_label"] not in pick) or (q and q not in hay):
            continue
        rows.append({
            "Host / indicator": h["value"], "Type": h["role_label"], "Intel": theme.VERDICT_LABEL.get(h["verdict"], h["verdict"]) if h["queried"] else "not looked up",
            "Flagging engines": i.get("malicious"), "Owner (ASN)": h.get("owner") or "—", "Country": h.get("country") or "—",
            "Open ports": ", ".join(str(p) for p in i.get("open_ports", [])) or "—", "Families": ", ".join(i.get("families", [])) or "—",
            "Referenced by": ", ".join(labels.get(j, j) for j in h["samples"]), "Code note": "; ".join(h["notes"]) or "—"})
    st.caption(f"{len(rows)} of {len(data['hosts'])} hosts")
    if rows:
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")


def _draw(data: dict) -> None:
    theme.legend(LEGEND)
    st.markdown(f'<div class="mx-graph">{graph.render(data)}</div>', unsafe_allow_html=True)


def _caveats(data: dict) -> None:
    if data["summary"]["queried_hosts"] == 0:
        theme.note("No host has been looked up. Hosts are shown as found in code, with no reputation or hosting data. Re-run the analysis with threat "
                   "intelligence enabled to add passive ASN, country, open-port and detection data. Nothing here contacts any host.")
    theme.note("A host in the code is a lead, not proof of command-and-control. Country and ASN describe where a provider says the address is hosted, "
               "not where an operator is. \"No data\" is not \"safe\".")


def page(client: ApiClient) -> None:
    theme.page_header("Infrastructure", "Network hosts referenced by analysed samples, and which samples share them.")
    data = client.infrastructure()
    if not data["hosts"]:
        theme.empty_state("No network references yet", "Analyse an APK that embeds IP addresses, domains or URLs, then return here to see shared infrastructure.")
        return
    _summary(data)
    _caveats(data)
    st.subheader("Map")
    _draw(data)
    shared = [h for h in data["hosts"] if len(h["samples"]) > 1 and infra.is_notable(h)]
    plain = sum(1 for h in data["hosts"] if len(h["samples"]) > 1 and not infra.is_notable(h))
    if shared:
        st.subheader("Shared infrastructure")
        st.caption("Unusual hosts referenced by more than one analysed sample: a pivot point for linking campaigns."
                   + (f" {plain} ordinary domain/URL references are also shared (typically common libraries or providers); see the full table below." if plain else ""))
        labels = {s["job_id"]: s["label"] for s in data["samples"]}
        st.dataframe(pd.DataFrame([{"Host": h["value"], "Samples": len(h["samples"]), "Referenced by": ", ".join(labels.get(j, j) for j in h["samples"]),
                                    "Intel": theme.VERDICT_LABEL.get(h["verdict"], h["verdict"])} for h in shared]), hide_index=True, width="stretch")
    if data["owners"]:
        st.subheader("Hosting owners")
        st.dataframe(pd.DataFrame([{"Owner": o["owner"], "Country": o["country"] or "—", "Hosts": o["hosts"], "Samples": len(o["samples"])} for o in data["owners"]]),
                     hide_index=True, width="stretch")
    st.subheader("All referenced hosts")
    _table(data, "global")


def tab(res: dict, job_id: str) -> None:
    """Per-analysis view built from the already-fetched result (no extra request)."""
    static = res["static"]
    meta = {"job_id": job_id, "name": res["job"]["display_name"]}
    data = infra.build([(meta, res)])
    if not data["hosts"]:
        theme.empty_state("No network references found", "No IP addresses, domains or URLs were extracted from this app's own code. "
                          "That does not rule out network behaviour (obfuscation, native code, runtime-decoded strings).")
        return
    _summary(data)
    _caveats(data)
    _draw(data)
    st.subheader("Referenced hosts")
    _table(data, f"job_{job_id}")
    c2_rules = [f for f in static["findings"] if f["rule_id"] in ("STR-TELEGRAM-BOT-API", "STR-IP-LITERAL-ENDPOINT")]
    if c2_rules:
        st.subheader("Related findings")
        for f in c2_rules:
            st.markdown(f"- {theme.sev_badge(f['severity'])} {theme.md(f['title'])}", unsafe_allow_html=True)
