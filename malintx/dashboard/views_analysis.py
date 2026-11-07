"""Detailed analysis view: summary, manifest, behaviours, evidence, intel, ATT&CK, risk, AI, report."""

from __future__ import annotations

from html import escape

import altair as alt
import pandas as pd
import streamlit as st

from malintx.dashboard import theme, views_c2
from malintx.dashboard.client import ApiClient
from malintx.dashboard.views_basic import progress

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def render(client: ApiClient, job_id: str) -> None:
    job = client.job(job_id)
    if job["status"] not in ("completed", "failed"):
        st.title(f"Analysis · {job['display_name']}")
        progress(client, job_id)
        return
    res = client.result(job_id)
    if res is None:
        theme.unavailable("Result", "no result was stored for this job")
        return
    static, risk = res.get("static"), res.get("risk")
    title = (static or {}).get("sample", {}).get("package_name") or job["display_name"]
    st.title(title)
    if job["status"] == "failed":
        st.error(f"Analysis failed [{job['error_code']}]: {job['error_message']}")
    if risk:
        _banner(risk)
    if static is None:
        theme.unavailable("Analysis details", "static analysis did not complete; no evidence is available for this sample")
        return
    tabs = st.tabs(["Summary", "Manifest", "Behaviours", "Evidence", "Network / C2", "Threat intel", "ATT&CK", "Risk", "Lineage", "AI", "Report"])
    with tabs[0]:
        _summary(res, static, risk)
    with tabs[1]:
        _manifest(static)
    with tabs[2]:
        _behaviours(static)
    with tabs[3]:
        _evidence(static)
    with tabs[4]:
        views_c2.tab(res, job_id)
    with tabs[5]:
        _intel(res.get("intel"), static)
    with tabs[6]:
        _mitre(static, res.get("ai"))
    with tabs[7]:
        _risk(risk)
    with tabs[8]:
        _lineage(client, job_id, static)
    with tabs[9]:
        _ai(res.get("ai"))
    with tabs[10]:
        _report(client, job_id, res)


def _banner(risk: dict) -> None:
    color = theme.CLASSIFICATION.get(risk["classification"], theme.MUTED)
    score = risk["score"]
    meter = (f'<div class="mx-kpi-label">Risk score</div><div class="mx-kpi-value">{score}<span class="mx-muted"> / 100</span></div>'
             f'<div class="mx-meter"><i style="width:{score}%"></i></div><div class="mx-meter-scale"><span>0</span><span>30</span><span>55</span><span>80</span><span>100</span></div>'
             if score is not None else '<div class="mx-kpi-label">Risk score</div><div class="mx-kpi-value">n/a</div><div class="mx-muted">withheld: not enough evidence</div>')
    st.markdown(f'<div class="mx-banner" style="--c:{color}"><div><div class="cls">{risk["classification"].replace("_", " ").upper()}</div>'
                f'<div class="sub">Deterministic, evidence-based. AI is not an input.</div><div class="txt">{escape(risk["summary"])}</div></div><div>{meter}</div></div>',
                unsafe_allow_html=True)


def _summary(res: dict, static: dict, risk: dict | None) -> None:
    s, cov = static["sample"], static["coverage"]
    c = st.columns(4)
    with c[0]:
        theme.kpi("Findings", len(static["findings"]), f"{sum(1 for f in static['findings'] if f['kind'] == 'malicious_behavior')} correlated behaviours")
    with c[1]:
        theme.kpi("Evidence items", len(static["evidence"]), cov["backend"] + " · " + cov["source_scan"].replace("_", " "))
    with c[2]:
        theme.kpi("Indicators", len(static["indicators"]), "ips, urls, domains, emails, paths")
    with c[3]:
        theme.kpi("Analysis time", f"{cov['duration_s']} s", f"{cov['classes']:,} classes · {cov['methods']:,} methods")
    left, right = st.columns([3, 2])
    with left:
        st.subheader("Sample")
        rows = {"SHA-256": s["sha256"], "SHA-1": s["sha1"], "MD5": s["md5"], "Size": f"{s['size_bytes']:,} bytes", "Package": s.get("package_name") or "—",
                "Version": f"{s.get('version_name') or '—'} (code {s.get('version_code') or '—'})", "SDK min/target": f"{s.get('min_sdk')} / {s.get('target_sdk')}",
                "Signing": ", ".join(s["signing_schemes"]) or "none detected", "Registered": s["first_seen"], "Original name (untrusted)": s["display_name"]}
        st.dataframe(pd.DataFrame({"Field": list(rows), "Value": list(rows.values())}), hide_index=True, width="stretch")
        for cert in s["certificates"]:
            st.caption(theme.md(f"Certificate {cert['sha256'][:16]}… · {cert['subject']} · {cert['not_before'][:10] if cert['not_before'] else '?'} → {cert['not_after'][:10] if cert['not_after'] else '?'} · self-signed: {cert['self_signed']}"))
    with right:
        st.subheader("Findings by severity")
        counts = pd.DataFrame([{"severity": sv, "count": sum(1 for f in static["findings"] if f["severity"] == sv)} for sv in SEV_ORDER])
        st.altair_chart(alt.Chart(counts).mark_bar().encode(
            x=alt.X("severity:N", sort=SEV_ORDER, title=None), y=alt.Y("count:Q", title=None),
            color=alt.Color("severity:N", scale=alt.Scale(domain=SEV_ORDER, range=[theme.SEVERITY[k] for k in SEV_ORDER]), legend=None)).properties(height=200),
            width="stretch")
    st.subheader("Coverage and limitations")
    for lim in cov["limitations"] + static["warnings"] + (risk["limitations"] if risk else []):
        st.markdown(f"- {theme.md(lim)}")
    if risk and risk["recommendations"]:
        st.subheader("Analyst recommendations")
        for r in risk["recommendations"]:
            st.markdown(f"- {theme.md(r)}")


def _manifest(static: dict) -> None:
    m = static["manifest"]
    c = st.columns(4)
    with c[0]:
        theme.kpi("Permissions", len(m["permissions"]), f"{sum(1 for p in m['permissions'] if p['sensitivity'] != 'normal')} dangerous/special")
    with c[1]:
        theme.kpi("Components", len(m["components"]), f"{sum(1 for x in m['components'] if x['exported'])} exported")
    with c[2]:
        theme.kpi("Accessibility svc", len(m["accessibility_services"]), "declared")
    with c[3]:
        theme.kpi("Device admin", len(m["device_admin_receivers"]), "receivers")
    st.subheader("Permissions")
    pdf = pd.DataFrame([{"Permission": p["name"], "Class": p["sensitivity"], "Platform": p["is_platform"]} for p in m["permissions"]])
    only = st.checkbox("Only dangerous / special-access", value=True)
    st.dataframe(pdf[pdf["Class"] != "normal"] if only and not pdf.empty else pdf, hide_index=True, width="stretch")
    st.subheader("Components")
    cdf = pd.DataFrame([{"Type": x["kind"], "Name": x["name"], "Exported": x["exported"], "Explicit": x["exported_explicit"], "Guard permission": x["permission"] or "—",
                         "Actions": ", ".join(a for f in x["intent_filters"] for a in f["actions"])[:120],
                         "Max filter priority": max([f["priority"] or 0 for f in x["intent_filters"]], default=0)} for x in m["components"]])
    st.dataframe(cdf, hide_index=True, width="stretch")
    st.subheader("Application flags")
    st.write({"debuggable": m["debuggable"], "allowBackup": m["allow_backup"], "usesCleartextTraffic": m["uses_cleartext_traffic"],
              "networkSecurityConfig": m["network_security_config"], "testOnly": m["test_only"], "sharedUserId": m["shared_user_id"]})
    man_findings = [f for f in static["findings"] if f["rule_id"].startswith("MAN-")]
    if man_findings:
        st.subheader("Manifest findings")
        st.dataframe(pd.DataFrame([{"Severity": f["severity"], "Kind": f["kind"].replace("_", " "), "Finding": f["title"], "Evidence": ", ".join(f["evidence_ids"][:3])} for f in man_findings]),
                     hide_index=True, width="stretch")


def _behaviours(static: dict) -> None:
    kinds = {"malicious_behavior": "Correlated malicious behaviour", "suspicious_capability": "Suspicious capability",
             "security_misconfiguration": "Security misconfiguration (not malice)", "informational": "Informational"}
    theme.note("Single API calls are capabilities, not intent. Only correlated patterns are labelled malicious behaviour. Misconfigurations are shown separately.")
    if static.get("near_misses"):
        with st.expander(f"Near misses: {len(static['near_misses'])} high-severity pattern(s) this app almost matches"):
            st.caption("Counterfactual view: for each pattern the rules did NOT report, the one missing signal. This shows how close the app is "
                       "to a high-severity pattern, and what an evader would have to add.")
            for n in static["near_misses"]:
                st.markdown(f"**{theme.md(n['title'])}** — {n['satisfied']}/{n['total']} requirements met. Missing: _{theme.md('; '.join(n['missing']))}_")
    sel = st.multiselect("Show", list(kinds), default=["malicious_behavior", "suspicious_capability"], format_func=lambda k: kinds[k])
    items = [f for f in static["findings"] if f["kind"] in sel]
    if not items:
        st.caption("No findings of the selected kinds.")
    for f in items:
        with st.expander(f"{f['severity'].upper()} · {f['title']}  ({f['id']})"):
            st.markdown(theme.sev_badge(f["severity"]) + " " + theme.badge(f["kind"].replace("_", " "), theme.MUTED) + " "
                        + theme.badge(f"{f['confidence']} confidence", theme.ACCENT), unsafe_allow_html=True)
            st.write(theme.md(f["description"]))
            if f["false_positive_notes"]:
                st.caption(theme.md("Legitimate-use context: " + f["false_positive_notes"]))
            if f["suppressed_by"]:
                theme.note("Deterministic context adjustment: " + ", ".join(f["suppressed_by"]))
            if f["composite_of"]:
                st.caption(theme.md("Built from: " + ", ".join(f["composite_of"])))
            st.caption(theme.md(f"ATT&CK: {', '.join(f['mitre_ids']) or '—'} · MASVS: {', '.join(f['masvs']) or '—'} · Evidence: {', '.join(f['evidence_ids'][:8])}"))
            if f["limitations"]:
                st.caption(theme.md("Limitations: " + f["limitations"]))


def _evidence(static: dict) -> None:
    ev = static["evidence"]
    if not ev:
        st.caption("No evidence items.")
        return
    c1, c2, c3 = st.columns([1, 1, 2])
    kinds = sorted({e["kind"] for e in ev})
    kind = c1.multiselect("Kind", kinds, default=kinds)
    rules = c2.multiselect("Rule", sorted({e["rule_id"] or "—" for e in ev}))
    q = c3.text_input("Filter (class, API, artifact)").lower()
    rows = [e for e in ev if e["kind"] in kind and (not rules or (e["rule_id"] or "—") in rules)
            and (not q or q in " ".join(str(e.get(k) or "") for k in ("class_name", "api", "artifact", "method_name")).lower())]
    st.caption(f"{len(rows)} of {len(ev)} evidence items")
    st.dataframe(pd.DataFrame([{"ID": e["id"], "Kind": e["kind"], "Rule": e["rule_id"], "File": e["source_file"], "Class": e["class_name"], "Method": e["method_name"],
                                "API / artifact": e["api"] or e["artifact"]} for e in rows]), hide_index=True, width="stretch", height=240)
    if rows:
        pick = st.selectbox("Inspect evidence", [e["id"] for e in rows],
                            format_func=lambda i: next(f"{e['id']} · {e['rule_id']} · {(e['class_name'] or e['source_file'])[:70]}" for e in rows if e["id"] == i))
        e = next(x for x in rows if x["id"] == pick)
        st.dataframe(pd.DataFrame([{"File": e["source_file"], "Class": e["class_name"] or "—", "Method": e["method_name"] or "—",
                                    "Offset": hex(e["bytecode_offset"]) if e["bytecode_offset"] is not None else "—", "Line": e["line_number"] or "—",
                                    "Extraction": e["extraction_method"], "Confidence": e["confidence"]}]), hide_index=True, width="stretch")
        st.code(e["snippet"] or "(no snippet available for this evidence)", language="text")
        if e["limitations"]:
            st.caption(theme.md("Limitations: " + e["limitations"]))
    st.subheader("Extracted indicators")
    ind = static["indicators"]
    if ind:
        st.dataframe(pd.DataFrame([{"Type": i["type"], "Value": i["value"], "Seen": i["occurrences"], "Note": i["note"] or "", "Evidence": ", ".join(i["evidence_ids"][:2])} for i in ind]),
                     hide_index=True, width="stretch")
    else:
        st.caption("No indicators extracted.")


def _intel(intel: dict | None, static: dict) -> None:
    if not intel or not intel["requested"]:
        theme.unavailable("Threat intelligence", "not requested for this analysis, so no data left this host. Extracted indicators are UNKNOWN, not safe.")
        return
    st.markdown(" ".join(theme.badge(f"{k}: {v}", theme.ACCENT if v == "ok" else theme.WARN) for k, v in intel["providers"].items()), unsafe_allow_html=True)
    st.markdown(f"**Sample hash verdict:** {theme.badge(intel['sample_verdict'], theme.VERDICT[intel['sample_verdict']])}", unsafe_allow_html=True)
    for lk in intel["sample_lookups"]:
        st.caption(theme.md(f"{lk['provider']}: {lk['status']} — {lk['detail'] or ''} {('· ' + lk['reference_url']) if lk['reference_url'] else ''}"))
    if intel["indicators"]:
        rows = []
        for i in intel["indicators"]:
            for lk in i["lookups"] or [None]:
                rows.append({"Indicator": i["value"][:80], "Overall": i["verdict"], "Provider": lk["provider"] if lk else "—", "Status": lk["status"] if lk else "—",
                             "Malicious": lk["malicious"] if lk else None, "ASN / owner": f"{lk['asn'] or ''} {lk['as_owner'] or ''}".strip() if lk else "", "Country": lk["country"] if lk else "",
                             "Families": ", ".join(lk["malware_families"]) if lk else ""})
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    else:
        st.caption("No indicators were looked up.")
    for n in intel["notes"]:
        st.caption(theme.md("• " + n))
    theme.note("Unknown means no provider returned data. It must never be read as safe.")


def _mitre(static: dict, ai: dict | None) -> None:
    m = static["mitre"]
    st.subheader("Deterministic mappings")
    if not m:
        st.caption("No ATT&CK techniques were mapped from deterministic rules.")
    else:
        st.caption(m[0]["source"] + " — mappings are rule outputs, not AI inferences.")
        st.dataframe(pd.DataFrame([{"Technique": t["technique_id"], "Name": t["technique_name"], "Tactics": ", ".join(t["tactics"]), "Confidence": t["confidence"],
                                    "Evidence": ", ".join(t["evidence_ids"][:3]), "Rationale": t["rationale"]} for t in m]), hide_index=True, width="stretch")
        tactics = pd.Series([tac for t in m for tac in t["tactics"]]).value_counts().rename_axis("tactic").reset_index(name="techniques")
        st.altair_chart(alt.Chart(tactics).mark_bar(color=theme.ACCENT).encode(y=alt.Y("tactic:N", sort="-x", title=None), x=alt.X("techniques:Q", title="techniques mapped")).properties(height=max(100, 32 * len(tactics))),
                        width="stretch")
    if ai and ai["status"] == "completed" and ai["accepted_mitre"]:
        st.subheader("AI-suggested (advisory, evidence-validated)")
        theme.note("These IDs come from AI claims that cite real evidence. They are interpretation, kept separate from the deterministic mappings above.", "ai")
        st.write(theme.md(", ".join(ai["accepted_mitre"])))


def _risk(risk: dict | None) -> None:
    if not risk:
        theme.unavailable("Risk assessment", "not computed")
        return
    c = st.columns(3)
    with c[0]:
        theme.kpi("Classification", risk["classification"].replace("_", " "))
    with c[1]:
        theme.kpi("Score", f"{risk['score']}/100" if risk["score"] is not None else "n/a", "deterministic; AI is not an input")
    with c[2]:
        theme.kpi("Posture issues", risk["security_posture_issues"], "reported separately from malice")
    if risk["contributions"]:
        df = pd.DataFrame(risk["contributions"])
        st.altair_chart(alt.Chart(df.head(15)).mark_bar(color=theme.ACCENT).encode(
            y=alt.Y("label:N", sort="-x", title=None), x=alt.X("applied_points:Q", title="points applied"),
            tooltip=["label", "category", "base_points", "multiplier", "applied_points", "note"]).properties(height=max(120, 26 * min(15, len(df)))), width="stretch")
        st.dataframe(df[["label", "category", "base_points", "multiplier", "applied_points", "note"]], hide_index=True, width="stretch")
    for text in risk["adjustments"] + risk["floors_applied"] + risk["suppressions"]:
        st.markdown(f"- {theme.md(text)}")
    st.subheader("Methodology")
    st.markdown("Points = severity (low 2, medium 6, high 12, critical 20) × kind weight (behaviour 1.0, capability 0.6) × confidence (high 1.0, medium 0.7, low 0.4). "
                "Diminishing returns within a behaviour group (1, 0.5, 0.25…; cap 24). Capabilities already part of a composite count half. Threat-intel adds points only when a provider returned data. "
                "Bands: <10 informational, <30 low, <55 medium, <80 high, ≥80 critical. Inconclusive / insufficient-evidence / failed are never forced into a malware-or-benign label.")
    st.caption(f"Engine {risk['engine_version']} · rule set {risk['ruleset_version']} · inputs digest {risk['inputs_digest']}")


def _lineage(client: ApiClient, job_id: str, static: dict) -> None:
    theme.note("Hash-free lineage: a MinHash sketch of the framework APIs this app's own code calls. Obfuscators can rename classes but not "
               "`SmsManager.sendTextMessage`, so variants, repacks and version drift of one codebase stay similar even when every file hash differs.")
    sim = client.similar(job_id)
    if not sim["available"]:
        theme.unavailable("Lineage", sim["reason"])
        return
    fp = static["lineage"]
    st.caption(f"Fingerprint over {fp['api_count']:,} distinct framework APIs · compared against {sim['compared_against']} other analysed sample(s)")
    if not sim["matches"]:
        st.caption("No other analysed sample is similar (≥ 0.30). Analyse more samples to build lineage.")
    else:
        df = pd.DataFrame([{"Job": m["job_id"], "Package": m["package"], "API similarity": m["api_similarity"], "Permissions": m["permission_similarity"],
                            "Behaviours": m["behaviour_similarity"], "Same signer": m["same_signer"], "Interpretation": m["relation"]} for m in sim["matches"]])
        st.dataframe(df, hide_index=True, width="stretch")
        st.caption("Bands calibrated on real apps: unrelated pairs rarely exceed 0.64; related families have a median of 0.78. A match is a lead, not proof.")
        pick = st.selectbox("Capability diff against", [m["job_id"] for m in sim["matches"]],
                            format_func=lambda j: next(f"{m['package']} ({m['api_similarity']:.2f})" for m in sim["matches"] if m["job_id"] == j))
        d = client.diff(pick, job_id)
        st.subheader("What this sample adds relative to the match")
        theme.note(d["summary"])
        c1, c2 = st.columns(2)
        with c1:
            st.markdown("**Permissions added**")
            st.write(d["permissions_added"] or "none")
            st.markdown("**Components added**")
            st.write(d["components_added"][:15] or "none")
        with c2:
            st.markdown("**Findings added**")
            st.dataframe(pd.DataFrame(d["findings_added"]) if d["findings_added"] else pd.DataFrame({"none": []}), hide_index=True, width="stretch")
            st.markdown("**Indicators added**")
            st.write([f"{i['type']}: {i['value']}" for i in d["indicators_added"][:15]] or "none")


def _ai(ai: dict | None) -> None:
    if not ai or ai["status"] == "not_requested":
        theme.unavailable("AI interpretation", "not requested; no evidence was sent to an AI provider. The deterministic analysis is complete without it.")
        return
    if ai["status"] != "completed":
        theme.unavailable("AI interpretation", f"status {ai['status']}: {ai.get('error') or ''}. Deterministic results are unaffected.")
        return
    theme.note(f"AI-generated interpretation by {ai['provider']} / {ai['model']}. Advisory: it does not influence the score or classification. Verify every claim against its cited evidence.", "ai")
    a = ai["assessment"]
    st.subheader(f"Overall: {a['overall'].replace('_', ' ')}")
    st.write(theme.md(a["summary"]))
    for c in a["claims"]:
        with st.expander(f"{c['title']} — {c['assessment'].replace('_', ' ')} ({c['confidence']})"):
            st.write(theme.md(c["explanation"]))
            st.caption(theme.md(f"Cited evidence: {', '.join(c['evidence_ids'])} · ATT&CK: {', '.join(c['mitre_ids']) or '—'}"))
            st.caption(theme.md("Uncertainty: " + (c["uncertainty"] or "not stated")))
    if ai["dropped_claims"]:
        st.subheader("Discarded by validation")
        for d in ai["dropped_claims"]:
            st.markdown(f"- {theme.md(d)}")
    for lim in a["limitations"]:
        st.caption(theme.md("• " + lim))


def _report(client: ApiClient, job_id: str, res: dict) -> None:
    if not res["report_available"]:
        theme.unavailable("PDF report", "no report was generated for this job (see the reporting stage on the progress view)")
        return
    pdf = client.report(job_id)
    if pdf is None:
        theme.unavailable("PDF report", "the report file is missing on the server")
        return
    st.success(f"Report ready · {len(pdf) // 1024} KiB")
    st.download_button("Download PDF report", pdf, file_name=f"malintx-{job_id}.pdf", mime="application/pdf", type="primary")
    st.caption("The report is traceable to this job and rule set and is not a chain-of-custody record. Use the download to read it; embedded preview is intentionally not used.")
