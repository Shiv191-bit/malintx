"""Overview, upload/progress, history and configuration views."""

from __future__ import annotations

import time

import altair as alt
import pandas as pd
import streamlit as st

from malintx.dashboard import theme
from malintx.dashboard.client import ApiClient, ApiError

ORDER = ["critical", "high", "medium", "low", "informational", "inconclusive", "insufficient_evidence", "analysis_failed"]
STAGE_ICON = {"pending": "○", "running": "◔", "done": "●", "skipped": "◌", "failed": "✕"}


def open_job(job_id: str) -> None:
    st.session_state["job_id"] = job_id
    # Use _nav_to so we do not modify the radio widget key after it has been instantiated
    st.session_state["_nav_to"] = "Analysis"


def overview(client: ApiClient) -> None:
    theme.page_header("Overview", "Evidence-based triage of Android samples. Static analysis only: nothing is executed.")
    ov = client.overview()
    hist = client.history(200)
    if not ov["jobs_total"]:
        theme.empty_state("No analyses yet", "Open Analyze and upload an APK, or load the synthetic demo samples with scripts/seed_demo.py.")
    c = st.columns(4)
    with c[0]:
        theme.kpi("Analyses", ov["jobs_total"], "all jobs recorded")
    with c[1]:
        theme.kpi("Unique samples", ov["samples_total"], "by SHA-256")
    with c[2]:
        done = ov["jobs_by_status"].get("completed", 0)
        theme.kpi("Completed", done, f"{ov['jobs_by_status'].get('failed', 0)} failed")
    with c[3]:
        flagged = sum(n for k, n in ov["results_by_classification"].items() if k in ("high", "critical"))
        theme.kpi("High / critical", flagged, "evidence-based classification")
    left, right = st.columns([1, 1])
    with left:
        st.subheader("Results by classification")
        data = ov["results_by_classification"]
        if not data:
            st.caption("No completed analyses yet.")
        else:
            df = pd.DataFrame({"classification": list(data), "count": list(data.values())})
            st.altair_chart(alt.Chart(df).mark_bar().encode(
                y=alt.Y("classification:N", sort=ORDER, title=None), x=alt.X("count:Q", title=None, axis=alt.Axis(tickMinStep=1, format="d")),
                color=alt.Color("classification:N", scale=alt.Scale(domain=list(theme.CLASSIFICATION), range=list(theme.CLASSIFICATION.values())), legend=None),
                tooltip=["classification", "count"]).properties(height=max(120, 34 * len(df))), width="stretch")
    with right:
        st.subheader("Job status")
        if ov["jobs_by_status"]:
            st.dataframe(pd.DataFrame({"status": list(ov["jobs_by_status"]), "jobs": list(ov["jobs_by_status"].values())}), hide_index=True, width="stretch")
        else:
            st.caption("No jobs yet.")
    st.subheader("Recent analyses")
    _history_table(hist[:8], key="ov")


def _history_table(rows: list[dict], key: str) -> None:
    if not rows:
        st.caption("Nothing to show yet.")
        return
    df = pd.DataFrame([{
        "Job": r["job_id"], "Created": r["created_at"][:19].replace("T", " "), "Package": r.get("package_name") or "—",
        "File": r["display_name"], "Status": r["status"], "Classification": (r.get("classification") or "—").replace("_", " "),
        "Score": r.get("score") if r.get("score") is not None else "—", "Enriched": "yes" if r.get("enrich_requested") else "no",
        "AI": "yes" if r.get("ai_requested") else "no",
    } for r in rows])
    st.dataframe(df, hide_index=True, width="stretch")
    pick = st.selectbox("Open analysis", [""] + [r["job_id"] for r in rows], key=f"pick_{key}",
                        format_func=lambda j: "Select…" if not j else f"{j} · {next(r['display_name'] for r in rows if r['job_id'] == j)}")
    if pick:
        open_job(pick)
        st.rerun()


def history(client: ApiClient) -> None:
    theme.page_header("History", "Every analysis recorded on this instance. Select one to open it.")
    _history_table(client.history(200), key="hist")


def upload(client: ApiClient) -> None:
    theme.page_header("Analyze an APK", "Static analysis only. The sample is never installed or executed.")
    cfg = client.config()
    st.markdown("Upload a sample for **static analysis only**. The APK is never installed or executed. "
                f"Limit {cfg['limits']['max_upload_mb']} MiB; the file name and MIME type are not trusted.")
    f = st.file_uploader("APK file", type=None, accept_multiple_files=False)
    intel_ready = [k for k, v in cfg["threat_intel"].items() if v["configured"]]
    ai_ready = cfg["ai"]["configured"] and cfg["ai"]["provider"] != "none"
    c1, c2 = st.columns(2)
    with c1:
        enrich = st.checkbox("Enrich with threat intelligence", value=False, disabled=not intel_ready,
                             help="Sends the sample's SHA-256 and extracted indicators to the configured providers. Never contacts the indicators themselves.")
        if intel_ready:
            theme.note(f"Providers configured: {', '.join(intel_ready)}. Enabling this shares the sample hash and extracted network indicators with them.")
        else:
            st.caption("No threat-intel provider configured (set VT_API_KEY, SHODAN_API_KEY, ABUSECH_AUTH_KEY or KOODOUS_TOKEN).")
    with c2:
        ai = st.checkbox("AI-assisted interpretation", value=False, disabled=not ai_ready,
                         help="Sends bounded evidence excerpts (not the APK) to the configured AI provider. Advisory only.")
        if ai_ready:
            theme.note(f"Provider: {cfg['ai']['provider']}. Enabling this sends code excerpts and indicators to that third party.")
        else:
            st.caption("AI provider not configured (set MALINTX_AI_PROVIDER and its API key).")
    force = st.checkbox("Re-analyse even if this exact sample was already analysed", value=False)
    if st.button("Start analysis", type="primary", disabled=f is None):
        try:
            out = client.submit(f.name, f.getvalue(), enrich=enrich, ai=ai, force=force)
        except ApiError as exc:
            st.error(f"Upload rejected: {exc.message} [{exc.code}]")
            return
        if out["reused_existing"]:
            st.info("This exact sample was already analysed; opening the existing result.")
        open_job(out["job"]["id"])
        st.rerun()


@st.fragment(run_every=2)
def progress(client: ApiClient, job_id: str) -> None:
    job = client.job(job_id)
    st.subheader("Analysis progress")
    done = sum(1 for s in job["stages"] if s["state"] in ("done", "skipped", "failed"))
    st.progress(done / max(1, len(job["stages"])), text=f"{job['status'].replace('_', ' ')} — {done}/{len(job['stages'])} stages finished")
    for s in job["stages"]:
        st.markdown(f"`{STAGE_ICON[s['state']]}` **{s['name'].replace('_', ' ')}** · {s['state']} — {theme.md(s['message'] or '…')}")
    if job["status"] in ("completed", "failed"):
        if job.get("error_message"):
            st.error(f"[{job['error_code']}] {job['error_message']}")
        time.sleep(0.3)
        st.rerun()


def configuration(client: ApiClient) -> None:
    theme.page_header("Configuration", "Integrations, limits and tooling detected on this host. Secrets are never shown.")
    cfg = client.config()
    v = cfg["versions"]
    st.subheader("Versions")
    st.dataframe(pd.DataFrame({"Component": list(v), "Value": [str(x) for x in v.values()]}), hide_index=True, width="stretch")
    st.subheader("Threat-intelligence providers")
    rows = [{"Provider": k, "Configured": "yes" if d["configured"] else "no", "Supports": ", ".join(d["supports"]),
             "Note": "experimental adapter" if d["experimental"] else ""} for k, d in cfg["threat_intel"].items()]
    st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
    st.subheader("AI provider")
    ai = cfg["ai"]
    st.write(f"Provider: `{ai['provider']}` — {'configured' if ai['configured'] else 'not configured (AI is optional; the core pipeline is unaffected)'}")
    st.subheader("Decompilers")
    d = cfg["decompilers"]
    st.write(f"Mode: **{d['mode']}** · Java: {'found' if d['java'] else 'not found'} · JADX: {'found' if d['jadx'] else 'not found'} · Apktool: {'found' if d['apktool'] else 'not found'}")
    if d["mode"] == "bytecode-only":
        theme.note("JADX/JRE not available: evidence uses Dalvik bytecode slices instead of decompiled Java. Analysis is otherwise complete.")
    st.subheader("Limits and security")
    lim = cfg["limits"]
    st.write(f"Max upload {lim['max_upload_mb']} MiB · analysis timeout {lim['analysis_timeout_s']} s · worker memory limit {lim['worker_memory_mb']} MiB · "
             f"API authentication {'required' if cfg['auth_required'] else 'not required (bind to localhost only)'}")
    st.caption("API keys are read from environment variables or .env and are never displayed or stored by the dashboard.")
