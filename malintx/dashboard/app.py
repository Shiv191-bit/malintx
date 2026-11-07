"""MALINT-X analyst dashboard (Streamlit). Run: `streamlit run malintx/dashboard/app.py`."""

from __future__ import annotations

import streamlit as st

from malintx.dashboard import theme, views_analysis, views_basic, views_c2
from malintx.dashboard.client import ApiClient, ApiError, ApiUnreachable

PAGES = ["Overview", "Analyze", "Analysis", "Infrastructure", "History", "Configuration"]


def main() -> None:
    st.set_page_config(page_title="MALINT-X", layout="wide")
    theme.inject()
    client = ApiClient()
    st.session_state.setdefault("page", "Overview")
    # Flush pending navigation set by open_job() before the radio widget renders
    if st.session_state.get("_nav_to"):
        st.session_state["page"] = st.session_state.pop("_nav_to")
    linked = st.query_params.get("job")
    if linked and not st.session_state.get("_deeplink_applied"):  # shareable link: ?job=<analysis id>
        st.session_state.update(job_id=linked, page="Analysis", _deeplink_applied=True)
    with st.sidebar:
        st.markdown('<div class="mx-brand">MALINT<span>-X</span></div><div class="mx-tag">Android malware analysis and threat intelligence</div>',
                    unsafe_allow_html=True)
        page = st.radio("Navigate", PAGES, key="page", label_visibility="collapsed")
        if st.session_state.get("job_id"):
            st.caption(f"Current analysis: `{st.session_state['job_id']}`")
        try:
            h = client.health()
            st.caption(f"API {h['version']} · schema {h['schema_version']}")
        except (ApiUnreachable, ApiError):
            st.caption("API: unreachable")
    try:
        if page == "Overview":
            views_basic.overview(client)
        elif page == "Analyze":
            views_basic.upload(client)
        elif page == "Analysis":
            if st.session_state.get("job_id"):
                views_analysis.render(client, st.session_state["job_id"])
            else:
                st.title("Analysis")
                st.caption("No analysis selected. Upload an APK or open one from History.")
        elif page == "Infrastructure":
            views_c2.page(client)
        elif page == "History":
            views_basic.history(client)
        else:
            views_basic.configuration(client)
    except ApiUnreachable as exc:
        theme.unavailable("Backend", f"{exc}. Start it with `malintx-api` or check MALINTX_API_URL.")
    except ApiError as exc:
        st.error(f"{exc.message} [{exc.code}]")


main()
