"""`malintx-dashboard` entry point."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> None:  # pragma: no cover
    from streamlit.web import cli

    app = Path(__file__).with_name("app.py")
    sys.argv = ["streamlit", "run", str(app), "--server.address", "127.0.0.1", "--server.port", "8501"]
    cli.main()
