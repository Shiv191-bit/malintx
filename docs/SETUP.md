# Setup

Tested on Windows 11, Python 3.14.6. Requires Python ≥ 3.10.

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.lock.txt   # exact tested versions
.venv\Scripts\python -m pip install -e . --no-deps
copy .env.example .env                                          # all keys optional
```

## Run
```bash
.venv\Scripts\python -m malintx.api.app                         # API on 127.0.0.1:8750
.venv\Scripts\python -m streamlit run malintx/dashboard/app.py  # dashboard on :8501 (set MALINTX_API_URL / MALINTX_API_TOKEN if needed)
```
Open `http://localhost:8501/?job=<id>` to deep-link an analysis.

### Demo data
Seed a **clean** data directory with the synthetic demo samples (plus two real F-Droid builds if you have them) so every dashboard page has content:
```bash
set MALINTX_DATA_DIR=var_demo
.venv\Scripts\python -m malintx.api.app                       # terminal 1
.venv\Scripts\python scripts/seed_demo.py                     # terminal 2; add --enrich for passive intel on the trojan-pattern sample
```
See [JUDGE_DEMO.md](JUDGE_DEMO.md).

## Optional tooling
Verified combination: Microsoft OpenJDK 21 (`winget install Microsoft.OpenJDK.21`), JADX 1.5.6 and Apktool 3.0.3 (GitHub releases). Apktool ships as a jar: create a launcher (`apktool.bat` running `java -jar apktool.jar %*`).
JADX/Apktool need a JRE (≥ 11). Install them yourself (e.g. a JDK package, then releases from the skylot/jadx and iBotPeaches/Apktool GitHub pages) and set `MALINTX_JAVA`, `MALINTX_JADX`, `MALINTX_APKTOOL`. `GET /api/v1/config` reports `bytecode+source` mode when found. Without them everything works in `bytecode-only` mode.

## Tests
```bash
.venv\Scripts\python -m pytest tests -q
.venv\Scripts\python -m ruff check malintx tests
```
Tests need no network, keys, Java or real samples.
