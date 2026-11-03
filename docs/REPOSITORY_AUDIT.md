# Repository audit (Phase 0)

Audited 2026-11-03 against `SENTINEL_Final_Boots_N_Guts.pdf` (4 pages, fully read) and the pre-existing scaffold.

## What existed
`malintx/` (~2.5k lines: config, models, scorer, decompiler wrapper, manifest/slicer/IoC extractors, VT client, assembler, prompts, PDF generator, pipeline), `docs/SETUP.md`, `docs/TECHNICAL_DECISIONS.md`, `documents/malintx_build_plan.md`, a hand-written ATT&CK JSON, `scripts/setup_tools.py`. No tests, no git history, no `.env`.

## Findings
| Area | Finding | Disposition |
|---|---|---|
| Pipeline | `pipeline.py` imported `manifest_parser`, `code_slicer`, `ioc_extractor`, `llm_client`, none of which exist; `dashboard/app.py`, `llm_client.py`, `tests/` referenced by README but absent. **Could not run.** | Rewritten |
| Environment | `pydantic-settings`, `streamlit`, `reportlab` not installed; no Java, so JADX/Apktool unusable; invalid build backend in `pyproject.toml`. | Fixed (venv, lock file); Java remains a blocker |
| MITRE data | Hand-written; wrong IDs/names (T1636 labelled "Input Capture", T1636.001 "Keylogging", non-existent T1447/T1448, T1398 mislabelled). Violates "do not invent IDs". | Replaced by official ATT&CK for Mobile v20.0 STIX bundle; every rule ID validated by a test |
| Scoring | Scored LLM-detected techniques directly; flat points per dangerous permission; "Clean" for no data; no abstention. Contradicts "LLM must not set the verdict" and FP requirements. | Replaced by deterministic engine that ignores AI |
| FP control | Package-name prefix allow-list (`com.sbi.`…): trivially spoofable by an attacker. | Removed; replaced by operator-supplied certificate fingerprints (halve capability weights only) and OTP-API context rule |
| Slicer | Every `SmsManager` mention was "critical"; matched imports and comments; Java source only (impossible without Java). | Replaced by call-site-level bytecode analysis + optional source enrichment |
| XML | Stdlib `ElementTree` on untrusted manifest XML (entity expansion). | `defusedxml` + native binary-manifest decoding |
| Subprocess | `subprocess.run` with the full environment (including API keys), no memory limit, no tree kill. | `tools/runner.py`: scrubbed env, Job Object/RLIMIT, tree kill, capped output |
| Config | Created directories at import time; secrets as plain `str`. | `Settings` with `SecretStr`, explicit `ensure_dirs()` |
| Threat intel | VT only, `aiohttp` + ad-hoc throttle, no URL-credential guard, no host pinning. | New provider layer |
| Dashboard/API/storage | Missing. | Built |

## Reused
The code-slice idea, PDF layout approach, ioc noise lists (reduced: `github.com`, `firebaseio.com` removed because attackers abuse them), and the build plan's stage structure. Old files are preserved under `legacy/`.

## Spec deviations (deliberate)
* Spec says live C2 "active reconnaissance" and a "global map". Replaced by **passive** lookups and no map: probing C2 is unsafe/out of scope, and geolocation of arbitrary IPs from the data we have would be speculative. The UI shows ASN/country only where a provider returned it.
* Spec cites "near-zero false positives" and a 90 s target. Neither is claimed; the analysis typically completes in seconds on small samples but large APKs may take minutes (timeout 600 s).
* Spec uses Gemini 1.5 Flash; that model is retired. Model names are configuration.
