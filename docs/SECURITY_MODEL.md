# MALINT-X Security Model

MALINT-X processes hostile files and handles third-party credentials, so it is treated as security-sensitive software. **Intended deployment: a single trusted analyst or small team, on a workstation or lab host, API bound to localhost.** It is not hardened for hostile multi-tenant exposure.

## Assets and threats
| Threat | Control (implemented) | Verified by |
|---|---|---|
| Sample executes on host | Static analysis only; nothing is installed or run; DEX is parsed, never loaded | design; no execution path exists |
| Parser crash/hang/memory bomb in androguard | Analysis in a child process: timeout + whole-tree kill, Windows Job Object / POSIX `RLIMIT_AS`, output capped | `test_tools` (timeout, memory limit) |
| Credentials reach code that touches samples | Child env is scrubbed (`minimal_env`), cwd is an empty workspace, `python -I` | `test_environment_is_scrubbed_of_secrets` |
| Zip bomb / entry explosion / traversal | Entry-count, total-size and ratio limits; entries never extracted by name; traversal/duplicate names reported as findings | `test_ingestion` |
| Oversized upload | Cap enforced while streaming at the ASGI layer (before buffering) and again during hashing | `test_oversize_*` |
| Untrusted filename/MIME | Basename sanitised, content-addressed storage (`<sha256>.sample`), magic + structure validated | `test_filename_never_trusted` |
| Concurrent identical uploads | Race-safe store | `test_concurrent_identical_uploads_are_safe` |
| XML entity attacks on manifests | `defusedxml`; binary manifests decoded natively | `test_manifest_text_parser_rejects_xml_entity_attacks` |
| Path escape via decompiler output | `SourceIndex` resolves and confines paths (class names come from hostile DEX) | `test_source_index_is_confined_to_output_dir` |
| Prompt injection from strings in the APK | Evidence sent as delimited untrusted data; instruction-like text detected and disclosed; no tools; output schema-validated; unknown evidence IDs ⇒ claim dropped; AI cannot affect score | `test_ai` |
| Hostile strings attacking the analyst's browser | All dynamic HTML escaped; untrusted text passed through `theme.md()` before Markdown; PDF text XML-escaped | `test_dashboard`, `test_report` |
| Leaking data to third parties | Intel and AI are **opt-in per analysis**; keys alone do nothing; URLs carrying tokens/credentials are never sent; query/fragment stripped; passive GET lookups only; hosts pinned | `test_intel`, `test_ai` |
| Contacting attacker infrastructure | Providers are host-pinned; extracted hosts are never requested | `test_service_never_contacts_extracted_infrastructure` |
| Secrets in logs/responses | `SecretStr`, redacting log filter, `/config` returns booleans only, provider errors sanitised | `test_config_endpoint_never_leaks_secrets` |
| API abuse | Optional bearer token (constant-time compare), per-IP rate limits (stricter for uploads), no CORS | `test_pipeline_api` |
| Crash leaves stale state | Workspaces always removed (`sweep_stale` for crashes); interrupted jobs failed on startup | tests |

## Things you must do
* Set `MALINTX_API_TOKEN` and put a TLS reverse proxy in front before binding to anything but localhost. `/api/docs` is unauthenticated (schema only).
* Rate limiting is per client IP as seen by the app; behind a proxy, configure it to pass the real address or rate-limit at the proxy.
* Keep keys in the environment/`.env` (git-ignored). Rotate any key that appears in a log.
* Analyse real malware only in an isolated lab host/VM. Static analysis is safe in principle, but parser exploits are possible; the child-process limits reduce, not eliminate, that risk.
* The sample store is read-only content-addressed files on disk **unencrypted**; protect the volume.

## Provider terms (verify before use)
* **VirusTotal**: public API key is rate-limited (4 req/min is the documented free tier) and intended for non-commercial use; sharing hashes/URLs/IPs discloses them to VT.
* **Shodan**: API access and host-lookup credits depend on plan; Shodan is context (ports/ASN/tags), not a reputation verdict, so only `c2/malware/botnet`-style tags produce `suspicious`.
* **MalwareBazaar (abuse.ch)**: free **Auth-Key** from auth.abuse.ch sent as `Auth-Key`; free under fair-use, commercial use may need a paid plan; daily download limits apply (checked 2026-11-03 at bazaar.abuse.ch/api).
* **Koodous**: API has changed repeatedly (its docs say so); access terms could not be confirmed. The adapter is **experimental and unverified**.
* **AndroZoo**: research access on request (site unreachable during this audit; confirm terms directly). No automated download is implemented.

## Chain of custody
Not provided. Reports record hashes, job/rule/engine versions and a risk-input digest so results are *reproducible*, but nothing is signed or timestamped by a third party.
