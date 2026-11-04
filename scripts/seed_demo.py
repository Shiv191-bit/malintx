"""Load the synthetic demo samples into a RUNNING MALINT-X API so the dashboard has something to show.

  python scripts/seed_demo.py [--api http://127.0.0.1:8750] [--enrich]

--enrich asks the API to run passive threat-intel lookups (needs provider keys in .env; sends the sample hash and its extracted
indicators to those providers). Without it nothing leaves this machine. Samples are synthetic fixtures, not malware.
"""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import scenarios as sc  # noqa: E402

from malintx.dashboard.client import ApiClient  # noqa: E402

SAMPLES = {
    "benign_bank.apk": (sc.benign_bank, False),
    "banking_trojan_pattern.apk": (lambda: sc.banking_trojan(c2_demo=True), True),
    "banking_trojan_variant.apk": (lambda: sc.banking_trojan(c2_demo=True, pkg="com.secure.bank.helper", bot_id="0000000001"), False),
    "packed_loader_stub.apk": (sc.loader_stub, False),
    "remote_control_like.apk": (sc.remote_control_like, False),
    "prompt_injection.apk": (sc.injection_app, False),
    "manifest_only_no_code.apk": (sc.manifest_only, False),
}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default=os.environ.get("MALINTX_API_URL"))
    ap.add_argument("--real", nargs="*", default=[], type=Path, help="extra real benign APK files (e.g. two F-Droid builds for the lineage demo)")
    ap.add_argument("--enrich", action="store_true", help="passive threat-intel lookups for the trojan-pattern sample only")
    args = ap.parse_args()
    client = ApiClient(args.api)
    client.health()
    jobs = {name: (build, enrich_ok) for name, (build, enrich_ok) in SAMPLES.items()}
    jobs.update({p.name: ((lambda p=p: p.read_bytes()), False) for p in args.real})
    have = {r["display_name"] for r in client.history(200)}  # synthetic APK bytes differ per build, so skip names already loaded
    for name, (build, enrich_ok) in jobs.items():
        if name in have:
            print(f"{name:32s} already loaded, skipped")
            continue
        out = client.submit(name, build(), enrich=bool(args.enrich and enrich_ok), ai=False, force=False)
        job = out["job"]["id"]
        for _ in range(240):
            if client.job(job)["status"] in ("completed", "failed"):
                break
            time.sleep(1)
        res = client.result(job) or {}
        risk = res.get("risk") or {}
        print(f"{name:32s} {risk.get('classification', '?'):22s} {risk.get('score')}  job={job}{'  (reused)' if out['reused_existing'] else ''}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
