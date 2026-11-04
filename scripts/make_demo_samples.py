"""Write SYNTHETIC demo APKs for live demonstrations. Usage: python scripts/make_demo_samples.py [outdir]

These are generated test fixtures (tests/apkbuilder.py), not real malware and not executable on a device: they exist so a demo
needs no malware on the machine. 'banking_trojan' reproduces the *pattern* (hard-coded SMS exfil + overlay + accessibility
+ SMS interception); 'injection_app' carries a prompt-injection string to show the AI layer cannot be steered.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

import scenarios as sc  # noqa: E402

DEMO = {
    "01_benign_bank": sc.benign_bank,            # SMS/network APIs in a legitimate banking app: capability != malice
    "02_banking_trojan_pattern": sc.banking_trojan,
    "03_packed_loader_stub": sc.loader_stub,     # thin packed stub, like those seen in real samples
    "04_remote_control_like": sc.remote_control_like,  # legitimate remote-control app: must NOT be rated high
    "05_prompt_injection": sc.injection_app,
    "06_manifest_only_no_code": sc.manifest_only,  # no DEX: honest "insufficient evidence", not "safe"
}


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ROOT / "demo_samples")
    out.mkdir(parents=True, exist_ok=True)
    for name, fn in DEMO.items():
        (out / f"{name}.apk").write_bytes(fn())
        print("wrote", out / f"{name}.apk")


if __name__ == "__main__":
    main()
