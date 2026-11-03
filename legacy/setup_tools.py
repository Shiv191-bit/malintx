"""
MALINT-X Tool Setup Script.

Downloads JADX and Apktool to the tools/ directory.
These tools require a Java Runtime Environment (JRE 11+).
"""

from __future__ import annotations

import io
import os
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import requests

TOOLS_DIR = Path(__file__).resolve().parent.parent / "tools"

# Tool download URLs (update versions as needed)
JADX_VERSION = "1.5.1"
JADX_URL = f"https://github.com/skylot/jadx/releases/download/v{JADX_VERSION}/jadx-{JADX_VERSION}.zip"

APKTOOL_VERSION = "2.10.0"
APKTOOL_URL = f"https://github.com/iBotPeaches/Apktool/releases/download/v{APKTOOL_VERSION}/apktool_{APKTOOL_VERSION}.jar"


def check_java() -> bool:
    """Check if Java is available in PATH."""
    try:
        result = subprocess.run(
            ["java", "-version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        version_info = result.stderr or result.stdout
        print(f"[OK] Java found: {version_info.splitlines()[0].strip()}")
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("[WARNING] Java not found in PATH.")
        print("  JADX and Apktool require Java Runtime Environment (JRE 11+).")
        print("  Install from: https://adoptium.net/")
        return False


def download_jadx() -> bool:
    """Download and extract JADX to tools/jadx/."""
    jadx_dir = TOOLS_DIR / "jadx"
    jadx_bin = jadx_dir / "bin" / "jadx"
    jadx_bat = jadx_dir / "bin" / "jadx.bat"

    if jadx_bin.exists() or jadx_bat.exists():
        print(f"[OK] JADX already installed at {jadx_dir}")
        return True

    print(f"[...] Downloading JADX v{JADX_VERSION}...")
    try:
        response = requests.get(JADX_URL, stream=True, timeout=120)
        response.raise_for_status()

        jadx_dir.mkdir(parents=True, exist_ok=True)

        total_size = int(response.headers.get("content-length", 0))
        downloaded = 0
        buffer = io.BytesIO()

        for chunk in response.iter_content(chunk_size=8192):
            buffer.write(chunk)
            downloaded += len(chunk)
            if total_size > 0:
                pct = downloaded * 100 // total_size
                print(f"\r  Downloaded: {downloaded // 1024 // 1024}MB / {total_size // 1024 // 1024}MB ({pct}%)", end="")

        print()
        print("[...] Extracting JADX...")

        buffer.seek(0)
        with zipfile.ZipFile(buffer) as zf:
            zf.extractall(jadx_dir)

        # Make jadx executable on unix
        if jadx_bin.exists():
            jadx_bin.chmod(jadx_bin.stat().st_mode | stat.S_IEXEC)

        print(f"[OK] JADX installed to {jadx_dir}")
        return True

    except Exception as e:
        print(f"[ERROR] Failed to download JADX: {e}")
        return False


def download_apktool() -> bool:
    """Download Apktool JAR to tools/apktool/."""
    apktool_dir = TOOLS_DIR / "apktool"
    apktool_jar = apktool_dir / "apktool.jar"

    if apktool_jar.exists():
        print(f"[OK] Apktool already installed at {apktool_jar}")
        return True

    print(f"[...] Downloading Apktool v{APKTOOL_VERSION}...")
    try:
        response = requests.get(APKTOOL_URL, stream=True, timeout=120)
        response.raise_for_status()

        apktool_dir.mkdir(parents=True, exist_ok=True)

        with open(apktool_jar, "wb") as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        print(f"[OK] Apktool installed to {apktool_jar}")
        return True

    except Exception as e:
        print(f"[ERROR] Failed to download Apktool: {e}")
        return False


def verify_installation() -> dict[str, bool]:
    """Verify that tools are accessible."""
    results = {}

    # Check JADX
    jadx_paths = [
        TOOLS_DIR / "jadx" / "bin" / "jadx.bat",
        TOOLS_DIR / "jadx" / "bin" / "jadx",
    ]
    jadx_found = any(p.exists() for p in jadx_paths)
    results["jadx"] = jadx_found
    print(f"  JADX: {'[OK]' if jadx_found else '[MISSING]'}")

    # Check Apktool
    apktool_found = (TOOLS_DIR / "apktool" / "apktool.jar").exists()
    results["apktool"] = apktool_found
    print(f"  Apktool: {'[OK]' if apktool_found else '[MISSING]'}")

    # Check Java
    results["java"] = check_java()

    return results


def main():
    """Run the setup script."""
    print("=" * 60)
    print("  MALINT-X Tool Setup")
    print("=" * 60)
    print()

    TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    # Check Java first
    has_java = check_java()
    print()

    # Download tools
    jadx_ok = download_jadx()
    print()
    apktool_ok = download_apktool()
    print()

    # Summary
    print("=" * 60)
    print("  Setup Summary")
    print("=" * 60)
    verify_installation()
    print()

    if not has_java:
        print("[!] Java is required to run JADX and Apktool.")
        print("    Install JRE 11+ from: https://adoptium.net/")
        print("    The MALINT-X extraction pipeline will use fallback")
        print("    methods if Java tools are unavailable.")
        print()

    if jadx_ok and apktool_ok:
        print("[OK] All tools installed successfully!")
    else:
        print("[WARNING] Some tools failed to install.")
        print("  You can install them manually:")
        print(f"  - JADX: {JADX_URL}")
        print(f"  - Apktool: {APKTOOL_URL}")

    return 0 if (jadx_ok and apktool_ok) else 1


if __name__ == "__main__":
    sys.exit(main())

