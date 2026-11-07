from __future__ import annotations

import os
import stat
import sys
import time

import pytest
from scenarios import banking_trojan

from malintx.analysis.manifest import parse_manifest_text
from malintx.errors import AnalysisError
from malintx.schemas.common import EvidenceKind
from malintx.tools.decompilers import (
    SourceIndex,
    ToolPaths,
    cross_check_manifests,
    decode_manifest_with_apktool,
    enrich_with_source,
    run_jadx,
)
from malintx.tools.runner import run_isolated

PY = sys.executable


def test_timeout_kills_process_tree(tmp_path):
    t = time.time()
    res = run_isolated([PY, "-c", "import time; time.sleep(120)"], cwd=tmp_path, timeout_s=2)
    assert res.timed_out and time.time() - t < 20


def test_environment_is_scrubbed_of_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "super-secret-vt")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "super-secret-anthropic")
    res = run_isolated([PY, "-c", "import os,sys; sys.stdout.write(chr(10).join(f'{k}={v}' for k, v in sorted(os.environ.items())))"], cwd=tmp_path, timeout_s=30)
    assert res.returncode == 0
    assert "super-secret" not in res.stdout and "VT_API_KEY" not in res.stdout and "ANTHROPIC" not in res.stdout
    assert str(tmp_path) in res.stdout  # TEMP redirected into the workspace


def test_output_capture_is_capped(tmp_path):
    res = run_isolated([PY, "-c", "import sys; sys.stdout.write('A' * 5_000_000)"], cwd=tmp_path, timeout_s=30)
    assert len(res.stdout) < 300_000 and "truncated" in res.stdout


def test_exit_code_and_stderr_reported(tmp_path):
    res = run_isolated([PY, "-c", "import sys; sys.stderr.write('oops'); sys.exit(7)"], cwd=tmp_path, timeout_s=30)
    assert res.returncode == 7 and "oops" in res.stderr and not res.timed_out


@pytest.mark.skipif(sys.platform != "win32", reason="Job Object memory limit is the Windows mechanism; POSIX uses RLIMIT_AS")
def test_memory_limit_enforced_on_windows(tmp_path):
    res = run_isolated([PY, "-c", "x = bytearray(1_500_000_000); print('allocated')"], cwd=tmp_path, timeout_s=60, memory_mb=300)
    assert not res.limits_failed and res.limits_applied
    assert res.returncode != 0 and "allocated" not in res.stdout


def test_worker_reports_failure_for_garbage_input(settings, tmp_path):
    from malintx.analysis.runner import run_static_analysis

    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"this is not a zip at all")
    ws = tmp_path / "ws"
    ws.mkdir()
    ing = {"sha256": "0" * 64, "sha1": "0" * 40, "md5": "0" * 32, "size_bytes": 24, "display_name": "bad.apk", "first_seen": "t", "archive": None}
    with pytest.raises(AnalysisError):
        run_static_analysis(bad, ing, settings, ws)


def test_static_analysis_runs_in_isolated_subprocess(settings, tmp_path):
    from malintx.analysis.runner import run_static_analysis
    from malintx.ingestion import ingest_path

    f = tmp_path / "a.apk"
    f.write_bytes(banking_trojan())
    ing = ingest_path(f, settings)
    d = dict(sha256=ing.sha256, sha1=ing.sha1, md5=ing.md5, size_bytes=ing.size_bytes, display_name=ing.display_name,
             first_seen=ing.first_seen, archive=ing.archive.model_dump(mode="json"))
    ws = tmp_path / "ws"
    ws.mkdir()
    r = run_static_analysis(ing.stored_path, d, settings, ws)
    assert r.sample.package_name == "com.fake.update.service" and r.findings
    assert not r.coverage.limitations or not any("resource limit could not be applied" in x for x in r.coverage.limitations)


# ---------------------------------------------------------------------------------------------- decompiler adapters
JAVA = """package com.fake.update.service;

public class SmsRx extends BroadcastReceiver {
    public void onReceive(Context ctx, Intent intent) {
        Object[] pdus = (Object[]) intent.getExtras().get("pdus");
        SmsMessage m = SmsMessage.createFromPdu((byte[]) pdus[0]);
        String body = m.getMessageBody();
        abortBroadcast();
    }
}
"""


def _src(tmp_path):
    root = tmp_path / "sources"
    (root / "com/fake/update/service").mkdir(parents=True)
    (root / "com/fake/update/service/SmsRx.java").write_text(JAVA)
    return root


def test_source_index_locates_call_with_line_numbers(tmp_path):
    idx = SourceIndex(_src(tmp_path))
    line, text = idx.locate("Lcom/fake/update/service/SmsRx;", "onReceive", "createFromPdu", 2)
    assert line == 6 and ">>     6:" in text and "createFromPdu" in text and "abortBroadcast" not in text.split(">>")[0]
    assert idx.locate("Lcom/fake/update/service/SmsRx;", "onReceive", "nothingHere", 2) is None
    assert idx.locate("Lcom/other/Missing;", "m", "x", 2) is None


def test_source_index_is_confined_to_output_dir(tmp_path):
    root = _src(tmp_path)
    (tmp_path / "secret.java").write_text("secret createFromPdu(")
    idx = SourceIndex(root)
    assert idx.locate("L../secret;", "m", "createFromPdu", 2) is None
    assert idx.locate("Lcom/../../secret;", "m", "createFromPdu", 2) is None


def test_enrich_with_source_adds_line_numbers_and_keeps_bytecode(analyzed, tmp_path):
    st = analyzed["banking_trojan"]
    new, n = enrich_with_source(st.evidence, SourceIndex(_src(tmp_path)), 5)
    assert n >= 1
    e = next(x for x in new if x.kind == EvidenceKind.API_CALL and x.api.endswith("createFromPdu"))
    assert e.line_number == 6 and "+jadx-source" in e.extraction_method and "Dalvik bytecode" in e.snippet
    assert [x.id for x in new] == [x.id for x in st.evidence]


def _stub_tool(tmp_path, name, body):
    script = tmp_path / f"{name}_impl.py"
    script.write_text(body)
    if sys.platform == "win32":
        launcher = tmp_path / f"{name}.cmd"
        launcher.write_text(f'@echo off\r\n"{PY}" "{script}" %*\r\n')
    else:
        launcher = tmp_path / name
        launcher.write_text(f'#!/bin/sh\nexec "{PY}" "{script}" "$@"\n')
        launcher.chmod(launcher.stat().st_mode | stat.S_IEXEC)
    return str(launcher)


def test_jadx_adapter_with_stub_executable(settings, tmp_path):
    stub = _stub_tool(tmp_path, "jadx", (
        "import sys, pathlib\n"
        "out = pathlib.Path(sys.argv[sys.argv.index('-d') + 1])\n"
        "(out / 'sources/com/x').mkdir(parents=True)\n"
        "(out / 'sources/com/x/A.java').write_text('class A {}')\n"
        "sys.exit(1)  # JADX exits non-zero on partial decompilation errors\n"))
    warnings: list[str] = []
    out = tmp_path / "jadx_out"
    src = run_jadx(ToolPaths(java=PY, jadx=stub, apktool=None), tmp_path / "x.apk", out, settings, warnings)
    assert src == out / "sources" and (src / "com/x/A.java").exists()
    assert any("reported errors" in w for w in warnings)


def test_jadx_adapter_timeout_and_missing_tool(settings, tmp_path):
    slow = _stub_tool(tmp_path, "jadx", "import time; time.sleep(60)\n")
    s = settings.model_copy(update={"decompiler_timeout_s": 2})
    w: list[str] = []
    assert run_jadx(ToolPaths(PY, slow, None), tmp_path / "x.apk", tmp_path / "o", s, w) is None and any("timed out" in x for x in w)
    assert run_jadx(ToolPaths(None, None, None), tmp_path / "x.apk", tmp_path / "o2", s, []) is None


def test_apktool_manifest_cross_check(settings, tmp_path, analyzed):
    native = analyzed["banking_trojan"].manifest
    xml = '<?xml version="1.0"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.fake.update.service"><application/></manifest>'
    stub = _stub_tool(tmp_path, "apktool", (
        "import sys, pathlib\n"
        "out = pathlib.Path(sys.argv[sys.argv.index('-o') + 1]); out.mkdir(parents=True, exist_ok=True)\n"
        f"(out / 'AndroidManifest.xml').write_text({xml!r})\n"))
    w: list[str] = []
    other = decode_manifest_with_apktool(ToolPaths(PY, None, stub), tmp_path / "x.apk", tmp_path / "ap", settings, w)
    assert other is not None and other.package == native.package
    issues = cross_check_manifests(native, other)
    assert any("permission sets differ" in i for i in issues) and any("component sets differ" in i for i in issues)
    assert cross_check_manifests(native, native) == []


def test_manifest_text_parser_rejects_xml_entity_attacks():
    bomb = '<?xml version="1.0"?><!DOCTYPE m [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;">]><manifest package="x">&b;</manifest>'
    with pytest.raises(Exception, match="(?i)entit|forbidden|DTD"):
        parse_manifest_text(bomb)
    xxe = '<?xml version="1.0"?><!DOCTYPE m [<!ENTITY x SYSTEM "file:///etc/passwd">]><manifest package="x">&x;</manifest>'
    with pytest.raises(Exception, match="(?i)entit|forbidden|DTD"):
        parse_manifest_text(xxe)


def test_stale_env_unchanged():  # sanity: this test module must not leak env into other tests
    assert "super-secret-vt" not in os.environ.values()


def test_nested_runs_in_same_directory_do_not_collide(tmp_path):
    """Worker -> decompiler runs share a cwd with the parent run; capture files must be unique per run."""
    inner = f"import sys; sys.path.insert(0, r'{os.getcwd()}'); from malintx.tools.runner import run_isolated; from pathlib import Path; r = run_isolated([r'{PY}', '-c', 'print(1)'], cwd=Path.cwd(), timeout_s=30); print('inner', r.returncode)"
    res = run_isolated([PY, "-c", inner], cwd=tmp_path, timeout_s=60)
    assert res.returncode == 0 and "inner 0" in res.stdout, res.stderr


REAL = {
    "java": next(iter(__import__("glob").glob(r"C:\Program Files\Microsoft\jdk-*\bin\java.exe")), ""),
    "jadx": str(__import__("pathlib").Path(__file__).parent.parent / "tools" / "jadx" / "bin" / "jadx.bat"),
    "apktool": str(__import__("pathlib").Path(__file__).parent.parent / "tools" / "apktool" / "apktool.bat"),
}


@pytest.mark.skipif(not all(os.path.isfile(v) for v in REAL.values()), reason="real JRE/JADX/Apktool not installed")
def test_real_jadx_and_apktool_end_to_end(settings, tmp_path):
    from malintx.analysis.runner import run_static_analysis
    from malintx.ingestion import ingest_path

    s = settings.model_copy(update={"java_path": REAL["java"], "jadx_path": REAL["jadx"], "apktool_path": REAL["apktool"]})
    f = tmp_path / "a.apk"
    f.write_bytes(banking_trojan())
    ing = ingest_path(f, s)
    d = dict(sha256=ing.sha256, sha1=ing.sha1, md5=ing.md5, size_bytes=ing.size_bytes, display_name=ing.display_name,
             first_seen=ing.first_seen, archive=ing.archive.model_dump(mode="json"))
    ws = tmp_path / "ws"
    ws.mkdir()
    r = run_static_analysis(ing.stored_path, d, s, ws)
    assert r.coverage.source_scan == "bytecode+decompiled_source"
    with_src = [e for e in r.evidence if e.line_number]
    assert with_src and all("+jadx-source" in e.extraction_method and "Dalvik bytecode" in e.snippet for e in with_src)
    assert any("Apktool (consistent)" in x for x in r.coverage.limitations)
