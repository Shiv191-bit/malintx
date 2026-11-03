"""Safe subprocess execution for untrusted-sample processing.

* never uses a shell; argument lists only
* scrubbed environment (no API keys or tokens ever reach a child process)
* wall-clock timeout with whole-process-tree termination
* stdout/stderr captured to files with a hard size cap (no pipe deadlocks, bounded memory)
* memory limit: Windows Job Object / POSIX RLIMIT_AS; failure to apply is reported, not hidden
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

MAX_CAPTURE_BYTES = 256 * 1024


@dataclass
class RunResult:
    returncode: int | None
    timed_out: bool
    duration_s: float
    stdout: str = ""
    stderr: str = ""
    limits_applied: list[str] = field(default_factory=list)
    limits_failed: list[str] = field(default_factory=list)


def minimal_env(workdir: Path) -> dict[str, str]:
    env = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUTF8": "1",
        "TMP": str(workdir),
        "TEMP": str(workdir),
        "TMPDIR": str(workdir),
        "HOME": str(workdir),
    }
    for key in ("SYSTEMROOT", "SystemRoot", "PATH", "LANG", "LC_ALL", "JAVA_HOME"):
        if key in os.environ and key != "PATH":
            env[key] = os.environ[key]
    # PATH is kept only for locating java/jadx; it contains no secrets by convention.
    if "PATH" in os.environ:
        env["PATH"] = os.environ["PATH"]
    return env


def _read_capped(path: Path) -> str:
    try:
        with path.open("rb") as fh:
            data = fh.read(MAX_CAPTURE_BYTES + 1)
    except OSError:
        return ""
    text = data[:MAX_CAPTURE_BYTES].decode("utf-8", errors="replace")
    return text + ("\n… (output truncated)" if len(data) > MAX_CAPTURE_BYTES else "")


# --------------------------------------------------------------------- Windows job object
def _windows_apply_memory_limit(proc: subprocess.Popen[bytes], limit_mb: int) -> bool:
    import ctypes
    from ctypes import wintypes

    class BASIC(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD),
        ]

    class IOC(ctypes.Structure):
        _fields_ = [(n, ctypes.c_uint64) for n in (
            "ReadOps", "WriteOps", "OtherOps", "ReadBytes", "WriteBytes", "OtherBytes")]

    class EXT(ctypes.Structure):
        _fields_ = [
            ("Basic", BASIC), ("Io", IOC), ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateJobObjectW.restype = wintypes.HANDLE
    k32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    k32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    job = k32.CreateJobObjectW(None, None)
    if not job:
        return False
    info = EXT()
    info.Basic.LimitFlags = 0x100 | 0x2000  # PROCESS_MEMORY | KILL_ON_JOB_CLOSE
    info.ProcessMemoryLimit = limit_mb * 1024 * 1024
    if not k32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
        return False
    if not k32.AssignProcessToJobObject(job, wintypes.HANDLE(int(proc._handle))):  # type: ignore[attr-defined]
        return False
    # Keep the handle alive for the process lifetime: closing it would kill the child (KILL_ON_JOB_CLOSE).
    proc._malintx_job = job  # type: ignore[attr-defined]
    return True


def _posix_preexec(memory_mb: int | None, cpu_s: int | None):  # pragma: no cover - not exercised on Windows
    def apply() -> None:
        import resource

        if memory_mb:
            resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 2**20, memory_mb * 2**20))
        if cpu_s:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s))
        resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 2**30, 2 * 2**30))
        os.setsid()

    return apply


def _kill_tree(proc: subprocess.Popen[bytes]) -> None:
    if proc.poll() is not None:
        return
    if sys.platform == "win32":
        subprocess.run(  # noqa: S603
            ["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True, check=False, timeout=15
        )
    else:  # pragma: no cover
        import signal

        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            proc.kill()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def run_isolated(
    cmd: list[str],
    *,
    cwd: Path,
    timeout_s: float,
    memory_mb: int | None = None,
    env: dict[str, str] | None = None,
) -> RunResult:
    """Run *cmd* without a shell inside *cwd* with the documented limits."""
    cwd.mkdir(parents=True, exist_ok=True)
    tag = uuid.uuid4().hex[:8]  # unique per run: nested runs (worker -> JADX) share a directory
    out_path, err_path = cwd / f".stdout-{tag}", cwd / f".stderr-{tag}"
    result = RunResult(returncode=None, timed_out=False, duration_s=0.0)
    popen_kwargs: dict = {}
    if sys.platform == "win32":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    else:  # pragma: no cover
        popen_kwargs["preexec_fn"] = _posix_preexec(memory_mb, int(timeout_s) + 30)  # noqa: PLW1509
        if memory_mb:
            result.limits_applied.append(f"RLIMIT_AS={memory_mb}MiB")
    start = time.perf_counter()
    with out_path.open("wb") as fo, err_path.open("wb") as fe:
        proc = subprocess.Popen(  # noqa: S603
            cmd, cwd=cwd, env=env if env is not None else minimal_env(cwd), stdin=subprocess.DEVNULL,
            stdout=fo, stderr=fe, shell=False, **popen_kwargs,
        )
        if sys.platform == "win32" and memory_mb:
            try:
                ok = _windows_apply_memory_limit(proc, memory_mb)
            except Exception as exc:  # noqa: BLE001 - ctypes failures must not abort analysis
                log.warning("job object setup failed: %s", exc)
                ok = False
            (result.limits_applied if ok else result.limits_failed).append(f"JobObject memory={memory_mb}MiB")
        try:
            proc.wait(timeout=timeout_s)
        except subprocess.TimeoutExpired:
            result.timed_out = True
            _kill_tree(proc)
    result.returncode = proc.returncode
    result.duration_s = round(time.perf_counter() - start, 2)
    result.stdout, result.stderr = _read_capped(out_path), _read_capped(err_path)
    for p in (out_path, err_path):
        p.unlink(missing_ok=True)
    return result
