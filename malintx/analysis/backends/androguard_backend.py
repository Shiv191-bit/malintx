"""Androguard-based bytecode backend. Pure Python: no JVM required.

DEX files are loaded one by one so a single corrupt `classesN.dex` degrades coverage instead of
aborting the analysis. Nothing in the APK is ever executed.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

from malintx.schemas.analysis import AnalysisCoverage

from .base import CallSite, StringRef, is_library_class

log = logging.getLogger(__name__)

_PACKER_LIB_HINTS = {
    "libjiagu": "Qihoo 360 Jiagu",
    "libsecexe": "Bangcle/SecNeo",
    "libsecmain": "Bangcle/SecNeo",
    "libdexhelper": "SecNeo DexHelper",
    "libprotectclass": "Tencent/Legu protector",
    "libshell": "Tencent Legu shell",
    "libbaiduprotect": "Baidu Protect",
    "libnqshield": "NQ Shield",
    "libapkprotect": "ApkProtect",
    "libmobisec": "AliProtect/Ali mobile security",
    "libegis": "Bangcle Egis",
    "libddog": "DexGuard-like loader",
    "libexec.so": "Bangcle exec shell",
    "libijiami": "Ijiami",
    "libkwscmm": "Kiwi/Wushan packer",
}
_PACKER_CLASS_HINTS = {
    "Lcom/stub/StubApp;": "Qihoo 360 Jiagu (StubApp)",
    "Lcom/tencent/StubShell/": "Tencent Legu (StubShell)",
    "Lcom/secneo/": "SecNeo/Bangcle",
    "Lcom/ijiami/": "Ijiami",
    "Lcom/baidu/protect/": "Baidu Protect",
    "Lcom/wrapper/proxyapplication/": "Wrapper proxy application (common packer shell)",
}


class AndroguardBackend:
    name = "androguard"

    def __init__(self, apk_path: Path) -> None:
        self._path = Path(apk_path)
        self.apk: Any = None
        self._dx: Any = None
        self._cov = AnalysisCoverage(backend=self.name)
        self._dex_of_class: dict[str, str] = {}

    # ------------------------------------------------------------------ loading
    def load(self) -> None:
        from loguru import logger as _loguru

        _loguru.remove()  # androguard is extremely chatty at DEBUG; keep our own logging
        import androguard
        from androguard.core.analysis.analysis import Analysis
        from androguard.core.apk import APK
        from androguard.core.dex import DEX

        start = time.perf_counter()
        self._cov.backend_version = getattr(androguard, "__version__", "")
        self.apk = APK(str(self._path))
        self._cov.manifest_parsed = self.apk.get_android_manifest_xml() is not None

        dx = Analysis()
        names = list(self.apk.get_dex_names())
        parsed = 0
        for name, blob in zip(names, self.apk.get_all_dex(), strict=False):
            try:
                dex = DEX(blob)
                dx.add(dex)
                for cls in dex.get_classes():
                    self._dex_of_class[cls.get_name()] = name
                parsed += 1
            except Exception as exc:  # noqa: BLE001 - third-party parser on hostile input
                log.warning("DEX %s failed to parse: %s", name, exc)
                self._cov.dex_files_failed.append(f"{name}: {type(exc).__name__}")
        if parsed:
            dx.create_xref()
        self._dx = dx
        self._cov.dex_files_parsed = parsed

        internal = [c for c in dx.get_classes() if not c.is_external()]
        self._cov.classes = len(internal)
        self._cov.methods = sum(len(list(c.get_methods())) for c in internal)
        self._cov.strings = len(dx.strings) if hasattr(dx, "strings") else 0
        self._cov.obfuscation_ratio = self._obfuscation_ratio(internal)
        files = self.apk.get_files()
        self._cov.native_libraries = sorted(f for f in files if f.startswith("lib/") and f.endswith(".so"))
        self._cov.packer_hints = self._packer_hints(files, [c.name for c in internal])
        self._cov.source_scan = "bytecode"
        self._cov.duration_s = round(time.perf_counter() - start, 2)
        if self._cov.dex_files_failed:
            self._cov.limitations.append(
                f"{len(self._cov.dex_files_failed)} DEX file(s) could not be parsed; their code was not analysed"
            )

    @staticmethod
    def _obfuscation_ratio(internal: list[Any]) -> float | None:
        app = [c.name for c in internal if not is_library_class(c.name)]
        if len(app) < 10:
            return None
        short = 0
        for name in app:
            simple = name.rstrip(";").rsplit("/", 1)[-1].split("$", 1)[0]
            if len(simple) <= 2:
                short += 1
        return round(short / len(app), 3)

    @staticmethod
    def _packer_hints(files: list[str], classes: list[str]) -> list[str]:
        hints: set[str] = set()
        lowered = [f.lower() for f in files]
        for f in lowered:
            base = f.rsplit("/", 1)[-1]
            for key, label in _PACKER_LIB_HINTS.items():
                if base.startswith(key):
                    hints.add(label)
        for cls in classes:
            for prefix, label in _PACKER_CLASS_HINTS.items():
                if cls.startswith(prefix):
                    hints.add(label)
        return sorted(hints)

    # ------------------------------------------------------------------ queries
    def coverage(self) -> AnalysisCoverage:
        return self._cov

    def internal_class_names(self) -> list[str]:
        return [c.name for c in self._dx.get_classes() if not c.is_external()]

    def call_sites(
        self, signatures: Iterable[tuple[str, tuple[str, ...] | None]]
    ) -> list[CallSite]:
        sites: list[CallSite] = []
        seen: set[tuple[str, str, str, str, int]] = set()
        for cls_desc, methods in signatures:
            cls = self._dx.classes.get(cls_desc)
            if cls is None:
                continue
            wanted = None if methods is None else set(methods)
            for m in cls.get_methods():
                if wanted is not None and m.name not in wanted:
                    continue
                for caller_cls, caller_m, offset in m.get_xref_from():
                    em = caller_m.get_method()
                    key = (cls_desc, m.name, caller_cls.name, str(caller_m.name), offset)
                    if key in seen:
                        continue
                    seen.add(key)
                    sites.append(
                        CallSite(
                            callee_class=cls_desc,
                            callee_method=m.name,
                            callee_desc=str(m.descriptor),
                            caller_class=caller_cls.name,
                            caller_method=str(caller_m.name),
                            caller_desc=str(em.get_descriptor()) if hasattr(em, "get_descriptor") else "",
                            offset=int(offset),
                            dex_file=self._dex_of_class.get(caller_cls.name, "classes.dex"),
                        )
                    )
        sites.sort(key=lambda s: (s.caller_class, s.caller_method, s.offset, s.callee_method))
        return sites

    _FRAMEWORK = ("Landroid/", "Ljava/", "Ljavax/", "Ldalvik/", "Lorg/json/", "Lorg/xml/", "Lorg/w3c/", "Lkotlin/jvm/")

    def framework_api_set(self) -> set[str]:
        """Framework methods called by the app's own (non-library) code, as `Lcls;->name`. Names cannot be
        obfuscated, so this set survives renaming/repackaging."""
        apis: set[str] = set()
        for cls in self._dx.get_classes():
            if not cls.is_external() or not cls.name.startswith(self._FRAMEWORK):
                continue
            for m in cls.get_methods():
                for caller_cls, _caller_m, _off in m.get_xref_from():
                    if not is_library_class(caller_cls.name):
                        apis.add(f"{cls.name}->{m.name}")
                        break
        return apis

    def subclass_map(self, base_classes: set[str]) -> dict[str, list[str]]:
        """Map each base class to the internal classes that extend it (transitively)."""
        extends: dict[str, str] = {}
        for c in self._dx.get_classes():
            if not c.is_external() and c.extends:
                extends[c.name] = c.extends
        result: dict[str, list[str]] = {b: [] for b in base_classes}
        for cls in extends:
            cur, hops = extends.get(cls), 0
            while cur and hops < 32:
                if cur in base_classes:
                    result[cur].append(cls)
                    break
                cur = extends.get(cur)
                hops += 1
        return {k: sorted(v) for k, v in result.items() if v}

    def strings(self) -> Iterator[StringRef]:
        for s in self._dx.get_strings():
            value = s.get_value()
            if not value:
                continue
            xrefs = list(s.get_xref_from(with_offset=True))
            if not xrefs:
                yield StringRef(value, None, None, None)
                continue
            xrefs.sort(key=lambda x: (x[0].name, str(x[1].name), x[2]))
            for cls, meth, off in xrefs[:3]:
                yield StringRef(
                    value, cls.name, str(meth.name), int(off), self._dex_of_class.get(cls.name, "classes.dex")
                )

    # ------------------------------------------------------------------ snippets
    def _encoded_method(self, class_name: str, method: str, desc: str) -> Any | None:
        cls = self._dx.classes.get(class_name)
        if cls is None:
            return None
        for m in cls.get_methods():
            if m.name == method and (not desc or str(m.get_method().get_descriptor()) == desc):
                return m.get_method()
        for m in cls.get_methods():
            if m.name == method:
                return m.get_method()
        return None

    def _window(self, class_name: str, method: str, desc: str, offset: int, radius: int) -> str | None:
        em = self._encoded_method(class_name, method, desc)
        if em is None:
            return None
        try:
            instrs = list(em.get_instructions_idx())
        except Exception:  # noqa: BLE001 - malformed method bodies are possible
            return None
        if not instrs:
            return None
        center = next((i for i, (idx, _) in enumerate(instrs) if idx >= offset), len(instrs) - 1)
        lo, hi = max(0, center - radius), min(len(instrs), center + radius + 1)
        lines = [f"# {class_name}->{method}{desc}  (Dalvik bytecode, offsets in bytes)"]
        for i in range(lo, hi):
            idx, ins = instrs[i]
            marker = ">>" if i == center else "  "
            text = f"{marker} {idx:04x}: {ins.get_name()} {ins.get_output()}".rstrip()
            lines.append(text[:220])
        return "\n".join(lines)

    def snippet(self, site: CallSite, radius: int) -> str | None:
        return self._window(site.caller_class, site.caller_method, site.caller_desc, site.offset, radius)

    def string_snippet(self, ref: StringRef, radius: int) -> str | None:
        if ref.caller_class is None or ref.caller_method is None or ref.offset is None:
            return None
        return self._window(ref.caller_class, ref.caller_method, "", ref.offset, radius)
