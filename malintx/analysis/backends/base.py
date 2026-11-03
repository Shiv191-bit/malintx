"""Backend-neutral code-index types. The rule engine only talks to `CodeBackend`."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Protocol

from malintx.schemas.analysis import AnalysisCoverage

# Third-party library namespaces (smali descriptors). Hits that occur only inside these are
# reported with reduced confidence: the API usage is real but likely belongs to an SDK.
LIBRARY_PREFIXES = (
    "Landroidx/", "Landroid/support/", "Lcom/google/android/gms/", "Lcom/google/firebase/",
    "Lcom/google/android/material/", "Lcom/google/android/play/", "Lcom/google/gson/",
    "Lcom/google/protobuf/", "Lkotlin/", "Lkotlinx/", "Lokhttp3/", "Lokio/", "Lretrofit2/",
    "Lcom/squareup/", "Lcom/facebook/", "Lcom/bumptech/", "Lorg/apache/", "Lio/reactivex/",
    "Lcom/unity3d/", "Lcom/applovin/", "Lcom/adjust/", "Lcom/appsflyer/", "Lcom/crashlytics/",
    "Lio/fabric/", "Lcom/airbnb/", "Lorg/jetbrains/", "Lcom/android/volley/", "Lorg/bouncycastle/",
)


def is_library_class(class_name: str) -> bool:
    return class_name.startswith(LIBRARY_PREFIXES)


def outer_class(class_name: str) -> str:
    """Correlation key for a class.

    Deliberately the *exact* class (nested classes are not folded into their owner): folding would merge
    e.g. an activity's inner OTP `SmsReceiver` with the activity's unrelated networking code and create
    false behavioural correlations in legitimate apps. Name kept for call-site stability.
    """
    return class_name


@dataclass(frozen=True)
class CallSite:
    callee_class: str
    callee_method: str
    callee_desc: str
    caller_class: str
    caller_method: str
    caller_desc: str
    offset: int
    dex_file: str = "classes.dex"


@dataclass(frozen=True)
class StringRef:
    value: str
    caller_class: str | None
    caller_method: str | None
    offset: int | None
    dex_file: str = "classes.dex"


class CodeBackend(Protocol):
    name: str

    def load(self) -> None: ...

    def coverage(self) -> AnalysisCoverage: ...

    def call_sites(
        self, signatures: Iterable[tuple[str, tuple[str, ...] | None]]
    ) -> list[CallSite]: ...

    def subclass_map(self, base_classes: set[str]) -> dict[str, list[str]]: ...

    def strings(self) -> Iterator[StringRef]: ...

    def snippet(self, site: CallSite, radius: int) -> str | None: ...

    def string_snippet(self, ref: StringRef, radius: int) -> str | None: ...

    def internal_class_names(self) -> list[str]: ...
