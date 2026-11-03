"""Reproducible evaluation runner: dataset manifest → per-sample analysis → metrics report."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from malintx import __version__
from malintx.analysis.rules.catalog import RULESET_VERSION
from malintx.analysis.runner import run_static_analysis
from malintx.config import Settings
from malintx.evaluation.dataset import DatasetManifest, SampleEntry, load_manifest
from malintx.evaluation.metrics import Confusion, duration_stats, technique_scores
from malintx.ingestion import ingest_path, workspace
from malintx.mitre import get_catalog
from malintx.risk.engine import ENGINE_VERSION, assess
from malintx.schemas.common import Classification
from malintx.schemas.results import RiskResult

LADDER = ["informational", "low", "medium", "high", "critical"]
ABSTAIN = {Classification.INCONCLUSIVE, Classification.INSUFFICIENT_EVIDENCE, Classification.ANALYSIS_FAILED}


@dataclass
class SampleOutcome:
    entry: SampleEntry
    risk: RiskResult | None
    duration_s: float
    error: str | None
    coverage: dict[str, Any]
    predicted_techniques: set[str]
    ai_techniques: set[str] | None
    digests: list[str]


def predict(risk: RiskResult | None, threshold: str) -> str:
    """'malicious' | 'benign' | 'abstain' for a given classification threshold on the ladder."""
    if risk is None or risk.classification in ABSTAIN:
        return "abstain"
    return "malicious" if LADDER.index(risk.classification.value) >= LADDER.index(threshold) else "benign"


def analyse_sample(entry: SampleEntry, root: Path, settings: Settings, repeats: int, ai: bool) -> SampleOutcome:
    import time

    path = root / entry.path
    digests: list[str] = []
    risk: RiskResult | None = None
    err: str | None = None
    cov: dict[str, Any] = {}
    techniques: set[str] = set()
    ai_t: set[str] | None = None
    dur = 0.0
    for i in range(max(1, repeats)):
        t0 = time.perf_counter()
        try:
            ing = ingest_path(path, settings)
            d = {"sha256": ing.sha256, "sha1": ing.sha1, "md5": ing.md5, "size_bytes": ing.size_bytes, "display_name": ing.display_name,
                 "first_seen": ing.first_seen, "archive": ing.archive.model_dump(mode="json")}
            with workspace(settings.workspaces_dir, "eval-") as ws:
                static = run_static_analysis(ing.stored_path, d, settings, ws)
            risk = assess(static, None, settings)
            digests.append(f"{risk.inputs_digest}:{risk.score}:{risk.classification.value}")
            if i == 0:
                techniques = {m.technique_id for m in static.mitre}
                cov = {"manifest_parsed": static.coverage.manifest_parsed, "usable_code": static.coverage.usable_code,
                       "dex_failed": len(static.coverage.dex_files_failed), "packer_hints": bool(static.coverage.packer_hints),
                       "classes": static.coverage.classes, "methods": static.coverage.methods, "indicators": len(static.indicators)}
                if ai:
                    from malintx.ai.service import run_ai

                    res = run_ai(static, None, settings)
                    ai_t = set(res.accepted_mitre) if res.status == "completed" else None
        except Exception as exc:  # noqa: BLE001 - evaluation must record failures per sample, not abort the run
            err = f"{type(exc).__name__}: {str(exc)[:160]}"
            risk = None
        if i == 0:
            dur = time.perf_counter() - t0
    return SampleOutcome(entry, risk, round(dur, 3), err, cov, techniques, ai_t, digests)


def evaluate(manifest: DatasetManifest, root: Path, settings: Settings, *, split: str = "test", threshold: str = "high",
             repeats: int = 1, ai: bool = False) -> dict[str, Any]:
    entries = [s for s in manifest.samples if s.split == split]
    outcomes = [analyse_sample(e, root, settings, repeats, ai) for e in entries]

    conf = Confusion()
    for o in outcomes:
        p = predict(o.risk, threshold)
        if o.entry.label == "malicious":
            if p == "malicious":
                conf.tp += 1
            elif p == "benign":
                conf.fn += 1
            else:
                conf.abstain_malicious += 1
        elif p == "malicious":
            conf.fp += 1
        elif p == "benign":
            conf.tn += 1
        else:
            conf.abstain_benign += 1

    cat = get_catalog(settings)
    labelled = [o for o in outcomes if o.entry.expected_techniques]
    det_pairs = [({t for t in o.entry.expected_techniques if cat.is_valid(t)}, o.predicted_techniques) for o in labelled]
    ai_pairs = [({t for t in o.entry.expected_techniques if cat.is_valid(t)}, o.ai_techniques) for o in labelled if o.ai_techniques is not None]
    consistent = [len(set(o.digests)) == 1 for o in outcomes if len(o.digests) >= 2]
    prov = {}
    for o in outcomes:
        key = f"{o.entry.source.name}/{o.entry.source.provenance}/{o.entry.label}"
        prov[key] = prov.get(key, 0) + 1
    covered = [o.coverage for o in outcomes if o.coverage]
    warnings = []
    if any(o.entry.source.provenance == "synthetic" for o in outcomes):
        warnings.append("This run includes SYNTHETIC samples. Synthetic fixtures verify the plumbing; they say nothing about real-world detection performance.")
    if any(o.entry.source.provenance == "unknown" for o in outcomes):
        warnings.append("Some samples have unknown provenance and must not be described as wild-caught.")
    if len(outcomes) < 30:
        warnings.append(f"Only {len(outcomes)} samples: confidence intervals are wide; do not draw performance claims from this run.")
    if not any(o.entry.label == "benign" for o in outcomes) or not any(o.entry.label == "malicious" for o in outcomes):
        warnings.append("Both malicious and benign samples are needed for meaningful precision / false-positive rates.")

    return {
        "dataset": {"name": manifest.name, "version": manifest.version, "split": split, "samples": len(outcomes), "provenance_breakdown": prov},
        "configuration": {"decision_threshold": f">= {threshold}", "abstain_classifications": sorted(a.value for a in ABSTAIN), "repeats": repeats,
                          "platform": __version__, "ruleset": RULESET_VERSION, "risk_engine": ENGINE_VERSION, "mitre": cat.source,
                          "run_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "ai_evaluated": ai},
        "detection": conf.summary(),
        "analysis_duration": duration_stats([o.duration_s for o in outcomes if o.error is None]),
        "extraction_coverage": {
            "samples_with_manifest": sum(1 for c in covered if c["manifest_parsed"]), "samples_with_usable_code": sum(1 for c in covered if c["usable_code"]),
            "samples_packer_hinted": sum(1 for c in covered if c["packer_hints"]), "analysed": len(covered), "errors": sum(1 for o in outcomes if o.error),
        },
        "scoring_consistency": {"samples_repeated": len(consistent), "identical_across_repeats": sum(consistent),
                                "consistency": None if not consistent else round(sum(consistent) / len(consistent), 4)},
        "technique_mapping": {"deterministic": technique_scores(det_pairs) if det_pairs else "n/a (no expected_techniques labels)",
                              "ai": technique_scores(ai_pairs) if ai_pairs else "n/a (AI not run, unavailable, or no labels)"},
        "samples": [{"sha256": o.entry.sha256, "label": o.entry.label, "family": o.entry.family, "classification": o.risk.classification.value if o.risk else None,
                     "score": o.risk.score if o.risk else None, "prediction": predict(o.risk, threshold), "duration_s": o.duration_s, "error": o.error}
                    for o in outcomes],
        "warnings": warnings,
    }


def calibrate(manifest: DatasetManifest, root: Path, settings: Settings) -> dict[str, Any]:
    """Choose the decision threshold that maximises F1 on the *calibration* split only."""
    rows = []
    for th in LADDER[1:]:
        r = evaluate(manifest, root, settings, split="calibration", threshold=th)
        rows.append({"threshold": th, "f1": r["detection"]["f1"], "precision": r["detection"]["precision"], "recall": r["detection"]["recall"],
                     "fpr": r["detection"]["false_positive_rate"]})
    best = max(rows, key=lambda r: (r["f1"] or 0, LADDER.index(r["threshold"])))
    return {"calibration_split_only": True, "candidates": rows, "recommended_threshold": best["threshold"]}


def render_markdown(report: dict[str, Any]) -> str:
    d, det, cfg = report["dataset"], report["detection"], report["configuration"]
    pct = lambda v: "n/a" if v is None else f"{v:.1%}"  # noqa: E731
    ci = lambda v: "" if not v else f" (95% CI {v[0]:.1%}–{v[1]:.1%})"  # noqa: E731
    lines = [f"# MALINT-X evaluation: {d['name']} v{d['version']} ({d['split']} split)", "",
             f"Run at {cfg['run_at']} · platform {cfg['platform']} · rule set {cfg['ruleset']} · engine {cfg['risk_engine']} · {cfg['mitre']}", ""]
    lines += [f"> ⚠ {w}" for w in report["warnings"]] + [""]
    lines += ["## Detection", f"Decision rule: malicious if classification {cfg['decision_threshold']}; inconclusive / insufficient / failed are *abstentions*.", "",
              f"- Samples: {det['n']}  ·  confusion: {det['confusion']}",
              f"- Precision: {pct(det['precision'])}{ci(det['precision_ci95'])}",
              f"- Recall: {pct(det['recall'])}{ci(det['recall_ci95'])} (abstentions on malware count as misses)",
              f"- F1: {pct(det['f1'])}",
              f"- False-positive rate: {pct(det['false_positive_rate'])}{ci(det['false_positive_rate_ci95'])}",
              f"- False-negative rate: {pct(det['false_negative_rate'])}{ci(det['false_negative_rate_ci95'])}",
              f"- Abstention rate: {pct(det['abstention_rate'])}", "",
              "## Performance and coverage", f"- Analysis duration: {report['analysis_duration']}", f"- Extraction coverage: {report['extraction_coverage']}",
              f"- Scoring consistency: {report['scoring_consistency']}", "", "## ATT&CK technique mapping",
              f"- Deterministic rules: {report['technique_mapping']['deterministic']}", f"- AI: {report['technique_mapping']['ai']}", "",
              "## Provenance", *[f"- {k}: {v}" for k, v in d["provenance_breakdown"].items()], "",
              "## Per-sample results", "| sha256 | label | family | classification | score | prediction | s |", "|---|---|---|---|---|---|---|"]
    for s in report["samples"]:
        lines.append(f"| {s['sha256'][:12]} | {s['label']} | {s['family'] or ''} | {s['classification'] or s['error']} | {s['score']} | {s['prediction']} | {s['duration_s']} |")
    return "\n".join(lines) + "\n"


def run_from_files(manifest_path: Path, out_dir: Path, *, split: str, threshold: str, repeats: int, ai: bool, data_dir: Path | None = None) -> dict[str, Any]:
    manifest, root = load_manifest(manifest_path)
    with tempfile.TemporaryDirectory() as tmp:
        settings = Settings(data_dir=data_dir or Path(tmp), _env_file=None)
        settings.ensure_dirs()
        report = evaluate(manifest, root, settings, split=split, threshold=threshold, repeats=repeats, ai=ai)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "results.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")
    return report
