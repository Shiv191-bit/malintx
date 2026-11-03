from __future__ import annotations

import json
from pathlib import Path

import pytest
from scenarios import banking_trojan, benign_bank, misconfigured_only, packed_app

from malintx.config import Settings
from malintx.evaluation.cli import main as eval_main
from malintx.evaluation.dataset import DatasetManifest, init_manifest, load_manifest, sha256_file
from malintx.evaluation.metrics import Confusion, duration_stats, technique_scores, wilson
from malintx.evaluation.runner import calibrate, evaluate, predict, render_markdown
from malintx.schemas.common import Classification
from malintx.schemas.results import RiskResult


def test_metrics_match_hand_computation():
    c = Confusion(tp=8, fp=2, tn=18, fn=2)
    s = c.summary()
    assert s["precision"] == 0.8 and s["recall"] == 0.8 and s["f1"] == 0.8
    assert s["false_positive_rate"] == 0.1 and s["false_negative_rate"] == 0.2 and s["n"] == 30
    lo, hi = s["recall_ci95"]
    assert lo < 0.8 < hi and 0.49 < lo < 0.60 and 0.90 < hi < 0.95  # Wilson interval for 8/10


def test_abstentions_count_against_recall_but_not_as_false_positives():
    s = Confusion(tp=5, fn=0, abstain_malicious=5, tn=5, fp=0, abstain_benign=5).summary()
    assert s["recall"] == 0.5 and s["false_negative_rate"] == 0.5
    assert s["false_positive_rate"] == 0.0 and s["abstention_rate"] == 0.5


def test_empty_denominators_are_none_not_zero():
    s = Confusion().summary()
    assert s["precision"] is None and s["recall"] is None and s["f1"] is None and wilson(0, 0) is None


def test_technique_scores_and_durations():
    t = technique_scores([({"T1", "T2"}, {"T1", "T3"}), ({"T4"}, {"T4"})])
    assert (t["tp"], t["fp"], t["fn"]) == (2, 1, 1) and t["precision"] == 0.6667 and t["recall"] == 0.6667
    d = duration_stats([1, 2, 3, 4, 100])
    assert d["median_s"] == 3 and d["p95_s"] == 100 and d["n"] == 5


def test_predict_thresholds_and_abstain():
    def risk(c):
        return RiskResult(classification=c, score=0, summary="", engine_version="1", ruleset_version="1", inputs_digest="d")

    assert predict(risk(Classification.HIGH), "high") == "malicious" and predict(risk(Classification.MEDIUM), "high") == "benign"
    assert predict(risk(Classification.MEDIUM), "medium") == "malicious"
    for c in (Classification.INCONCLUSIVE, Classification.INSUFFICIENT_EVIDENCE, Classification.ANALYSIS_FAILED):
        assert predict(risk(c), "high") == "abstain"
    assert predict(None, "high") == "abstain"


# ---------------------------------------------------------------------------------------------- manifests
def make_dataset(tmp_path: Path, provenance="synthetic", name="synthetic") -> Path:
    d = tmp_path / "ds"
    (d / "malicious").mkdir(parents=True)
    (d / "benign").mkdir()
    files = {"malicious/trojan.apk": banking_trojan(), "benign/bank.apk": benign_bank(), "benign/notes.apk": misconfigured_only(),
             "malicious/packed.apk": packed_app()}
    samples = []
    for rel, data in files.items():
        (d / rel).write_bytes(data)
        label = rel.split("/")[0]
        samples.append({"path": rel, "sha256": sha256_file(d / rel), "label": label, "split": "test",
                        "family": "synthetic-banker" if "trojan" in rel else None, "expected_techniques": ["T1636.004", "T1453"] if "trojan" in rel else [],
                        "source": {"name": name, "provenance": provenance}})
    (d / "manifest.json").write_text(json.dumps({"name": "unit-synthetic", "version": "1", "samples": samples}))
    return d / "manifest.json"


def test_manifest_validation_and_hash_verification(tmp_path):
    mp = make_dataset(tmp_path)
    m, root = load_manifest(mp)
    assert len(m.samples) == 4
    (root / "benign/bank.apk").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="sha256 mismatch"):
        load_manifest(mp)


def test_wild_caught_requires_documented_source_and_date():
    base = {"path": "a.apk", "sha256": "0" * 64, "label": "malicious", "split": "test"}
    with pytest.raises(ValueError, match="documented source"):
        DatasetManifest.model_validate({"name": "n", "version": "1", "samples": [{**base, "source": {"name": "my-friend", "provenance": "wild_caught"}}]})
    with pytest.raises(ValueError, match="retrieved_at"):
        DatasetManifest.model_validate({"name": "n", "version": "1", "samples": [{**base, "source": {"name": "MalwareBazaar", "provenance": "wild_caught"}}]})
    ok = DatasetManifest.model_validate({"name": "n", "version": "1", "samples": [
        {**base, "source": {"name": "MalwareBazaar", "provenance": "wild_caught", "retrieved_at": "2026-01-01"}}]})
    assert ok.samples[0].source.provenance == "wild_caught"


def test_split_leakage_and_duplicates_rejected():
    s = {"path": "a.apk", "sha256": "a" * 64, "label": "benign", "source": {"name": "x", "provenance": "unknown"}}
    with pytest.raises(ValueError, match="split leakage"):
        DatasetManifest.model_validate({"name": "n", "version": "1", "samples": [{**s, "split": "calibration"}, {**s, "split": "test", "path": "b.apk"}]})
    with pytest.raises(ValueError, match="duplicate"):
        DatasetManifest.model_validate({"name": "n", "version": "1", "samples": [{**s, "split": "test"}, {**s, "split": "test", "path": "b.apk"}]})


def test_path_escape_rejected(tmp_path):
    (tmp_path / "outside.apk").write_bytes(b"x")
    d = tmp_path / "ds"
    d.mkdir()
    mp = d / "m.json"
    mp.write_text(json.dumps({"name": "n", "version": "1", "samples": [{"path": "../outside.apk", "sha256": sha256_file(tmp_path / "outside.apk"), "label": "benign",
                                                                         "split": "test", "source": {"name": "x", "provenance": "unknown"}}]}))
    with pytest.raises(ValueError, match="escapes"):
        load_manifest(mp)


def test_init_manifest_defaults_to_unknown_provenance(tmp_path):
    (tmp_path / "malicious").mkdir()
    (tmp_path / "benign").mkdir()
    (tmp_path / "malicious" / "x.apk").write_bytes(b"abc")
    m = init_manifest(tmp_path, "mine", "0.1")
    assert m["samples"][0]["source"]["provenance"] == "unknown" and m["samples"][0]["label"] == "malicious"


# ---------------------------------------------------------------------------------------------- end to end
def test_evaluation_run_on_synthetic_set_is_labelled_and_consistent(tmp_path):
    mp = make_dataset(tmp_path)
    m, root = load_manifest(mp)
    s = Settings(data_dir=tmp_path / "var", _env_file=None)
    s.ensure_dirs()
    rep = evaluate(m, root, s, threshold="high", repeats=2)
    det = rep["detection"]["confusion"]
    assert det["tp"] == 1 and det["tn"] == 2 and det["abstain_malicious"] == 1 and det["fp"] == 0  # packed sample withheld, not scored benign
    assert rep["scoring_consistency"] == {"samples_repeated": 4, "identical_across_repeats": 4, "consistency": 1.0}
    assert rep["extraction_coverage"]["samples_with_usable_code"] == 4
    assert rep["technique_mapping"]["deterministic"]["recall"] == 1.0
    assert rep["technique_mapping"]["ai"].startswith("n/a")
    joined = " ".join(rep["warnings"])
    assert "SYNTHETIC" in joined and "Only 4 samples" in joined
    md = render_markdown(rep)
    assert "⚠" in md and "abstentions" in md and "95% CI" in md


def test_calibration_uses_only_calibration_split(tmp_path):
    mp = make_dataset(tmp_path)
    raw = json.loads(mp.read_text())
    for smp in raw["samples"]:
        smp["split"] = "calibration" if "bank" in smp["path"] or "trojan" in smp["path"] else "test"
    mp.write_text(json.dumps(raw))
    m, root = load_manifest(mp)
    s = Settings(data_dir=tmp_path / "var", _env_file=None)
    s.ensure_dirs()
    out = calibrate(m, root, s)
    assert out["calibration_split_only"] and out["recommended_threshold"] in ("medium", "high", "critical", "low")
    assert len(out["candidates"]) == 4


def test_cli_validate_run_and_failure_recorded_per_sample(tmp_path, capsys):
    mp = make_dataset(tmp_path)
    assert eval_main(["validate", str(mp)]) == 0
    out = tmp_path / "out"
    assert eval_main(["run", str(mp), "--out", str(out)]) == 0
    assert json.loads((out / "results.json").read_text())["dataset"]["samples"] == 4 and (out / "report.md").exists()
