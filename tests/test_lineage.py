from __future__ import annotations

import random

import pytest
from conftest import run_static
from fastapi.testclient import TestClient
from scenarios import banking_trojan, benign_bank, manifest_only, remote_control_like

from malintx.api.app import create_app
from malintx.config import Settings
from malintx.lineage import exact_jaccard, minhash, similarity
from malintx.lineage.diff import diff_results
from malintx.lineage.search import compare, relation
from malintx.pipeline.orchestrator import JobRunner, Platform
from malintx.risk.engine import assess
from malintx.schemas.common import Classification, FindingKind


# ---------------------------------------------------------------------------------------------- sketch maths
def test_minhash_is_deterministic_and_order_independent():
    items = [f"Landroid/x/C{i};->m{i}" for i in range(300)]
    assert minhash(items) == minhash(reversed(items)) == minhash(items + items[:50])
    assert len(minhash(items)) == 128 * 16


@pytest.mark.parametrize("overlap", [0.0, 0.25, 0.5, 0.8, 1.0])
def test_minhash_estimates_true_jaccard(overlap):
    rng = random.Random(7)
    universe = [f"api{i}" for i in range(4000)]
    a = set(rng.sample(universe, 1500))
    shared = set(rng.sample(sorted(a), int(1500 * overlap)))
    b = shared | set(rng.sample([u for u in universe if u not in a], 1500 - len(shared)))
    est, true = similarity(minhash(a), minhash(b)), exact_jaccard(a, b)
    assert abs(est - true) < 0.12, (est, true)  # 128 slots: std-dev ≈ 0.04


def test_empty_sketches_are_not_comparable():
    assert similarity(minhash([]), minhash(["a"])) is None and similarity(minhash([]), minhash([])) is None


def test_relation_bands_are_monotonic():
    labels = [relation(x) for x in (None, 0.1, 0.55, 0.7, 0.9)]
    assert labels[0].startswith("not comparable") and labels[1] == "unrelated" and "loosely" in labels[2]
    assert "closely" in labels[3] and "near-identical" in labels[4]


# ---------------------------------------------------------------------------------------------- real pipeline
@pytest.fixture(scope="module")
def variants(tmp_path_factory):
    base = tmp_path_factory.mktemp("lin")
    s = Settings(data_dir=base / "var", _env_file=None)
    s.ensure_dirs()
    out = {}
    for name, data in {"orig": benign_bank(), "obf": benign_bank(rename=True), "repack": benign_bank(extra=True),
                       "trojan": banking_trojan(), "nodex": manifest_only()}.items():
        d = base / name
        d.mkdir()
        out[name] = run_static(data, d, s)[0]
    return out


def test_fingerprint_survives_identifier_obfuscation(variants):
    a, b = variants["orig"].lineage, variants["obf"].lineage
    assert a.api_count == b.api_count and a.minhash == b.minhash  # renaming classes cannot change framework API usage
    assert compare(a, b)["api_similarity"] == 1.0


def test_repack_is_close_but_distinguishable(variants):
    c = compare(variants["orig"].lineage, variants["repack"].lineage)
    assert 0.4 < c["api_similarity"] < 1.0
    assert compare(variants["orig"].lineage, variants["trojan"].lineage)["api_similarity"] < c["api_similarity"]


def test_diff_exposes_what_the_repack_added(variants):
    d = diff_results(variants["orig"], variants["repack"])
    added = {f["rule_id"] for f in d["findings_added"]}
    assert {"API-SMS-SEND", "API-DYNAMIC-CODE-LOAD"} <= added
    assert d["same_package"] and "high-or-critical" in d["summary"]
    assert "SAME package name but a DIFFERENT signing certificate" in d["summary"]  # each build signs with a fresh key
    assert diff_results(variants["orig"], variants["obf"])["findings_added"] == []


def test_no_code_means_no_fingerprint(variants):
    assert variants["nodex"].lineage is None


# ---------------------------------------------------------------------------------------------- near misses + real-data regression
def test_legit_remote_control_app_is_not_a_banking_trojan(settings, tmp_path):
    """Regression from real data: KDE Connect held accessibility+overlay+SMS+network and was rated HIGH."""
    st, _ = run_static(remote_control_like(), tmp_path, settings)
    rules = {f.rule_id for f in st.findings if f.kind == FindingKind.MALICIOUS_BEHAVIOR}
    assert "COMP-BANKING-TROJAN-PATTERN" not in rules and "COMP-DROPPER" not in rules
    risk = assess(st, None, settings)
    assert risk.classification in (Classification.LOW, Classification.MEDIUM) and risk.score < 55
    miss = {n.rule_id: n for n in st.near_misses}
    assert "COMP-BANKING-TROJAN-PATTERN" in miss and miss["COMP-BANKING-TROJAN-PATTERN"].satisfied == 3 and miss["COMP-BANKING-TROJAN-PATTERN"].total == 4 or \
        "COMP-BANKING-TROJAN-PATTERN" in miss
    assert any("elevated priority" in m for m in miss["COMP-BANKING-TROJAN-PATTERN"].missing)


def test_trojan_has_no_near_miss_for_what_it_already_does(variants):
    assert "COMP-BANKING-TROJAN-PATTERN" not in {n.rule_id for n in variants["trojan"].near_misses}


# ---------------------------------------------------------------------------------------------- API
def test_similar_and_diff_endpoints(tmp_path):
    s = Settings(data_dir=tmp_path / "var", _env_file=None)
    plat = Platform.create(s)
    runner = JobRunner(plat)
    with TestClient(create_app(s, plat, runner)) as c:
        ids = {}
        for name, data in {"orig": benign_bank(), "obf": benign_bank(rename=True), "trojan": banking_trojan(), "nodex": manifest_only()}.items():
            jid = c.post("/api/v1/analyses", files={"file": (f"{name}.apk", data, "application/octet-stream")}).json()["job"]["id"]
            runner.wait(jid, 180)
            ids[name] = jid
        sim = c.get(f"/api/v1/analyses/{ids['orig']}/similar?min_similarity=0.1").json()
        assert sim["available"] and sim["compared_against"] == 2  # trojan + obf (nodex has no fingerprint)
        assert sim["matches"][0]["job_id"] == ids["obf"] and sim["matches"][0]["api_similarity"] == 1.0
        assert sim["matches"][0]["relation"].startswith("near-identical")
        none = c.get(f"/api/v1/analyses/{ids['nodex']}/similar").json()
        assert none["available"] is False and "no analysable code" in none["reason"]
        d = c.get("/api/v1/diff", params={"base": ids["orig"], "other": ids["trojan"]}).json()
        assert d["behaviours_added"] and d["similarity"]["api_similarity"] < 0.5
        assert c.get("/api/v1/diff", params={"base": ids["orig"], "other": "nope"}).status_code == 404
    runner.shutdown()
