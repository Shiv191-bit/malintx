"""Integrity of the rule catalog against the vendored MITRE and MASVS datasets."""

from __future__ import annotations

import json
import re

from malintx.analysis.rules import catalog as cat
from malintx.analysis.rules.engine import all_rule_meta
from malintx.analysis.rules.manifest_rules import MANIFEST_RULES
from malintx.config import PROJECT_ROOT
from malintx.mitre import get_catalog


def test_catalog_loaded_from_official_dataset():
    c = get_catalog()
    assert c.version == "20.0" and len(c.techniques) > 100
    assert re.fullmatch(r"[0-9a-f]{64}", c.dataset_sha256)
    assert c.require("T1636.004").name == "SMS Messages"
    assert c.require("T1453").name == "Abuse Accessibility Features"
    assert not c.is_valid("T1447")  # an id the earlier hand-written scaffold invented


def test_every_rule_mitre_id_is_a_real_technique():
    c = get_catalog()
    bad = {(rid, t) for rid, m in all_rule_meta().items() for t in m.mitre if not c.is_valid(t)}
    assert not bad, f"rules reference unknown ATT&CK ids: {bad}"


def test_every_masvs_reference_exists():
    controls = json.loads((PROJECT_ROOT / "data" / "masvs" / "masvs-2.0-controls.json").read_text())["controls"]
    bad = {(rid, x) for rid, m in all_rule_meta().items() for x in m.masvs if x not in controls}
    assert not bad, f"unknown MASVS controls: {bad}"


def test_composite_requirements_reference_known_rules():
    known = set(all_rule_meta()) | {"IND-ENDPOINT", "CLS-BROADCAST-RECEIVER", "ARC-PACKER", "ARC-SUSPICIOUS-ENTRIES", "ARC-OBFUSCATED-NAMES", "ARC-TINY-CODE"}
    for comp in cat.COMPOSITE_RULES:
        for req in comp.requires:
            assert set(req.rule_ids) <= known, (comp.id, set(req.rule_ids) - known)


def test_rule_ids_unique_and_every_rule_documents_false_positives():
    all_ids = [r.id for r in (*cat.ALL_API_RULES, *cat.CLASS_RULES, *cat.STRING_RULES, *cat.COMPOSITE_RULES)]
    assert len(all_ids) == len(set(all_ids))
    assert not set(all_ids) & set(MANIFEST_RULES)
    for r in (*cat.API_RULES, *cat.CLASS_RULES):
        if r.kind.value == "suspicious_capability" and r.severity.rank >= 2:
            assert r.fp_notes, f"{r.id} is a high-impact capability rule without false-positive guidance"


def test_string_rule_regexes_compile():
    for r in cat.STRING_RULES:
        re.compile(r.pattern)


def test_only_composites_are_malicious_behaviour():
    for r in (*cat.ALL_API_RULES, *cat.CLASS_RULES, *cat.STRING_RULES):
        assert r.kind.value != "malicious_behavior", f"{r.id}: single signals must be capabilities, not malice"
    for m in MANIFEST_RULES.values():
        assert m.kind.value != "malicious_behavior"
