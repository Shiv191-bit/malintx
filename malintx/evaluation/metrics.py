"""Evaluation metrics with confidence intervals and explicit abstention handling."""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass


def wilson(successes: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    if n == 0:
        return None
    p = successes / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return round(max(0.0, centre - half), 4), round(min(1.0, centre + half), 4)


def ratio(num: int, den: int) -> float | None:
    return None if den == 0 else round(num / den, 4)


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    abstain_malicious: int = 0  # withheld verdict on a malicious sample (counts against recall)
    abstain_benign: int = 0  # withheld verdict on a benign sample (reported, not a false positive)

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.tn + self.fn + self.abstain_malicious + self.abstain_benign

    def summary(self) -> dict:
        precision = ratio(self.tp, self.tp + self.fp)
        mal = self.tp + self.fn + self.abstain_malicious
        recall = ratio(self.tp, mal)
        f1 = None if precision is None or recall is None or (precision + recall) == 0 else round(2 * precision * recall / (precision + recall), 4)
        ben_decided = self.fp + self.tn
        return {
            "n": self.n, "confusion": {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn,
                                       "abstain_malicious": self.abstain_malicious, "abstain_benign": self.abstain_benign},
            "precision": precision, "precision_ci95": wilson(self.tp, self.tp + self.fp),
            "recall": recall, "recall_ci95": wilson(self.tp, mal),
            "f1": f1,
            "false_positive_rate": ratio(self.fp, ben_decided), "false_positive_rate_ci95": wilson(self.fp, ben_decided),
            "false_negative_rate": ratio(self.fn + self.abstain_malicious, mal),
            "false_negative_rate_ci95": wilson(self.fn + self.abstain_malicious, mal),
            "abstention_rate": ratio(self.abstain_malicious + self.abstain_benign, self.n),
        }


def duration_stats(values: list[float]) -> dict:
    if not values:
        return {"n": 0}
    s = sorted(values)
    return {"n": len(s), "mean_s": round(statistics.fmean(s), 3), "median_s": round(statistics.median(s), 3),
            "p95_s": round(s[min(len(s) - 1, math.ceil(0.95 * len(s)) - 1)], 3), "max_s": round(s[-1], 3)}


def technique_scores(pairs: list[tuple[set[str], set[str]]]) -> dict:
    """pairs: (expected, predicted) technique-id sets per sample → micro precision/recall/F1."""
    tp = sum(len(e & p) for e, p in pairs)
    fp = sum(len(p - e) for e, p in pairs)
    fn = sum(len(e - p) for e, p in pairs)
    precision, recall = ratio(tp, tp + fp), ratio(tp, tp + fn)
    f1 = None if not precision or not recall else round(2 * precision * recall / (precision + recall), 4)
    return {"samples": len(pairs), "tp": tp, "fp": fp, "fn": fn, "precision": precision, "recall": recall, "f1": f1}
