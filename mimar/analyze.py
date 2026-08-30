"""Run the whole analysis over a model and score the result.

This ties STRIDE and the architecture checks together and turns the weaknesses
into a single grade, the way the other tools in this family do. The grade is a
blunt summary; the findings are the substance.
"""
from __future__ import annotations

from typing import Dict, List

from . import stride, weaknesses
from .model import Model

# how many points each weakness costs the score
_WEIGHT = {"critical": 30, "high": 15, "medium": 7, "low": 3, "info": 0}


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def analyze(model: Model) -> Dict:
    problems = model.validate()
    findings = weaknesses.find(model)
    threats = stride.threats_for(model)

    score = 100
    for f in findings:
        score -= _WEIGHT.get(f["severity"], 0)
    score = max(0, score)

    sev_counts = {s: 0 for s in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1

    kinds = {"entity": 0, "process": 0, "store": 0}
    for el in model.elements.values():
        kinds[el.kind] = kinds.get(el.kind, 0) + 1

    return {
        "name": model.name,
        "problems": problems,
        "summary": {
            "zones": len(model.zones),
            "elements": len(model.elements),
            "flows": len(model.flows),
            "entities": kinds["entity"],
            "processes": kinds["process"],
            "stores": kinds["store"],
            "threats": len(threats),
            "weaknesses": len(findings),
            "severity": sev_counts,
            "score": score,
            "grade": _grade(score),
        },
        "weaknesses": findings,
        "threats": threats,
        "stride_counts": stride.counts_by_category(threats),
    }
