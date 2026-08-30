"""Enumerate threats with STRIDE.

STRIDE is a checklist for what can go wrong with each part of a system. Spoofing,
Tampering, Repudiation, Information disclosure, Denial of service, and Elevation
of privilege. Not every category applies to every kind of element, and the
mapping below is the standard one: external entities can be spoofed and can deny
their actions, processes are exposed to all six, data stores face tampering,
repudiation, disclosure, and denial, and data in motion faces tampering,
disclosure, and denial. Each generated threat carries a plain description and a
concrete first mitigation.
"""
from __future__ import annotations

from typing import Dict, List

from .model import Model

# category -> (full name, one line meaning)
CATEGORIES = {
    "S": ("Spoofing", "an attacker pretends to be someone or something they are not"),
    "T": ("Tampering", "data or code is changed without authorization"),
    "R": ("Repudiation", "an action is taken that cannot later be proven or traced"),
    "I": ("Information disclosure", "data is exposed to someone who should not see it"),
    "D": ("Denial of service", "the component is overwhelmed or made unavailable"),
    "E": ("Elevation of privilege", "an attacker gains rights they should not have"),
}

# which categories apply to which element kind
_APPLIES = {
    "entity": ["S", "R"],
    "process": ["S", "T", "R", "I", "D", "E"],
    "store": ["T", "R", "I", "D"],
    "flow": ["T", "I", "D"],
}

# a first mitigation for each (kind, category) pair
_MITIGATION = {
    ("entity", "S"): "Authenticate the entity strongly, with multi factor where it matters.",
    ("entity", "R"): "Log the entity's actions to a tamper evident audit trail.",
    ("process", "S"): "Require authenticated identity for callers, and verify it on every request.",
    ("process", "T"): "Validate all input and protect code and configuration integrity.",
    ("process", "R"): "Write signed, time stamped logs that the process itself cannot quietly alter.",
    ("process", "I"): "Enforce least privilege and return only the data a caller is entitled to.",
    ("process", "D"): "Add rate limiting, timeouts, and resource quotas.",
    ("process", "E"): "Separate privileges, drop them early, and check authorization on every action.",
    ("store", "T"): "Restrict write access and use integrity checks on stored data.",
    ("store", "R"): "Log access to the store and keep those logs outside the store.",
    ("store", "I"): "Encrypt data at rest and enforce access control on every read.",
    ("store", "D"): "Provision for load, back up, and isolate the store from untrusted traffic.",
    ("flow", "T"): "Protect the flow with integrity, such as TLS, so it cannot be altered in transit.",
    ("flow", "I"): "Encrypt the flow so its contents cannot be read in transit.",
    ("flow", "D"): "Guard the endpoints with rate limiting and fail closed under overload.",
}

_KIND_WORD = {"entity": "external entity", "process": "process", "store": "data store", "flow": "data flow"}


def _threat(kind: str, category: str, target_id: str, target_name: str) -> Dict:
    full, meaning = CATEGORIES[category]
    return {
        "id": category + ":" + target_id,
        "category": category,
        "category_name": full,
        "target": target_id,
        "target_name": target_name,
        "target_kind": kind,
        "description": ("The " + _KIND_WORD[kind] + " " + target_name + " is exposed to " +
                        full.lower() + ", where " + meaning + "."),
        "mitigation": _MITIGATION[(kind, category)],
    }


def threats_for(model: Model) -> List[Dict]:
    """Generate the full STRIDE threat register for a model."""
    out: List[Dict] = []
    for el in model.elements.values():
        for category in _APPLIES[el.kind]:
            out.append(_threat(el.kind, category, el.id, el.name()))
    for i, fl in enumerate(model.flows):
        target_id = "flow" + str(i + 1)
        for category in _APPLIES["flow"]:
            out.append(_threat("flow", category, target_id, fl.name()))
    return out


def counts_by_category(threats: List[Dict]) -> Dict[str, int]:
    counts = {c: 0 for c in CATEGORIES}
    for t in threats:
        counts[t["category"]] += 1
    return counts
