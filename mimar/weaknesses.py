"""Look for weaknesses in the shape of the architecture itself.

STRIDE lists what could go wrong with each part in isolation. These checks look
at how the parts are arranged, which is where the most serious and most common
design mistakes live. A sensitive store an untrusted zone can reach. Cleartext
crossing a trust boundary. The most trusted zone reachable from the least. Each
finding names the parts involved, says why it matters, and gives the control
that would fix it.
"""
from __future__ import annotations

from typing import Dict, List

from .model import Element, Flow, Model

# how untrusted a zone must be to count as hostile ground
UNTRUSTED_MAX = 1

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _finding(fid: str, severity: str, title: str, why: str, control: str, involved: List[str]) -> Dict:
    return {"id": fid, "severity": severity, "title": title, "why": why,
            "control": control, "involved": involved}


def find(model: Model) -> List[Dict]:
    findings: List[Dict] = []
    zones = model.zones
    els = model.elements

    def zt(zone_id):
        z = zones.get(zone_id)
        return z.trust if z else 0

    trust_values = [z.trust for z in zones.values()]
    highest_trust = max(trust_values) if trust_values else 0

    for i, fl in enumerate(model.flows):
        a: Element = els.get(fl.src)
        b: Element = els.get(fl.dst)
        if not a or not b:
            continue
        crosses = a.zone != b.zone
        src_t, dst_t = zt(a.zone), zt(b.zone)
        pair = [fl.src, fl.dst]

        # a sensitive store reached from an untrusted zone
        if b.kind == "store" and b.sensitive and src_t <= UNTRUSTED_MAX and src_t < dst_t:
            findings.append(_finding(
                "exposed-sensitive-store-" + str(i + 1), "critical",
                "Sensitive data store reachable from an untrusted zone",
                "The store " + b.name() + " holds sensitive data, yet " + a.name() +
                " in an untrusted zone can reach it directly. One compromised entry point then reaches the data.",
                "Place the store behind an application tier that mediates every access, and never expose it to the untrusted zone.",
                pair))

        # an external entity talking straight to a data store
        if a.kind == "entity" and b.kind == "store":
            findings.append(_finding(
                "entity-to-store-" + str(i + 1), "high",
                "External entity has direct data store access",
                "The external entity " + a.name() + " connects straight to the data store " + b.name() +
                ", with no application logic in between to check what it is allowed to do.",
                "Route the entity through a process that enforces authorization, and remove the direct path to the store.",
                pair))

        # the most trusted zone reached from an untrusted one
        if highest_trust > 0 and dst_t == highest_trust and src_t <= UNTRUSTED_MAX and crosses:
            findings.append(_finding(
                "untrusted-to-crown-" + str(i + 1), "high",
                "The most trusted zone is reachable from an untrusted zone",
                a.name() + " sits in an untrusted zone but reaches " + b.name() +
                " in the most trusted zone. A management or core plane should never be one hop from hostile ground.",
                "Separate the trusted zone with a gateway and a jump path, and deny direct access from low trust zones.",
                pair))

        # cleartext across a trust boundary
        if crosses and not fl.encrypted:
            findings.append(_finding(
                "cleartext-crossing-" + str(i + 1), "high",
                "Cleartext flow crosses a trust boundary",
                "The flow " + fl.name() + " moves between zones without encryption, so anyone on the path between them can read or change it.",
                "Encrypt the flow end to end, for example with TLS, wherever it leaves a zone.",
                pair))

        # unauthenticated into a more trusted zone
        if crosses and dst_t > src_t and not fl.authenticated:
            findings.append(_finding(
                "unauth-inbound-" + str(i + 1), "medium",
                "Unauthenticated flow enters a more trusted zone",
                "The flow " + fl.name() + " enters a more trusted zone without authenticating the caller, so the zone trusts a request it has not verified.",
                "Require and verify authentication at the boundary before the request is accepted.",
                pair))

        # sensitive data flow not encrypted, even inside a zone
        if not crosses and not fl.encrypted and (b.kind == "store" and b.sensitive or a.kind == "store" and a.sensitive):
            findings.append(_finding(
                "sensitive-flow-cleartext-" + str(i + 1), "medium",
                "Sensitive data flow is not encrypted",
                "The flow " + fl.name() + " carries sensitive data in the clear. Even inside one zone, an attacker who gains a foothold can read it.",
                "Encrypt the flow so a foothold in the zone does not hand over the data.",
                pair))

    # sensitive store sitting in a low trust zone
    for el in els.values():
        if el.kind == "store" and el.sensitive and zt(el.zone) <= UNTRUSTED_MAX:
            findings.append(_finding(
                "sensitive-in-low-trust-" + el.id, "high",
                "Sensitive data store sits in a low trust zone",
                "The store " + el.name() + " holds sensitive data but lives in a low trust zone, close to where attackers start.",
                "Move the store into a restricted zone with its own trust boundary and tight access control.",
                [el.id]))

    # flat architecture, everything in one zone
    used_zones = {el.zone for el in els.values()}
    if len(used_zones) == 1 and len(els) >= 3:
        kinds = {el.kind for el in els.values()}
        if len(kinds) >= 2:
            findings.append(_finding(
                "flat-architecture", "medium",
                "Flat architecture with no trust segmentation",
                "Every component sits in a single zone, so there is no boundary to contain a breach. Once one part falls, the rest are equally exposed.",
                "Separate the system into zones by trust, for example a public tier, an application tier, and a restricted data tier.",
                sorted(els.keys())))

    # an external entity in the same zone as a data store
    for el in els.values():
        if el.kind == "store":
            for other in els.values():
                if other.kind == "entity" and other.zone == el.zone:
                    findings.append(_finding(
                        "entity-store-same-zone-" + el.id, "medium",
                        "External entity shares a zone with a data store",
                        "The external entity " + other.name() + " and the data store " + el.name() +
                        " are in the same zone, with no boundary between an outsider and the data.",
                        "Put the store in its own restricted zone, separated from any zone an external entity lives in.",
                        [other.id, el.id]))
                    break

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    return findings
