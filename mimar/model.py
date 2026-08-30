"""The model of a system: trust zones, components, and the flows between them.

A threat model starts with an honest picture of the architecture. Mimar keeps
that picture small and explicit. Zones are trust boundaries with a trust level.
Elements are the things inside them, an external entity, a process, or a data
store. Flows are directed connections that carry data from one element to
another. Everything else in Mimar is derived from this.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

ELEMENT_KINDS = ("entity", "process", "store")


@dataclass
class Zone:
    id: str
    trust: int  # 0 is fully untrusted, higher is more trusted
    label: str = ""

    def name(self) -> str:
        return self.label or self.id


@dataclass
class Element:
    id: str
    kind: str  # one of ELEMENT_KINDS
    zone: str
    sensitive: bool = False  # data stores that hold sensitive data
    label: str = ""

    def name(self) -> str:
        return self.label or self.id


@dataclass
class Flow:
    src: str
    dst: str
    protocol: str = ""
    encrypted: bool = False
    authenticated: bool = False
    label: str = ""

    def name(self) -> str:
        return self.label or (self.src + " to " + self.dst)


@dataclass
class Model:
    name: str = "system"
    zones: Dict[str, Zone] = field(default_factory=dict)
    elements: Dict[str, Element] = field(default_factory=dict)
    flows: List[Flow] = field(default_factory=list)

    # builder helpers, handy for tests and for building a model in code
    def add_zone(self, id: str, trust: int, label: str = "") -> "Model":
        self.zones[id] = Zone(id, trust, label)
        return self

    def add_element(self, id: str, kind: str, zone: str, sensitive: bool = False,
                    label: str = "") -> "Model":
        if kind not in ELEMENT_KINDS:
            raise ValueError("unknown element kind: " + kind)
        self.elements[id] = Element(id, kind, zone, sensitive, label)
        return self

    def add_flow(self, src: str, dst: str, protocol: str = "", encrypted: bool = False,
                 authenticated: bool = False, label: str = "") -> "Model":
        self.flows.append(Flow(src, dst, protocol, encrypted, authenticated, label))
        return self

    def zone_of(self, element_id: str) -> Optional[Zone]:
        el = self.elements.get(element_id)
        if not el:
            return None
        return self.zones.get(el.zone)

    def trust_of(self, element_id: str) -> Optional[int]:
        zone = self.zone_of(element_id)
        return zone.trust if zone else None

    def crosses_boundary(self, flow: Flow) -> bool:
        a = self.elements.get(flow.src)
        b = self.elements.get(flow.dst)
        if not a or not b:
            return False
        return a.zone != b.zone

    def validate(self) -> List[str]:
        """Return a list of problems that make the model itself incoherent."""
        problems = []
        for el in self.elements.values():
            if el.zone not in self.zones:
                problems.append("element '" + el.id + "' is in unknown zone '" + el.zone + "'")
        for i, fl in enumerate(self.flows):
            if fl.src not in self.elements:
                problems.append("flow " + str(i + 1) + " starts at unknown element '" + fl.src + "'")
            if fl.dst not in self.elements:
                problems.append("flow " + str(i + 1) + " ends at unknown element '" + fl.dst + "'")
        return problems

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "zones": [{"id": z.id, "trust": z.trust, "label": z.label} for z in self.zones.values()],
            "elements": [{"id": e.id, "kind": e.kind, "zone": e.zone, "sensitive": e.sensitive,
                          "label": e.label} for e in self.elements.values()],
            "flows": [{"src": f.src, "dst": f.dst, "protocol": f.protocol, "encrypted": f.encrypted,
                       "authenticated": f.authenticated, "label": f.label} for f in self.flows],
        }

    @staticmethod
    def from_dict(data: Dict) -> "Model":
        m = Model(name=data.get("name", "system"))
        for z in data.get("zones", []):
            m.add_zone(z["id"], int(z.get("trust", 0)), z.get("label", ""))
        for e in data.get("elements", []):
            m.add_element(e["id"], e["kind"], e["zone"], bool(e.get("sensitive", False)), e.get("label", ""))
        for f in data.get("flows", []):
            m.add_flow(f["src"], f["dst"], f.get("protocol", ""), bool(f.get("encrypted", False)),
                       bool(f.get("authenticated", False)), f.get("label", ""))
        return m
