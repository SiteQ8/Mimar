"""Parse the small language a person uses to describe a system.

The language is line based and reads close to plain notes. It exists so that a
threat model is a short text file anyone can write and review, with no tool and
no dependency. Each line is one of a handful of statements.

  zone internet trust=0
  zone dmz trust=3 label="Public facing"
  entity user in internet label="Customer"
  process web in dmz
  store db in data sensitive label="Customer records"
  flow user -> web proto=HTTPS encrypted authenticated label="Sign in"
  flow web -> db proto=SQL encrypted

Anything after a hash is a comment. A line starting with name= sets the model
name.
"""
from __future__ import annotations

import shlex
from typing import List

from .model import Model


def parse(text: str) -> Model:
    model = Model()
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            raise ValueError("line " + str(lineno) + ": could not read '" + line + "'")
        head = tokens[0].lower()

        if head == "name" and "=" in line:
            model.name = line.split("=", 1)[1].strip().strip('"')
            continue
        if head.startswith("name="):
            model.name = line.split("=", 1)[1].strip().strip('"')
            continue

        if head == "zone":
            _parse_zone(model, tokens, lineno)
        elif head in ("entity", "process", "store"):
            _parse_element(model, head, tokens, lineno)
        elif head == "flow":
            _parse_flow(model, tokens, lineno)
        else:
            raise ValueError("line " + str(lineno) + ": unknown statement '" + tokens[0] + "'")
    return model


def _opts(tokens: List[str]) -> dict:
    """Turn key=value tokens and bare flags into a dict."""
    out = {}
    for tok in tokens:
        if "=" in tok:
            k, v = tok.split("=", 1)
            out[k.lower()] = v.strip('"')
        else:
            out[tok.lower()] = True
    return out


def _parse_zone(model: Model, tokens: List[str], lineno: int) -> None:
    if len(tokens) < 2:
        raise ValueError("line " + str(lineno) + ": zone needs a name")
    zid = tokens[1]
    opts = _opts(tokens[2:])
    trust = int(opts.get("trust", 0))
    model.add_zone(zid, trust, str(opts.get("label", "")) if opts.get("label") not in (True, None) else "")


def _parse_element(model: Model, kind: str, tokens: List[str], lineno: int) -> None:
    if len(tokens) < 4 or tokens[2].lower() != "in":
        raise ValueError("line " + str(lineno) + ": expected '" + kind + " <id> in <zone>'")
    eid = tokens[1]
    zone = tokens[3]
    opts = _opts(tokens[4:])
    sensitive = bool(opts.get("sensitive", False))
    label = str(opts.get("label", "")) if opts.get("label") not in (True, None) else ""
    model.add_element(eid, kind, zone, sensitive, label)


def _parse_flow(model: Model, tokens: List[str], lineno: int) -> None:
    # flow <src> -> <dst> [opts]
    if "->" not in tokens:
        raise ValueError("line " + str(lineno) + ": a flow needs 'src -> dst'")
    arrow = tokens.index("->")
    if arrow < 2 or arrow + 1 >= len(tokens):
        raise ValueError("line " + str(lineno) + ": a flow needs 'src -> dst'")
    src = tokens[arrow - 1]
    dst = tokens[arrow + 1]
    opts = _opts(tokens[arrow + 2:])
    protocol = str(opts.get("proto", "")) if opts.get("proto") not in (True, None) else ""
    label = str(opts.get("label", "")) if opts.get("label") not in (True, None) else ""
    model.add_flow(src, dst, protocol, bool(opts.get("encrypted", False)),
                   bool(opts.get("authenticated", False)), label)
