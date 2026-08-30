"""The mimar command line."""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import List, Optional

from . import __version__, report
from .analyze import analyze
from .model import Model
from .parse import parse

_EXAMPLE = """name=Online shop

zone internet trust=0 label="Public internet"
zone dmz trust=3 label="Public facing"
zone app trust=6 label="Application"
zone data trust=9 label="Restricted data"

entity customer in internet label="Customer"
process web in dmz label="Web frontend"
process api in app label="Order API"
store orders in data sensitive label="Customer orders"

flow customer -> web proto=HTTPS encrypted authenticated label="Browse and buy"
flow web -> api proto=HTTP label="Order requests"
flow api -> orders proto=SQL encrypted label="Read and write orders"
"""


def _load(path: str) -> Model:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith(".json"):
        return Model.from_dict(json.loads(text))
    return parse(text)


def cmd_analyze(path: str, fmt: str, output: Optional[str], color: bool) -> int:
    if not os.path.isfile(path):
        print("mimar: no such file: " + path, file=sys.stderr)
        return 2
    try:
        model = _load(path)
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        print("mimar: could not read the model: " + str(exc), file=sys.stderr)
        return 2
    result = analyze(model)

    if fmt == "json":
        rendered = report.to_json(result)
    elif fmt == "markdown":
        rendered = report.to_markdown(result)
    elif fmt == "html":
        rendered = report.to_html(result)
    else:
        rendered = report.to_text(result, color=color and output is None)

    if output:
        with open(output, "w", encoding="utf-8") as fh:
            fh.write(rendered if rendered.endswith("\n") else rendered + "\n")
        print("wrote " + output)
    else:
        print(rendered)

    # a non zero exit if anything critical or high was found, useful in a pipeline
    sev = result["summary"]["severity"]
    return 1 if (sev.get("critical") or sev.get("high")) else 0


def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--no-color", action="store_true", help="Plain text without colors.")
    p = argparse.ArgumentParser(
        prog="mimar", parents=[common],
        description="A security architecture tool. Describe a system as trust zones, components, and "
                    "data flows, and get its threat model: the STRIDE threats and the weaknesses in the architecture.")
    sub = p.add_subparsers(dest="command")

    ap = sub.add_parser("analyze", help="Analyze a model file and print its threat model.", parents=[common])
    ap.add_argument("model", help="Path to a .mimar or .json model file.")
    ap.add_argument("--format", choices=["text", "json", "markdown", "html"], default="text")
    ap.add_argument("--output", help="Write the report to a file instead of the screen.")

    sub.add_parser("example", help="Print an example model to start from.", parents=[common])

    sv = sub.add_parser("serve", help="Open the browser version.", parents=[common])
    sv.add_argument("--host", default="127.0.0.1")
    sv.add_argument("--port", type=int, default=8200)
    sv.add_argument("--open", action="store_true")

    sub.add_parser("version", help="Print the version.", parents=[common])
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    color = not args.no_color and sys.stdout.isatty()
    if args.command == "version":
        print("mimar " + __version__)
        return 0
    if args.command == "example":
        sys.stdout.write(_EXAMPLE)
        return 0
    if args.command == "serve":
        from .serve import run_server
        return run_server(args.host, args.port, open_browser=args.open)
    if args.command == "analyze":
        return cmd_analyze(args.model, args.format, args.output, color)
    _parser().print_help()
    return 0
