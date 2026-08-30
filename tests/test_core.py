import json
import unittest

from mimar import report, stride, weaknesses
from mimar.analyze import analyze
from mimar.model import Model
from mimar.parse import parse

SHOP = """name=Shop
zone internet trust=0
zone dmz trust=3
zone app trust=6
zone data trust=9
entity customer in internet
entity admin in internet
process web in dmz
process api in app
store orders in data sensitive
flow customer -> web proto=HTTPS encrypted authenticated
flow web -> api proto=HTTP
flow api -> orders proto=SQL encrypted
flow admin -> orders proto=SQL
"""


class TestParse(unittest.TestCase):
    def test_parses_all_statements(self):
        m = parse(SHOP)
        self.assertEqual(m.name, "Shop")
        self.assertEqual(len(m.zones), 4)
        self.assertEqual(len(m.elements), 5)
        self.assertEqual(len(m.flows), 4)

    def test_zone_trust_and_element_zone(self):
        m = parse(SHOP)
        self.assertEqual(m.zones["data"].trust, 9)
        self.assertEqual(m.elements["orders"].kind, "store")
        self.assertTrue(m.elements["orders"].sensitive)
        self.assertEqual(m.elements["web"].zone, "dmz")

    def test_flow_flags(self):
        m = parse(SHOP)
        first = m.flows[0]
        self.assertTrue(first.encrypted and first.authenticated)
        self.assertEqual(first.protocol, "HTTPS")
        self.assertFalse(m.flows[1].encrypted)

    def test_labels_with_spaces(self):
        m = parse('zone dmz trust=2 label="Public facing"\nprocess web in dmz label="Web tier"')
        self.assertEqual(m.zones["dmz"].label, "Public facing")
        self.assertEqual(m.elements["web"].name(), "Web tier")

    def test_comments_and_blank_lines(self):
        m = parse("# a comment\n\nzone z trust=1\n  # indented comment\n")
        self.assertEqual(len(m.zones), 1)

    def test_unknown_statement_raises(self):
        with self.assertRaises(ValueError):
            parse("banana z trust=1")

    def test_flow_without_arrow_raises(self):
        with self.assertRaises(ValueError):
            parse("zone a trust=0\nprocess p in a\nflow p q")

    def test_roundtrip_dict(self):
        m = parse(SHOP)
        m2 = Model.from_dict(json.loads(json.dumps(m.to_dict())))
        self.assertEqual(len(m2.elements), len(m.elements))
        self.assertEqual(len(m2.flows), len(m.flows))


class TestModel(unittest.TestCase):
    def test_crosses_boundary(self):
        m = parse(SHOP)
        # web(dmz) -> api(app) crosses; customer(internet) -> web(dmz) crosses
        self.assertTrue(m.crosses_boundary(m.flows[1]))

    def test_validate_catches_bad_references(self):
        m = Model()
        m.add_zone("z", 1)
        m.add_element("p", "process", "missing_zone")
        m.add_flow("p", "ghost")
        problems = m.validate()
        self.assertTrue(any("unknown zone" in p for p in problems))
        self.assertTrue(any("ghost" in p for p in problems))


class TestStride(unittest.TestCase):
    def test_process_gets_all_six(self):
        m = Model().add_zone("z", 5).add_element("p", "process", "z")
        ts = [t for t in stride.threats_for(m) if t["target"] == "p"]
        self.assertEqual(len(ts), 6)

    def test_entity_gets_two(self):
        m = Model().add_zone("z", 0).add_element("u", "entity", "z")
        ts = [t for t in stride.threats_for(m) if t["target"] == "u"]
        self.assertEqual({t["category"] for t in ts}, {"S", "R"})

    def test_store_gets_four(self):
        m = Model().add_zone("z", 9).add_element("d", "store", "z")
        ts = [t for t in stride.threats_for(m) if t["target"] == "d"]
        self.assertEqual({t["category"] for t in ts}, {"T", "R", "I", "D"})

    def test_flow_threats_and_mitigations(self):
        m = parse(SHOP)
        ts = stride.threats_for(m)
        self.assertTrue(all(t["mitigation"] for t in ts))
        # every flow contributes T, I, D
        flow_ts = [t for t in ts if t["target_kind"] == "flow"]
        self.assertEqual(len(flow_ts), len(m.flows) * 3)


class TestWeaknesses(unittest.TestCase):
    def test_sensitive_store_from_untrusted_is_critical(self):
        m = parse(SHOP)
        fs = weaknesses.find(m)
        crit = [f for f in fs if f["severity"] == "critical"]
        self.assertTrue(any("Sensitive data store reachable" in f["title"] for f in crit))

    def test_entity_direct_to_store_flagged(self):
        m = parse(SHOP)
        fs = weaknesses.find(m)
        self.assertTrue(any("direct data store access" in f["title"] for f in fs))

    def test_cleartext_across_boundary_flagged(self):
        m = parse(SHOP)
        fs = weaknesses.find(m)
        self.assertTrue(any("Cleartext flow crosses a trust boundary" in f["title"] for f in fs))

    def test_hardened_model_has_no_weaknesses(self):
        hardened = """name=H
zone internet trust=0
zone dmz trust=3
zone app trust=6
zone data trust=9
entity customer in internet
process web in dmz
process api in app
store orders in data sensitive
flow customer -> web proto=HTTPS encrypted authenticated
flow web -> api proto=HTTPS encrypted authenticated
flow api -> orders proto=SQL encrypted authenticated
"""
        fs = weaknesses.find(parse(hardened))
        self.assertEqual(fs, [])

    def test_flat_architecture_flagged(self):
        flat = """name=F
zone all trust=5
entity user in all
process app in all
store db in all
flow user -> app
flow app -> db
"""
        fs = weaknesses.find(parse(flat))
        self.assertTrue(any(f["id"] == "flat-architecture" for f in fs))

    def test_findings_sorted_by_severity(self):
        fs = weaknesses.find(parse(SHOP))
        order = [weaknesses.SEVERITY_ORDER[f["severity"]] for f in fs]
        self.assertEqual(order, sorted(order))


class TestAnalyze(unittest.TestCase):
    def test_grade_and_summary(self):
        r = analyze(parse(SHOP))
        self.assertEqual(r["summary"]["grade"], "F")
        self.assertGreater(r["summary"]["threats"], 0)
        self.assertEqual(r["summary"]["zones"], 4)

    def test_hardened_scores_full(self):
        hardened = """name=H
zone internet trust=0
zone app trust=6
zone data trust=9
entity customer in internet
process web in app
store orders in data sensitive
flow customer -> web proto=HTTPS encrypted authenticated
flow web -> orders proto=SQL encrypted authenticated
"""
        r = analyze(parse(hardened))
        self.assertEqual(r["summary"]["score"], 100)
        self.assertEqual(r["summary"]["grade"], "A")

    def test_reports_render(self):
        r = analyze(parse(SHOP))
        self.assertIn("Shop", report.to_text(r))
        self.assertIn("threat model", report.to_markdown(r))
        html = report.to_html(r)
        self.assertIn("<html", html)
        self.assertIn("STRIDE", html)
        json.loads(report.to_json(r))  # must be valid JSON


if __name__ == "__main__":
    unittest.main()
