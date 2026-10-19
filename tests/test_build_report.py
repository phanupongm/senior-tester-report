import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "senior-tester" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import build_report as br  # noqa: E402

EXAMPLE = json.loads((ROOT / "examples" / "findings.json").read_text(encoding="utf-8"))
PREVIOUS = json.loads((ROOT / "examples" / "previous-findings.json").read_text(encoding="utf-8"))


def minimal(score=10, findings=None):
    return {
        "meta": {"system": "T", "language": "en"},
        "summary": "s",
        "scores": {a: {"score": score, "why": ""} for a in br.AREAS},
        "findings": findings or [],
    }


class ValidateTests(unittest.TestCase):
    def test_example_is_valid(self):
        self.assertEqual(br.validate(EXAMPLE), [])
        self.assertEqual(br.validate(PREVIOUS), [])

    def test_missing_scores(self):
        d = minimal()
        del d["scores"]["security"]
        self.assertTrue(any("scores.security" in e for e in br.validate(d)))

    def test_score_range(self):
        d = minimal()
        d["scores"]["security"]["score"] = 11
        self.assertTrue(any("0-10" in e for e in br.validate(d)))

    def test_critical_needs_steps_and_location(self):
        d = minimal(findings=[{"id": "S-1", "title": "t", "area": "security", "severity": "Critical"}])
        errs = br.validate(d)
        self.assertTrue(any("needs steps" in e for e in errs))
        self.assertTrue(any("location or url" in e for e in errs))

    def test_suspected_critical_does_not_need_steps(self):
        d = minimal(findings=[{"id": "S-1", "title": "t", "area": "security", "severity": "Critical",
                               "confidence": "suspected"}])
        self.assertEqual(br.validate(d), [])

    def test_duplicate_ids_and_prefix(self):
        f = {"id": "F-1", "title": "t", "area": "security", "severity": "Low"}
        errs = br.validate(minimal(findings=[f, dict(f)]))
        self.assertTrue(any("duplicate" in e for e in errs))
        self.assertTrue(any("should start with 'S-'" in e for e in errs))


class ScoringTests(unittest.TestCase):
    def test_perfect(self):
        self.assertEqual(br.overall(minimal(10)), (100, "A", None))

    def test_weighted(self):
        d = minimal(10)
        d["scores"]["security"]["score"] = 0  # weight 25
        self.assertEqual(br.overall(d)[0], 75)

    def test_critical_caps_at_d(self):
        f = {"id": "F-1", "title": "t", "area": "functionality", "severity": "Critical", "steps": ["x"], "url": "/"}
        self.assertEqual(br.overall(minimal(10, [f]))[1:], ("D", "cap_crit"))

    def test_high_security_caps_at_c(self):
        f = {"id": "S-1", "title": "t", "area": "security", "severity": "High", "steps": ["x"], "url": "/"}
        self.assertEqual(br.overall(minimal(10, [f]))[1:], ("C", "cap_sec"))

    def test_suspected_does_not_cap(self):
        f = {"id": "S-1", "title": "t", "area": "security", "severity": "Critical", "confidence": "suspected"}
        self.assertEqual(br.overall(minimal(10, [f]))[1], "A")

    def test_verdict(self):
        self.assertEqual(br.verdict(EXAMPLE), "block")
        self.assertEqual(br.verdict(minimal()), "ok")
        f = {"id": "F-1", "title": "t", "area": "functionality", "severity": "Medium"}
        self.assertEqual(br.verdict(minimal(findings=[f])), "risky")


class RenderTests(unittest.TestCase):
    def test_html_escapes_content(self):
        d = copy.deepcopy(EXAMPLE)
        d["findings"][0]["title"] = "<script>alert(1)</script>"
        out = br.render_html(d, None, None, "en")
        self.assertNotIn("<script>alert(1)</script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_html_sections(self):
        out = br.render_html(EXAMPLE, None, PREVIOUS, "en")
        for s in ("Fix these first", "Compared with previous run", "Persona journeys",
                  "Security checklist", "What to build next", 'id="S-001"'):
            self.assertIn(s, out)
        self.assertNotIn("{{", out)

    def test_thai_labels(self):
        out = br.render_html(EXAMPLE, None, None, "th")
        self.assertIn("ปัญหาที่พบ", out)

    def test_markdown(self):
        md = br.render_md(EXAMPLE, PREVIOUS, "en")
        self.assertIn("### S-001 · Critical", md)
        self.assertIn("Fixed: F-002", md)

    def test_sarif(self):
        s = br.render_sarif(EXAMPLE)
        self.assertEqual(s["version"], "2.1.0")
        run = s["runs"][0]
        ids = {r["ruleId"] for r in run["results"]}
        self.assertIn("S-001", ids)
        self.assertNotIn("U-001", ids)  # URL only, no file location
        s001 = next(r for r in run["results"] if r["ruleId"] == "S-001")
        self.assertEqual(len(s001["locations"]), 2)
        self.assertEqual(s001["locations"][0]["physicalLocation"]["region"]["startLine"], 42)
        rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "S-001")
        self.assertEqual(rule["properties"]["security-severity"], "9.5")

    def test_parse_loc(self):
        self.assertEqual(br.parse_loc("./src/a.ts:12"), ("src/a.ts", 12))
        self.assertEqual(br.parse_loc("src/a.ts:12:4"), ("src/a.ts", 12))
        self.assertEqual(br.parse_loc("src/a.ts"), ("src/a.ts", 1))
        self.assertIsNone(br.parse_loc("/api/results/1"))
        self.assertIsNone(br.parse_loc("https://x.test/a:1"))


class CliTests(unittest.TestCase):
    def test_cli_end_to_end(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            r = subprocess.run([sys.executable, str(SCRIPTS / "build_report.py"),
                                str(ROOT / "examples" / "findings.json"), str(d / "r.html"),
                                "--md", str(d / "r.md"), "--sarif", str(d / "r.sarif"),
                                "--previous", str(ROOT / "examples" / "previous-findings.json")],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue((d / "r.html").stat().st_size > 5000)
            json.loads((d / "r.sarif").read_text(encoding="utf-8"))

    def test_cli_rejects_invalid(self):
        with tempfile.TemporaryDirectory() as d:
            bad = Path(d) / "bad.json"
            bad.write_text(json.dumps({"meta": {}, "summary": "", "scores": {}, "findings": []}))
            r = subprocess.run([sys.executable, str(SCRIPTS / "build_report.py"), str(bad), str(Path(d) / "x.html")],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 1)
            self.assertIn("scores.security missing", r.stderr)


if __name__ == "__main__":
    unittest.main()
