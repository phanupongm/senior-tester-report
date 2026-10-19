"""Tests for scan_repo.py.

The vulnerable sample app is generated into a temp folder at test time, and
secret-looking strings are assembled from pieces, so this repository never
contains anything a secret scanner would flag.
"""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "skills" / "senior-tester" / "scripts"
sys.path.insert(0, str(SCRIPTS))

import scan_repo as sr  # noqa: E402

AWS = "AKIA" + "Q" * 16
GH = "ghp_" + "a1B2" * 9


def write(root, rel, text):
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def make_app(root):
    write(root, "package.json", json.dumps({
        "name": "vuln", "scripts": {"dev": "node server.js", "test": "jest"},
        "dependencies": {"express": "^4", "jsonwebtoken": "^9"},
    }))
    write(root, "server.js", "\n".join([
        "const express = require('express');",
        "const app = express();",
        "app.get('/api/public', (req, res) => res.send('ok'));",
        "app.get('/api/users/:id', async (req, res) => {",
        "  const rows = await db.query(\"SELECT * FROM users WHERE id = \" + req.params.id);",
        "  res.json(rows);",
        "});",
        "app.post('/api/admin/delete', requireAuth, (req, res) => res.sendStatus(204));",
        "app.use(cors({ origin: true, credentials: true }));",
        f"const AWS_KEY = '{AWS}';",
        "const password = 'changeme';",
        "el.innerHTML = req.query.msg;",
        "eval(userCode);",
        "https.request({ rejectUnauthorized: false });",
    ]))
    write(root, "app/api/orders/route.ts", "export async function GET() { return Response.json([]) }\n")
    write(root, "app/(shop)/cart/page.tsx", "export default function Page() { return null }\n")
    write(root, "actions.ts", "'use server'\nexport async function del(id) {}\n")
    write(root, "views.py", "from flask import Flask\napp = Flask(__name__)\n@app.route('/hello')\ndef hello():\n    return 'hi'\n")
    write(root, ".env", f"GITHUB_TOKEN={GH}\n")
    write(root, ".gitignore", "node_modules\n")
    write(root, "node_modules/lib/index.js", "eval('ignored');\n")
    write(root, "__tests__/a.test.js", "test('x', () => {})\n")


class ScanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        make_app(cls.root)
        cls.r = sr.scan(cls.root, 40)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_stack(self):
        self.assertIn("Express", self.r["stack"])
        self.assertIn("npm audit --json", self.r["audit_commands"])
        self.assertTrue(any("jest" in t for t in self.r["test_commands"]))

    def test_routes_and_auth_hints(self):
        by_path = {x["path"]: x for x in self.r["routes"]}
        self.assertIn("/api/users/:id", by_path)
        self.assertEqual(by_path["/api/admin/delete"]["auth"], "near-route")
        self.assertIn("/api/orders", by_path)       # Next.js app router API
        self.assertIn("/cart", by_path)             # route group stripped
        self.assertIn("/hello", by_path)            # Flask
        self.assertTrue(self.r["server_action_files"])

    def test_risky_patterns(self):
        for rid in ("sql-concat", "xss-sink", "code-exec", "tls-off", "cors-wide"):
            self.assertIn(rid, self.r["risky"], rid)
        hits = [h["where"] for h in self.r["risky"]["code-exec"]["hits"]]
        self.assertFalse(any("node_modules" in h for h in hits))

    def test_secrets_masked_and_placeholders_skipped(self):
        types = {s["type"] for s in self.r["secrets"]}
        self.assertIn("aws-access-key", types)
        self.assertIn("github-token", types)
        for s in self.r["secrets"]:
            self.assertTrue(s["value"].endswith("…"))
            self.assertNotIn(AWS, s["value"])
        self.assertFalse(any("changeme" in s["value"] for s in self.r["secrets"]))

    def test_env_hygiene(self):
        self.assertIn(".env", self.r["hygiene"]["env_files_present"])
        self.assertFalse(self.r["hygiene"]["env_in_gitignore"])

    def test_markdown_and_cli(self):
        md = sr.to_markdown(self.r)
        self.assertIn("Route inventory", md)
        self.assertNotIn(AWS, md)
        with tempfile.TemporaryDirectory() as out:
            p = subprocess.run([sys.executable, str(SCRIPTS / "scan_repo.py"), str(self.root), "--out", out],
                               capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue((Path(out) / "recon.md").exists())
            self.assertNotIn(AWS, (Path(out) / "recon.json").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
