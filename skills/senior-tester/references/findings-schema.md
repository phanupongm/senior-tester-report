# findings.json format

`build_report.py` validates this before rendering. A machine-readable JSON Schema lives at `schema/findings.schema.json` (editors like VS Code will autocomplete if you add `"$schema": "<path>/findings.schema.json"`).

## Example

```json
{
  "meta": {
    "system": "Acme Exams",
    "version": "a1b2c3d",
    "date": "2026-10-19",
    "mode": "full",
    "repo": "github.com/acme/exams",
    "url": "http://localhost:3000",
    "language": "en",
    "scope_notes": "Tested on localhost with seeded accounts for 3 roles. File upload not tested.",
    "personas": ["First-timer", "Mobile user", "Intruder", "Admin"]
  },
  "summary": "2–4 sentences: overall verdict in plain language, the biggest risk, and whether it's ready to ship.",
  "scores": {
    "functionality": { "score": 7, "why": "F-001 export breaks on non-ASCII filenames" },
    "security":      { "score": 0, "why": "S-001 IDOR on results API" },
    "usability":     { "score": 6, "why": "U-001 no save confirmation" },
    "mobile":        { "score": 4, "why": "M-001 submit button hidden on iOS" },
    "performance":   { "score": 8, "why": "No issues; pages < 1 s on localhost" },
    "code_quality":  { "score": 5, "why": "C-001 no tests for access control" },
    "accessibility": { "score": 6, "why": "A-001 icon buttons without labels" }
  },
  "findings": [
    {
      "id": "S-001",
      "title": "Students can read other students' results by changing the ID",
      "area": "security",
      "severity": "Critical",
      "confidence": "confirmed",
      "persona": "Intruder",
      "owasp": "A01",
      "cwe": "CWE-639",
      "location": "src/routes/results.ts:42",
      "locations": ["src/routes/results.ts:42", "src/routes/answers.ts:18"],
      "url": "/api/results/124",
      "steps": ["Log in as student1", "GET /api/results/124 (owned by student2)", "Response is 200 with student2's score"],
      "expected": "403 Forbidden",
      "actual": "200 with another student's data",
      "evidence": "{\"studentId\":2,\"score\":87}",
      "screenshot": "S-001.png",
      "fix": "Check that the result belongs to the logged-in user before returning it.",
      "fix_code": "if (result.studentId !== req.user.id) return res.sendStatus(403);"
    }
  ],
  "journeys": [
    { "persona": "First-timer", "goal": "Sign up and join an exam", "result": "struggled", "attempts": 3, "note": "Join-code field below the fold" }
  ],
  "checks": [
    { "id": "A01", "item": "Ownership check on every record route", "status": "fail", "ref": "S-001" }
  ],
  "ideas": [
    { "title": "Automated access-control tests", "why": "Would have caught S-001 before release", "effort": "S", "impact": "High" }
  ]
}
```

## Field rules

**Required:** `meta`, `summary`, `scores` (all 7 areas), `findings` (may be empty).

**Finding IDs** use an area prefix and stay **stable across runs** for the same issue, so `--previous` comparison works:
`F-` functionality · `S-` security · `U-` usability · `M-` mobile · `P-` performance · `C-` code_quality · `A-` accessibility

| Field | Values |
|---|---|
| `area` | `functionality` `security` `usability` `mobile` `performance` `code_quality` `accessibility` |
| `severity` | `Critical` `High` `Medium` `Low` `Info` |
| `confidence` | `confirmed` (default) `suspected` |
| `owasp` | `A01`…`A10`, `SECRETS`, `PRIVACY` |
| `location` | `path:line` — primary location; used for SARIF |
| `locations` | extra `path:line` entries when one root cause appears in several places |
| `journeys[].result` | `success` `struggled` `stuck` `failed` |
| `checks[].status` | `pass` `fail` `na` `unchecked` |
| `ideas[].effort` | `S` `M` `L` |
| `ideas[].impact` | `Low` `Med` `High` |
| `meta.language` | Report UI language. Built in: `en`, `th`. Others fall back to English labels; write the content itself in the user's language |

Confirmed **Critical/High** findings must have `steps` and a `location` or `url` (the script enforces this).

Optional everywhere: `persona`, `owasp`, `cwe`, `url`, `locations`, `screenshot`, `evidence`, `fix_code`, `expected`, `actual`.

Never put real secrets, real users' personal data, or passwords in any field.
