# Scoring rubric

Score each area 0–10 by choosing the anchor that best fits, then adjust by at most ±1. The justification (`why`) names the finding IDs behind the score. Fixed anchors make scores comparable across runs and across reviewers.

## Areas and weights

| Key | Area | Weight | Covers |
|---|---|---|---|
| `functionality` | Functionality | 25 | Features produce correct results; no crashes, 5xx, data loss |
| `security` | Security | 25 | Everything in the security checklist |
| `usability` | Usability | 15 | Personas can finish key journeys without confusion |
| `mobile` | Mobile & responsive | 10 | Works and is comfortable at ~390 px |
| `performance` | Performance & stability | 10 | Load time, responsiveness, no flaky behaviour, handles slow network |
| `code_quality` | Code quality | 10 | Tests, structure, error handling, maintainability risks |
| `accessibility` | Accessibility | 5 | Labels, contrast, keyboard use, focus, zoom |

Overall = weighted average × 10 → 0–100 (computed by `build_report.py`).

## Anchors

| Score | Meaning |
|---|---|
| **10** | Nothing worse than Info found in this area |
| **8** | Only Low findings; every key journey succeeds for every persona |
| **6** | At least one Medium, or a persona needed many attempts on a key journey |
| **4** | At least one High, or a key journey fails for one persona |
| **2** | Several High, or a key journey fails for most personas |
| **0** | A Critical finding in this area, or the area doesn't work at all |

If an area couldn't be tested, score what you could observe and say so in `why` (e.g. "code only, not tested live").

## Grade and caps (applied by the script)

A ≥ 90 · B ≥ 80 · C ≥ 70 · D ≥ 60 · F < 60

- Any **Critical** finding → grade can't be better than **D**
- Any **High** finding in `security` → grade can't be better than **C**

Caps exist because a high average must never hide one problem that can sink the product.

## Severity

Judge severity by **impact × likelihood** for this app's real users, not by category name.

| Severity | Meaning | Examples |
|---|---|---|
| **Critical** | Data breach, account takeover, money loss, or a core flow broken for everyone | IDOR exposing every user's records; production DB password committed; checkout always fails |
| **High** | Serious harm to some users, easy abuse, or a key flow broken in common conditions | Normal user can call an admin API; submit button unreachable on iOS Safari; stored XSS in comments |
| **Medium** | Wrong behaviour with a workaround, or a weakness needing extra conditions | No login rate limit; negative quantities accepted; export breaks on non-ASCII filenames |
| **Low** | Minor bug, cosmetic issue, small friction | Vague error text; overflow at one width; missing `aria-label` on one button |
| **Info** | Observation or hardening tip, not a defect | Missing `Referrer-Policy` on a static marketing page |

## Confidence

- `confirmed` — reproduced live, or the code path is unambiguous
- `suspected` — strong signal but not reproduced (e.g. scanner hit in code you couldn't reach live). Suspected findings still count toward scores, but at one severity level lower.
