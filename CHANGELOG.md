# Changelog

## 1.0.0 — 2026-10-19

First public release.

- 7-phase workflow: scope, code recon, persona testing, security review, scoring, ideas, report
- Modes: `full`, `code`, `live`, `quick`, `retest`
- 4 core + 6 optional personas, edge-input kit, journey journals
- OWASP Top 10 (2021) checklist plus secrets and privacy sections, non-destructive probes only
- Stack playbooks for 12 stacks (Express/NestJS, Next.js/Nuxt/SvelteKit, SPAs, Django, Flask/FastAPI, Laravel, WordPress, Rails, Go, Spring Boot, ASP.NET Core, Firebase/Supabase)
- `scan_repo.py`: stack detection, route inventory with auth hints, risky-pattern and masked secret detection, env/git hygiene, test and audit commands
- `build_report.py`: validated `findings.json` → self-contained HTML report (light/dark, mobile, print), Markdown and SARIF 2.1.0 exports, grade caps, run-to-run comparison, embedded screenshots
- Report UI in English and Thai
- Claude Code plugin + marketplace manifests; zip for Claude.ai upload
