# Contributing

Thanks for helping make `senior-tester` better. Good contributions usually fall into one of these:

- **Stack playbooks** — add or improve a section in `skills/senior-tester/references/stack-playbooks.md`: where routes live, where auth is checked, and the mistakes you've actually seen.
- **Scanner patterns** — new route, risky-code or secret patterns in `scripts/scan_repo.py`. Every pattern needs a test in `tests/test_scan_repo.py`, and should keep false positives low (run it on a real project and look at the noise).
- **Report translations** — add a language dictionary to `L` in `scripts/build_report.py` and a test.
- **Personas and checklist items** — grounded in real bugs, not theory.
- **Bug reports** — include the command, your OS and Python version, and (sanitized!) `findings.json` or the scanner output.

## Ground rules

- **Standard library only** for the scripts. Users shouldn't need `pip install` to run them.
- **Python 3.9+** compatible.
- **Nothing destructive.** The skill must never instruct Claude to run payloads that modify data, brute force, or overload a system. Probes stay harmless.
- **No real secrets in the repo**, even in tests. Build secret-shaped strings from pieces at test time (see `tests/test_scan_repo.py`).
- Keep `SKILL.md` focused on workflow; put detail in `references/`.

## Development

```bash
python3 -m unittest discover -s tests -v
python3 skills/senior-tester/scripts/build_report.py examples/findings.json /tmp/r.html \
  --previous examples/previous-findings.json --md /tmp/r.md --sarif /tmp/r.sarif
claude plugin validate .        # if you have Claude Code installed
```

If you change the report template or `build_report.py`, regenerate the examples:

```bash
python3 skills/senior-tester/scripts/build_report.py examples/findings.json examples/qa-report.html \
  --previous examples/previous-findings.json --md examples/qa-report.md --sarif examples/qa-findings.sarif
```

## Releases

Bump `version` in `.claude-plugin/plugin.json` and `VERSION` in `build_report.py` and update `CHANGELOG.md`. Then either push a tag `vX.Y.Z`, publish a release in the GitHub UI, or run **Actions → Release → Run workflow**. The release workflow attaches `senior-tester-skill.zip` for Claude.ai users.
