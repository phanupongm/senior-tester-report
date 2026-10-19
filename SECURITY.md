# Security and responsible use

## Using this skill responsibly

`senior-tester` asks Claude to look for weaknesses in software. Use it only on systems **you own or have explicit written permission to test**. Testing systems without authorization may be illegal where you live.

The skill is designed to be safe:

- It asks before testing anything that looks like a third-party site.
- It prefers localhost or staging and limits production to read-only checks.
- Security probes are harmless (e.g. requesting a record your own test account shouldn't see, or entering a `<b>` tag to see whether it renders). It never uses payloads that modify or destroy data, never brute forces, and never load tests.
- Secrets it finds are reported masked (first 4 characters only) with a recommendation to rotate them.

It is a strong second opinion, not a replacement for a professional penetration test on systems that handle money, health records or other sensitive data.

## Reports may contain sensitive information

A report describes weaknesses in your system. Treat `qa-report.html`, `findings.json` and screenshots as confidential: don't commit them to public repositories (the skill suggests adding `qa-work/` to `.gitignore`) and share them only with people who need them.

## Reporting a vulnerability in this project

If you find a security problem in the scripts or the skill itself (for example, a way a crafted `findings.json` could inject script into the report), please open a [private security advisory](../../security/advisories/new) instead of a public issue.
