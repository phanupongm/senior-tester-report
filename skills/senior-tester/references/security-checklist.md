# Security checklist (non-destructive)

Go through every section against the code AND, where it applies, the live app. Record each item in `checks` as `pass` / `fail` / `na` / `unchecked`. Only `fail` items become findings; link them with `ref`.

Map findings to OWASP Top 10 (2021) in the finding's `owasp` field (`A01`…`A10`), or `SECRETS` / `PRIVACY` for the extra sections.

All probes here are harmless by design. Don't escalate beyond them.

## A01 — Broken access control *(check first; most common serious bug)*
- [ ] Every non-public route checks authentication **on the server**
- [ ] Every route that touches a record checks **ownership or role** — test with two test accounts: user A requests user B's record ID
- [ ] Admin pages and APIs return 401/403 to anonymous and normal users (call the API directly, not just the hidden menu)
- [ ] Server ignores client-supplied `role`, `userId`, `price`, `score`, `isAdmin`, etc. (mass assignment)
- [ ] File downloads and signed URLs check ownership and expire
- [ ] Multi-tenant apps: every query is scoped by tenant/org

## A02 — Cryptographic failures
- [ ] Passwords hashed with bcrypt / argon2 / scrypt (not MD5/SHA-1/plain)
- [ ] HTTPS enforced in production; HSTS set
- [ ] API responses don't include fields they don't need (password hashes, tokens, internal IDs, other users' emails)
- [ ] Sensitive data at rest (IDs, health, payment) encrypted or not stored

## A03 — Injection
- [ ] SQL/NoSQL built with parameters or an ORM; no string concatenation with request data
- [ ] Output encoding: look for `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `dangerouslySetInnerHTML`, `v-html`, `{!! !!}`, `|safe`, `mark_safe`, `html_safe`, `raw`
- [ ] Live probe: `<b>xss-probe</b>` in text fields renders as literal text everywhere it's displayed (including admin views)
- [ ] No `eval`, `new Function`, shell execution, or template rendering with request data
- [ ] Rich-text/Markdown input is sanitized with an allow-list

## A04 — Insecure design
- [ ] Rate limiting on login, OTP, password reset, sign-up, and expensive endpoints
- [ ] Idempotency / double-submit protection on payments, orders, submissions, votes
- [ ] Business rules enforced on the server (deadlines, quotas, step order, time windows)
- [ ] Destructive actions require confirmation and are reversible or logged

## A05 — Security misconfiguration
- [ ] Debug mode and stack traces off in production config
- [ ] Headers: `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Strict-Transport-Security`, frame protection (`frame-ancestors` or `X-Frame-Options`)
- [ ] CORS is not `*` together with credentials; allowed origins are explicit
- [ ] No default credentials or seed admin accounts in production
- [ ] Not served publicly: `/.git/`, `/.env`, backups (`*.bak`, `*.sql`, `*.zip`), source maps in production (low), directory listings
- [ ] Error pages don't reveal framework versions or file paths

## A06 — Vulnerable and outdated components
- [ ] Dependency audit run (`npm audit`, `pnpm audit`, `yarn npm audit`, `pip-audit`, `composer audit`, `bundle audit`, `govulncheck`, `cargo audit`)
- [ ] Report High/Critical advisories that affect shipped code, with package, installed version and fixed version
- [ ] Runtime/framework version still supported

## A07 — Identification and authentication failures
- [ ] Session cookies: `HttpOnly`, `Secure`, `SameSite=Lax` or stricter; sensible expiry
- [ ] Logout invalidates the session server-side
- [ ] JWT: signature verified, algorithm pinned, secret strong and not committed, `exp` set, not stored where XSS can read it if avoidable
- [ ] Password reset / magic-link tokens: single-use, expire, not logged
- [ ] Password policy reasonable; breached-password check is a plus
- [ ] Login errors don't reveal whether an account exists (Low)
- [ ] MFA available for admin roles (idea if missing)

## A08 — Software and data integrity failures
- [ ] CSRF protection on state-changing requests when auth uses cookies
- [ ] File uploads: type checked on the server by content, size limited, stored outside the web root or with random names, never executed, served with `Content-Disposition: attachment` when user-supplied
- [ ] Third-party scripts loaded from trusted sources; SRI on CDN scripts is a plus
- [ ] Webhooks verify signatures

## A09 — Security logging and monitoring failures
- [ ] Server errors are logged somewhere someone will see
- [ ] Logs don't contain passwords, tokens, full card numbers, or unnecessary personal data
- [ ] Admin and security-relevant actions leave an audit trail

## A10 — Server-side request forgery
- [ ] Any feature that fetches a user-supplied URL (import from URL, webhooks, image proxy, link preview) restricts destinations and blocks internal addresses

## SECRETS — Secrets in the repository
- [ ] Review the scanner's secret hits; confirm each by opening the file
- [ ] `.env` and similar are in `.gitignore`
- [ ] Check history: `git log --all --oneline -- .env '*.pem' '*.key'` — a secret ever committed must be rotated even if deleted later
- [ ] Report confirmed real secrets as Critical; show only the first 4 characters + `…`; recommend rotation first, then removal from history

## PRIVACY — Personal data
- [ ] Only necessary personal data is collected; a privacy notice exists if personal data is collected
- [ ] Users can't see other users' personal data unless the feature requires it
- [ ] Personal data is deletable/exportable on request where the law applies (GDPR, PDPA, CCPA, etc.) — flag as an idea, not a defect, unless the user says compliance is required
