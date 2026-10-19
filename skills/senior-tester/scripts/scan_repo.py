#!/usr/bin/env python3
"""Fast, read-only reconnaissance of a code repository for the senior-tester skill.

Produces a map for a human/AI reviewer: detected stack, route inventory with
auth hints, risky code patterns, possible committed secrets (masked), env and
.gitignore hygiene, test setup and the dependency-audit command that fits.

Every hit is a LEAD, not a finding. Open the file and confirm before reporting.

Standard library only. Python 3.9+.

Usage:
  python3 scan_repo.py <repo-path> [--out qa-work/recon] [--max-hits 40]
"""
import argparse
import json
import os
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", "vendor", "dist", "build", ".next", ".nuxt", ".svelte-kit",
    ".output", "out", "coverage", "__pycache__", ".venv", "venv", "env", ".tox",
    "target", "bin", "obj", ".idea", ".vscode", ".turbo", ".cache", "storage",
    "public/build", "qa-work", ".terraform", "Pods", "DerivedData",
}
CODE_EXT = {
    ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro",
    ".py", ".php", ".rb", ".go", ".java", ".kt", ".cs", ".rs",
    ".html", ".htm", ".twig", ".blade.php", ".erb", ".ejs", ".hbs", ".jinja", ".j2",
}
CONFIG_EXT = {".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".xml", ".properties", ".rules"}
SECRET_SCAN_EXT = CODE_EXT | CONFIG_EXT | {".env", ".sh", ".txt", ".md", ".sql", ".tf", ".pem", ".key"}
MAX_FILE_BYTES = 1_000_000

# --------------------------------------------------------------------------- routes

ROUTE_PATTERNS = [
    # (stack label, extensions, regex, method group, path group)
    ("express-like", {".js", ".ts", ".mjs", ".cjs"},
     re.compile(r"\b(?:app|router|server|api|routes?|r|fastify)\.(get|post|put|patch|delete|all)\(\s*[`'\"]([^`'\"]+)"), 1, 2),
    ("nestjs", {".ts"}, re.compile(r"@(Get|Post|Put|Patch|Delete|All)\(\s*['\"]?([^'\")]*)"), 1, 2),
    ("flask/fastapi", {".py"},
     re.compile(r"@\w+\.(route|get|post|put|patch|delete|api_route)\(\s*['\"]([^'\"]+)"), 1, 2),
    ("django", {".py"}, re.compile(r"\b(re_path|path)\(\s*r?['\"]([^'\"]*)['\"]"), 1, 2),
    ("laravel", {".php"},
     re.compile(r"Route::(get|post|put|patch|delete|any|match|resource|apiResource)\(\s*['\"]([^'\"]+)"), 1, 2),
    ("wordpress-rest", {".php"}, re.compile(r"register_rest_route\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"]([^'\"]+)"), 1, 2),
    ("wordpress-ajax", {".php"}, re.compile(r"add_action\(\s*['\"](wp_ajax_(?:nopriv_)?)(\w+)"), 1, 2),
    ("rails", {".rb"}, re.compile(r"^\s*(get|post|put|patch|delete|resources?|root)\s+[:'\"]?([^'\",\s]+)"), 1, 2),
    ("go", {".go"}, re.compile(r"\.(GET|POST|PUT|PATCH|DELETE|HandleFunc|Handle|Get|Post|Put|Patch|Delete)\(\s*\"([^\"]+)\""), 1, 2),
    ("spring", {".java", ".kt"},
     re.compile(r"@(Get|Post|Put|Patch|Delete|Request)Mapping\(\s*(?:value\s*=\s*|path\s*=\s*)?\"([^\"]*)\""), 1, 2),
    ("aspnet", {".cs"}, re.compile(r"\[Http(Get|Post|Put|Patch|Delete)\(\s*\"([^\"]*)\"\s*\)\]"), 1, 2),
    ("aspnet-minimal", {".cs"}, re.compile(r"\.Map(Get|Post|Put|Patch|Delete)\(\s*\"([^\"]+)\""), 1, 2),
]

AUTH_HINTS = re.compile(
    r"login_required|LoginRequired|IsAuthenticated|permission_classes|authenticate|isAuthenticated|"
    r"requireAuth|require_auth|ensureAuth|withAuth|authMiddleware|auth\(\)|middleware\(\s*['\"]auth|"
    r"->middleware\(|UseGuards|AuthGuard|\[Authorize|RequireAuthorization|@PreAuthorize|before_action|"
    r"authenticate_user!|getServerSession|auth\(\)\.protect|currentUser|current_user|verifyToken|"
    r"jwt\.verify|passport\.authenticate|Depends\(\s*get_current|check_ajax_referer|current_user_can|"
    r"getUser\(|session\.user|req\.user|request\.user|isAuthorized|isAuthenticated|authorize\(|requireRole|"
    r"hasRole|checkRole|ensureLoggedIn|isAdmin|denyAll|@Secured|@RolesAllowed",
    re.I,
)
PUBLIC_HINTS = re.compile(r"AllowAnonymous|permitAll|AllowAny|@Public\(|wp_ajax_nopriv_|skip_before_action|csrf_exempt", re.I)

# --------------------------------------------------------------------------- risky patterns

RISKY = [
    ("xss-sink", "High", "Raw HTML sink — XSS if fed user data",
     re.compile(r"dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\(|document\.write\(|v-html=|\[innerHTML\]|\{!!.*!!\}|\|\s*safe\b|mark_safe\(|\.html_safe\b|\braw\(|Html\.Raw\(|template\.HTML\(")),
    ("sql-concat", "High", "SQL built from strings — check for injection",
     re.compile(r"(?i)(execute|query|raw|whereRaw|selectRaw|orderByRaw|FromSqlRaw|cursor\.execute|\.extra)\s*\(\s*(f['\"]|`[^`]*\$\{|['\"][^'\"]*(select|insert|update|delete)[^'\"]*['\"]\s*(\+|%|\.format|\.))")),
    ("code-exec", "High", "Dynamic code / shell execution",
     re.compile(r"\beval\(|new Function\(|child_process|\bexec\(|execSync\(|subprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True|os\.system\(|shell_exec\(|passthru\(|\bsystem\(|render_template_string\(|pickle\.loads\(|yaml\.load\((?![^)]*SafeLoader)|unserialize\(")),
    ("tls-off", "High", "TLS verification disabled",
     re.compile(r"rejectUnauthorized\s*:\s*false|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)")),
    ("debug-on", "Medium", "Debug mode enabled — make sure it's not production config",
     re.compile(r"(?i)^\s*DEBUG\s*=\s*True|APP_DEBUG\s*=\s*true|app\.run\([^)]*debug\s*=\s*True|UseDeveloperExceptionPage")),
    ("cors-wide", "Medium", "Permissive CORS",
     re.compile(r"(?i)origin\s*:\s*(true|['\"]\*['\"])|allow_origins\s*=\s*\[\s*['\"]\*|Access-Control-Allow-Origin['\"]?\s*[,:]\s*['\"]\*|AllowAnyOrigin\(|CORS_ALLOW_ALL_ORIGINS\s*=\s*True")),
    ("mass-assign", "Medium", "Possible mass assignment",
     re.compile(r"\$guarded\s*=\s*\[\s*\]|\.permit!|fields\s*=\s*['\"]__all__['\"]|\.create\(\s*req\.body\s*\)|\.update\(\s*req\.body\s*\)|\{\s*\.\.\.req\.body")),
    ("weak-hash", "Medium", "Weak hash — not OK for passwords",
     re.compile(r"(?i)\bmd5\(|createHash\(\s*['\"](md5|sha1)['\"]|hashlib\.(md5|sha1)\(|\bsha1\(")),
    ("jwt-risk", "Medium", "JWT decoded without verify, or algorithm not pinned",
     re.compile(r"jwt\.decode\(|algorithms\s*=\s*\[\s*['\"]none|verify_signature['\"]?\s*:\s*False|ignoreExpiration\s*:\s*true")),
    ("csrf-off", "Medium", "CSRF protection disabled",
     re.compile(r"csrf_exempt|csrf\(\)\.disable\(\)|\.csrf\(\s*AbstractHttpConfigurer::disable|VerifyCsrfToken|skip_forgery_protection|protect_from_forgery\s+with:\s*:null_session")),
    ("firebase-open", "Critical", "Database rules allow everyone",
     re.compile(r"allow\s+read\s*,\s*write\s*:\s*if\s+true|\"\.read\"\s*:\s*true|\"\.write\"\s*:\s*true")),
    ("service-key-client", "Critical", "Server-only key referenced in client code",
     re.compile(r"(?i)NEXT_PUBLIC_[A-Z_]*(SECRET|SERVICE_ROLE|PRIVATE)|VITE_[A-Z_]*(SECRET|SERVICE_ROLE|PRIVATE)|service_role")),
    ("open-redirect", "Low", "Redirect built from request data",
     re.compile(r"redirect\(\s*(req\.(query|body|params)|request\.(GET|args|query_params)|\$_GET|params\[)")),
    ("todo-security", "Info", "Security-related TODO/FIXME",
     re.compile(r"(?i)(TODO|FIXME|HACK|XXX).{0,40}(auth|secur|permission|validat|sanitiz|csrf|xss|sql|password|token)")),
]

# --------------------------------------------------------------------------- secrets

SECRET_PATTERNS = [
    ("aws-access-key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{50,}")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}")),
    ("stripe-live-key", re.compile(r"\b(sk|rk)_live_[0-9a-zA-Z]{20,}")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9\-_]{20,}")),
    ("openai-key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9]{32,}")),
    ("private-key", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("db-url-with-password", re.compile(r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^:\s/'\"]+:[^@\s'\"]{4,}@")),
    ("generic-assignment", re.compile(
        r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|client[_-]?secret|private[_-]?key)\b"
        r"\s*[:=]\s*['\"]([^'\"\s]{8,})['\"]")),
]
PLACEHOLDER = re.compile(
    r"(?i)example|sample|dummy|changeme|change_me|your[_-]|xxxx|\*\*\*|<.+>|\$\{|process\.env|os\.environ|getenv|env\(|"
    r"config\(|placeholder|test|fake|mock|redacted|lorem|password123|secret123|^\.\.\.$")


def mask(s):
    s = s.strip()
    return (s[:4] + "…") if len(s) > 4 else "…"


# --------------------------------------------------------------------------- helpers

def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and os.path.join(rel_dir, d).replace("\\", "/").lstrip("./") not in SKIP_DIRS]
        for f in filenames:
            p = Path(dirpath) / f
            try:
                if p.is_symlink() or p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p


def ext_of(p):
    name = p.name.lower()
    if name.endswith(".blade.php"):
        return ".blade.php"
    if name.startswith(".env"):
        return ".env"
    return p.suffix.lower()


def read_text(p):
    try:
        data = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:4096]:
        return None
    return data.decode("utf-8", errors="replace")


def load_json(p):
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def git(root, *args):
    try:
        r = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=20)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None


# --------------------------------------------------------------------------- stack detection

def detect_stack(root):
    stack, notes, audits, tests = [], [], [], []
    pkg = load_json(root / "package.json") if (root / "package.json").exists() else None
    if pkg:
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
        for dep, label in [("next", "Next.js"), ("nuxt", "Nuxt"), ("@sveltejs/kit", "SvelteKit"),
                           ("@nestjs/core", "NestJS"), ("express", "Express"), ("fastify", "Fastify"),
                           ("koa", "Koa"), ("hono", "Hono"), ("react", "React"), ("vue", "Vue"),
                           ("@angular/core", "Angular"), ("svelte", "Svelte"), ("astro", "Astro"),
                           ("firebase", "Firebase (client)"), ("firebase-admin", "Firebase Admin"),
                           ("@supabase/supabase-js", "Supabase"), ("prisma", "Prisma"), ("@prisma/client", "Prisma"),
                           ("mongoose", "Mongoose"), ("sequelize", "Sequelize"), ("typeorm", "TypeORM"),
                           ("drizzle-orm", "Drizzle"), ("next-auth", "NextAuth"), ("@clerk/nextjs", "Clerk"),
                           ("passport", "Passport"), ("jsonwebtoken", "jsonwebtoken"), ("helmet", "helmet"),
                           ("express-rate-limit", "express-rate-limit")]:
            if dep in deps and label not in stack:
                stack.append(label)
        if "helmet" not in deps and any(x in deps for x in ("express", "fastify", "koa")):
            notes.append("No `helmet` (or equivalent) dependency — check security headers")
        if not any(x in deps for x in ("express-rate-limit", "rate-limiter-flexible", "@fastify/rate-limit",
                                       "@nestjs/throttler", "@upstash/ratelimit")):
            notes.append("No rate-limiting library found — check login/OTP/reset endpoints")
        if (root / "pnpm-lock.yaml").exists():
            audits.append("pnpm audit --json")
        elif (root / "yarn.lock").exists():
            audits.append("yarn npm audit --json  (Yarn 2+) / yarn audit --json (Yarn 1)")
        else:
            audits.append("npm audit --json")
        scripts = pkg.get("scripts", {})
        for k in ("test", "test:unit", "test:e2e", "e2e"):
            if k in scripts:
                tests.append(f"npm run {k}  →  {scripts[k]}")
        for k in ("dev", "start", "serve", "preview"):
            if k in scripts:
                notes.append(f"Start command candidate: `npm run {k}` → {scripts[k]}")
                break

    py_files = [root / f for f in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py") if (root / f).exists()]
    if py_files:
        txt = " ".join((read_text(p) or "").lower() for p in py_files)
        for dep, label in [("django", "Django"), ("djangorestframework", "Django REST Framework"),
                           ("flask", "Flask"), ("fastapi", "FastAPI"), ("sqlalchemy", "SQLAlchemy"),
                           ("pydantic", "Pydantic")]:
            if re.search(rf"\b{re.escape(dep)}\b", txt) and label not in stack:
                stack.append(label)
        if not stack or not any(s in stack for s in ("Django", "Flask", "FastAPI")):
            stack.append("Python")
        audits.append("pip-audit  (pip install pip-audit)")
        if (root / "pytest.ini").exists() or "pytest" in txt or (root / "conftest.py").exists():
            tests.append("pytest")
        if (root / "manage.py").exists():
            tests.append("python manage.py test")

    comp = load_json(root / "composer.json") if (root / "composer.json").exists() else None
    if comp:
        req = {**comp.get("require", {}), **comp.get("require-dev", {})}
        stack.append("Laravel" if "laravel/framework" in req else "PHP")
        audits.append("composer audit --format=json")
        if (root / "phpunit.xml").exists() or (root / "phpunit.xml.dist").exists():
            tests.append("php artisan test / vendor/bin/phpunit")
    elif list(root.glob("*.php")) or (root / "wp-content").exists():
        stack.append("PHP")
    if list(root.glob("wp-config*.php")) or any(root.glob("*/plugin.php")):
        stack.append("WordPress")

    if (root / "Gemfile").exists():
        g = (read_text(root / "Gemfile") or "").lower()
        stack.append("Rails" if "rails" in g else "Ruby")
        audits.append("bundle audit check --update  (gem install bundler-audit)")
        tests.append("bin/rails test / bundle exec rspec")
    if (root / "go.mod").exists():
        g = (read_text(root / "go.mod") or "").lower()
        stack.append("Go" + (" (Gin)" if "gin-gonic" in g else " (Echo)" if "labstack/echo" in g else " (Chi)" if "go-chi" in g else ""))
        audits.append("govulncheck ./...  (go install golang.org/x/vuln/cmd/govulncheck@latest)")
        tests.append("go test ./...")
    if (root / "pom.xml").exists() or (root / "build.gradle").exists() or (root / "build.gradle.kts").exists():
        b = " ".join((read_text(p) or "") for p in [root / "pom.xml", root / "build.gradle", root / "build.gradle.kts"] if p.exists())
        stack.append("Spring Boot" if "spring-boot" in b else "JVM")
        audits.append("OWASP dependency-check / ./gradlew dependencyCheckAnalyze")
        tests.append("./mvnw test / ./gradlew test")
    if list(root.glob("*.csproj")) or list(root.glob("*.sln")) or list(root.glob("*/*.csproj")):
        stack.append("ASP.NET Core")
        audits.append("dotnet list package --vulnerable --include-transitive")
        tests.append("dotnet test")
    if (root / "Cargo.toml").exists():
        stack.append("Rust")
        audits.append("cargo audit")
        tests.append("cargo test")
    if (root / "firebase.json").exists() or list(root.glob("*.rules")):
        stack.append("Firebase rules")
    if (root / "supabase").is_dir():
        stack.append("Supabase project")
    if (root / "docker-compose.yml").exists() or (root / "compose.yaml").exists() or (root / "docker-compose.yaml").exists():
        notes.append("docker compose file present — may be the easiest way to start the app")
    return stack or ["Unknown"], notes, audits, tests


# --------------------------------------------------------------------------- file-based routes (Next/Nuxt/SvelteKit)

def file_routes(root, rel):
    r = rel.replace("\\", "/")
    m = re.match(r"(?:src/)?app/(.*)/route\.(ts|js|tsx|jsx)$", r) or re.match(r"(?:src/)?app/route\.(ts|js)$", r)
    if m:
        return "API", "/" + (m.group(1) if m.lastindex and m.lastindex > 1 else "")
    m = re.match(r"(?:src/)?pages/api/(.*)\.(ts|js)$", r)
    if m:
        return "API", "/api/" + re.sub(r"/?index$", "", m.group(1))
    m = re.match(r"(?:src/)?app/(.*)/page\.(tsx|jsx|ts|js|mdx)$", r)
    if m:
        return "PAGE", "/" + m.group(1)
    m = re.match(r"server/api/(.*)\.(ts|js)$", r)
    if m:
        return "API", "/api/" + re.sub(r"\.(get|post|put|patch|delete)$", "", m.group(1))
    m = re.match(r"src/routes/(.*)/\+server\.(ts|js)$", r)
    if m:
        return "API", "/" + m.group(1)
    m = re.match(r"src/routes/(.*)/\+page\.server\.(ts|js)$", r)
    if m:
        return "PAGE+SERVER", "/" + m.group(1)
    return None


def clean_route_path(p):
    # strip Next/Nuxt route groups like (marketing)
    return re.sub(r"/\([^)]+\)", "", p) or "/"


# --------------------------------------------------------------------------- main scan

def scan(root, max_hits):
    root = Path(root).resolve()
    stack, notes, audits, tests = detect_stack(root)
    routes, risky, secrets = [], defaultdict(list), []
    env_files, server_actions, test_files = [], [], 0
    file_count, line_count = 0, 0

    for p in iter_files(root):
        rel = str(p.relative_to(root)).replace("\\", "/")
        ext = ext_of(p)
        low = rel.lower()
        if p.name.startswith(".env") and not p.name.endswith((".example", ".sample", ".template", ".dist")):
            env_files.append(rel)
        is_test = bool(re.search(r"(^|/)(tests?|__tests__|spec|e2e|cypress|playwright|fixtures?|mocks?)(/|$)|\.(test|spec)\.[jt]sx?$|_test\.(go|py)$|(^|/)test_[^/]*\.py$", low))
        if is_test:
            test_files += 1
        if ext not in SECRET_SCAN_EXT and not p.name.startswith(".env"):
            continue
        text = read_text(p)
        if text is None:
            continue
        file_count += 1
        lines = text.splitlines()
        line_count += len(lines)
        is_code = ext in CODE_EXT

        fr = file_routes(root, rel) if is_code else None
        if fr:
            kind, path = fr
            routes.append({"stack": "file-based", "method": kind, "path": clean_route_path(path), "where": f"{rel}:1",
                           "auth": "in-file" if AUTH_HINTS.search(text) else ("public-marker" if PUBLIC_HINTS.search(text) else "none-seen")})
        if is_code and re.search(r"^\s*['\"]use server['\"]", text, re.M):
            server_actions.append(rel)
        file_has_auth = bool(AUTH_HINTS.search(text)) if is_code else False

        for i, line in enumerate(lines, 1):
            if len(line) > 2000:
                continue
            if is_code:
                for label, exts, rx, mg, pg in ROUTE_PATTERNS:
                    if ext not in exts:
                        continue
                    for m in rx.finditer(line):
                        window = "\n".join(lines[max(0, i - 4):i + 2])
                        if PUBLIC_HINTS.search(window):
                            auth = "public-marker"
                        elif AUTH_HINTS.search(window):
                            auth = "near-route"
                        elif file_has_auth:
                            auth = "in-file"
                        else:
                            auth = "none-seen"
                        routes.append({"stack": label, "method": m.group(mg).upper(), "path": m.group(pg),
                                       "where": f"{rel}:{i}", "auth": auth})
                for rid, sev, desc, rx in RISKY:
                    if rx.search(line) and len(risky[rid]) < max_hits:
                        risky[rid].append({"where": f"{rel}:{i}", "code": line.strip()[:160]})
            elif ext in CONFIG_EXT:
                for rid, sev, desc, rx in RISKY:
                    if rid in ("firebase-open", "cors-wide", "debug-on", "service-key-client") and rx.search(line) and len(risky[rid]) < max_hits:
                        risky[rid].append({"where": f"{rel}:{i}", "code": line.strip()[:160]})
            for sid, rx in SECRET_PATTERNS:
                for m in rx.finditer(line):
                    val = m.group(m.lastindex) if sid == "generic-assignment" else m.group(0)
                    if sid == "generic-assignment" and (PLACEHOLDER.search(val) or is_test or ext == ".md"):
                        continue
                    if sid == "jwt" and (is_test or ext == ".md"):
                        continue
                    if PLACEHOLDER.search(line) and sid in ("jwt", "db-url-with-password"):
                        continue
                    if len(secrets) < max_hits * 2:
                        secrets.append({"type": sid, "where": f"{rel}:{i}", "value": mask(val),
                                        "in_env_file": p.name.startswith(".env"), "in_test_file": is_test})

    # git / env hygiene
    gi = read_text(root / ".gitignore") or ""
    env_ignored = bool(re.search(r"^\s*/?\.env(\*|\.\*|\.local)?\s*$|^\s*\*\.env\s*$|^\s*\.env\*", gi, re.M))
    tracked_env, env_history = [], []
    if (root / ".git").exists():
        out = git(root, "ls-files")
        if out:
            tracked_env = [f for f in out.splitlines()
                           if re.search(r"(^|/)\.env(\.|$)", f) and not re.search(r"\.(example|sample|template|dist)$", f)]
        hist = git(root, "log", "--all", "--diff-filter=A", "--name-only", "--pretty=format:", "--", ".env", "*.pem", "*.key", "**/.env")
        if hist:
            env_history = sorted({h for h in hist.splitlines() if h.strip()})

    hygiene = {
        "env_files_present": env_files,
        "env_in_gitignore": env_ignored,
        "env_files_tracked_by_git": tracked_env,
        "secret_files_ever_committed": env_history,
    }
    if env_files and not env_ignored:
        notes.append("`.env` file(s) exist but `.gitignore` doesn't appear to ignore them")
    if tracked_env:
        notes.append("`.env` file(s) are TRACKED by git — treat any secrets inside as leaked")
    if env_history:
        notes.append("Secret-like files appear in git history — rotate anything they contained")
    if server_actions:
        notes.append(f"{len(server_actions)} file(s) with Next.js server actions — each action must check auth itself")

    # strongest secret types first
    weak = {"generic-assignment": 2, "jwt": 1}
    secrets.sort(key=lambda x: (x["in_test_file"], weak.get(x["type"], 0), x["where"]))

    # de-dup routes
    seen, uniq = set(), []
    for r in routes:
        k = (r["method"], r["path"], r["where"])
        if k not in seen:
            seen.add(k)
            uniq.append(r)

    return {
        "root": str(root),
        "stack": stack,
        "files_scanned": file_count,
        "lines_scanned": line_count,
        "test_files": test_files,
        "test_commands": tests,
        "audit_commands": audits,
        "notes": notes,
        "routes": uniq,
        "server_action_files": server_actions,
        "risky": {rid: {"severity_hint": sev, "description": desc, "hits": risky[rid]}
                  for rid, sev, desc, _ in RISKY if risky.get(rid)},
        "secrets": secrets,
        "hygiene": hygiene,
    }


# --------------------------------------------------------------------------- markdown

def to_markdown(r):
    o = []
    o.append("# Recon report\n")
    o.append("> Every item below is a **lead**, not a finding. Open the file and confirm before reporting.\n")
    o.append(f"- **Root:** `{r['root']}`")
    o.append(f"- **Stack:** {', '.join(r['stack'])}")
    o.append(f"- **Scanned:** {r['files_scanned']} files, {r['lines_scanned']:,} lines")
    o.append(f"- **Test files:** {r['test_files']}" + ("" if r['test_files'] else "  ⚠️ no tests found"))
    if r["test_commands"]:
        o.append("- **Test commands:** " + "; ".join(f"`{t}`" for t in r["test_commands"]))
    if r["audit_commands"]:
        o.append("- **Dependency audit:** " + "; ".join(f"`{a}`" for a in r["audit_commands"]))
    if r["notes"]:
        o.append("\n## Notes\n")
        o += [f"- {n}" for n in r["notes"]]

    o.append(f"\n## Route inventory ({len(r['routes'])})\n")
    if r["routes"]:
        o.append("Auth column: `near-route` = auth hint within a few lines · `in-file` = auth hint elsewhere in the file · "
                 "`public-marker` = explicitly public · `none-seen` = **verify first**.\n")
        o.append("| Method | Path | Where | Auth hint |\n|---|---|---|---|")
        order = {"none-seen": 0, "public-marker": 1, "in-file": 2, "near-route": 3}
        for x in sorted(r["routes"], key=lambda x: (order.get(x["auth"], 9), x["path"])):
            flag = " ⚠️" if x["auth"] == "none-seen" else ""
            o.append(f"| {x['method']} | `{x['path']}` | `{x['where']}` | {x['auth']}{flag} |")
    else:
        o.append("_No routes recognized automatically. Find the router manually (see stack-playbooks.md)._")

    o.append("\n## Risky code patterns\n")
    if r["risky"]:
        for rid, v in r["risky"].items():
            o.append(f"### {rid} — {v['description']} (hint: {v['severity_hint']}, {len(v['hits'])} hit(s))\n")
            for h in v["hits"]:
                code = h["code"].replace("|", "\\|").replace("`", "'")
                o.append(f"- `{h['where']}` — `{code}`")
            o.append("")
    else:
        o.append("_None matched._")

    o.append("\n## Possible secrets (masked)\n")
    if r["secrets"]:
        o.append("| Type | Where | Value | In .env file | In test/fixture |\n|---|---|---|---|---|")
        for s in r["secrets"]:
            o.append(f"| {s['type']} | `{s['where']}` | `{s['value']}` | {'yes' if s['in_env_file'] else 'no'} | "
                     f"{'yes' if s.get('in_test_file') else 'no'} |")
    else:
        o.append("_None matched._")

    h = r["hygiene"]
    o.append("\n## Env & git hygiene\n")
    o.append(f"- `.env` files present: {', '.join('`'+e+'`' for e in h['env_files_present']) or 'none'}")
    o.append(f"- `.env` ignored by `.gitignore`: {'yes' if h['env_in_gitignore'] else 'no / not found'}")
    o.append(f"- `.env` tracked by git: {', '.join('`'+e+'`' for e in h['env_files_tracked_by_git']) or 'none'}")
    o.append(f"- Secret-like files in git history: {', '.join('`'+e+'`' for e in h['secret_files_ever_committed']) or 'none'}")
    return "\n".join(o) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("repo", help="path to the repository")
    ap.add_argument("--out", default="qa-work/recon", help="output folder (default: qa-work/recon)")
    ap.add_argument("--max-hits", type=int, default=40, help="max hits per pattern (default 40)")
    a = ap.parse_args()
    if not Path(a.repo).is_dir():
        sys.exit(f"not a directory: {a.repo}")
    result = scan(a.repo, a.max_hits)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "recon.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    (out / "recon.md").write_text(to_markdown(result), encoding="utf-8")
    unauth = sum(1 for r in result["routes"] if r["auth"] == "none-seen")
    print(f"stack: {', '.join(result['stack'])}")
    print(f"routes: {len(result['routes'])} ({unauth} with no auth hint) · risky patterns: "
          f"{sum(len(v['hits']) for v in result['risky'].values())} · possible secrets: {len(result['secrets'])}")
    print(f"wrote {out / 'recon.md'} and {out / 'recon.json'}")


if __name__ == "__main__":
    main()
