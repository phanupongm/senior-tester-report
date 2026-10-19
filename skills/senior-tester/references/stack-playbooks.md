# Stack playbooks

Read only the section for the detected stack. Each lists where to find routes and auth, and the mistakes that show up most often in real projects of that stack.

## Contents
- Node.js — Express / Fastify / NestJS
- Next.js / Nuxt / SvelteKit (full-stack JS)
- React / Vue / Angular SPA + separate API
- Python — Django
- Python — Flask / FastAPI
- PHP — Laravel
- PHP — plain / WordPress plugins
- Ruby on Rails
- Go
- Java / Kotlin — Spring Boot
- .NET — ASP.NET Core
- Firebase / Supabase backends

---

## Node.js — Express / Fastify / NestJS
- **Routes:** `app.get/post(...)`, `router.*`, `fastify.route`, NestJS `@Controller` + `@Get/@Post`.
- **Auth:** middleware order matters — a route registered *before* `app.use(auth)` is public. NestJS: look for `@UseGuards`, global guards in `main.ts`/`app.module.ts`, and `@Public()` decorators.
- **Common mistakes:** IDOR via `findById(req.params.id)` without owner filter; `req.body` spread into `Model.create` (mass assignment); string-built SQL with `mysql`/`pg`; `cors({ origin: true, credentials: true })`; missing `helmet`; JWT `verify` without `algorithms`; error handler leaking `err.stack`; no `express-rate-limit` on login.

## Next.js / Nuxt / SvelteKit
- **Routes:** Next App Router `app/**/page.tsx` and `app/**/route.ts`; Pages Router `pages/**` and `pages/api/**`; Server Actions (`"use server"`); `middleware.ts` matchers. Nuxt `server/api/**`. SvelteKit `+page.server.ts`, `+server.ts`.
- **Auth:** check that **every** API route / server action re-checks the session — `middleware.ts` matchers often miss API paths, and server actions are callable directly.
- **Common mistakes:** server actions without auth or input validation; secrets in `NEXT_PUBLIC_*` env vars; data fetched on the server and passed whole to client components (leaking fields); `dangerouslySetInnerHTML` with CMS/Markdown; `revalidate`/caching serving one user's data to another; image/URL proxy SSRF.

## React / Vue / Angular SPA + separate API
- **Routes:** client routes (`react-router`, `vue-router`, Angular routes) are UI only — **route guards are not security**. Test the API directly.
- **Common mistakes:** role checks only in the UI; tokens in `localStorage` combined with XSS sinks; API base URL and keys hard-coded in the bundle; `v-html` / `[innerHTML]` with user content; source maps shipped to production.

## Python — Django
- **Routes:** `urls.py` (`path`, `re_path`, `include`), DRF `router.register`, viewsets.
- **Auth:** `@login_required`, `LoginRequiredMixin`, DRF `permission_classes` and `DEFAULT_PERMISSION_CLASSES` in settings; check `get_queryset` filters by `request.user`.
- **Common mistakes:** `DEBUG = True` or `ALLOWED_HOSTS = ['*']` in prod settings; `SECRET_KEY` committed; `.raw()`/`.extra()`/`cursor.execute` with f-strings; `mark_safe`/`|safe`; DRF `AllowAny` defaults; serializers with `fields = '__all__'` exposing sensitive fields; `@csrf_exempt`.

## Python — Flask / FastAPI
- **Routes:** `@app.route`, `@bp.route`, FastAPI `@app.get/post`, `APIRouter`.
- **Auth:** Flask-Login `@login_required`; FastAPI `Depends(get_current_user)` — check each route actually depends on it.
- **Common mistakes:** `app.run(debug=True)`; `render_template_string` with user data (SSTI); `text()`/f-string SQL; Pydantic models without field restrictions (mass assignment); `allow_origins=["*"]` with credentials; secret key hard-coded.

## PHP — Laravel
- **Routes:** `routes/web.php`, `routes/api.php` (`Route::get`, `Route::resource`), controllers.
- **Auth:** `->middleware('auth')`, route groups, Policies/Gates (`$this->authorize`, `can:`), Form Requests `authorize()` returning `true`.
- **Common mistakes:** `{!! $var !!}`; `DB::raw`/`whereRaw` with input; `$fillable`/`$guarded = []` mass assignment; `APP_DEBUG=true` in prod; `.env` reachable from web root; route-model binding without ownership check; file uploads stored in `public/` with original names.

## PHP — plain / WordPress plugins
- **Routes:** individual `.php` files, `add_action('wp_ajax_*')`, `register_rest_route`.
- **Common mistakes:** `wp_ajax_nopriv_` handlers doing privileged work; missing `check_ajax_referer`/nonces; missing `current_user_can`; `$wpdb->query` without `prepare`; `echo $_GET[...]` without `esc_html`.

## Ruby on Rails
- **Routes:** `config/routes.rb`, controllers.
- **Auth:** `before_action :authenticate_user!`, Pundit/CanCanCan; check `skip_before_action`.
- **Common mistakes:** `Model.find(params[:id])` instead of `current_user.things.find`; `permit!`; `html_safe`/`raw`; string interpolation in `where`; secrets in `config/master.key` committed.

## Go
- **Routes:** `http.HandleFunc`, `mux.Handle`, Gin/Echo/Chi `r.GET` etc.
- **Common mistakes:** middleware applied to some route groups only; `fmt.Sprintf` SQL; `template.HTML(userInput)`; `InsecureSkipVerify: true`; missing request body size limits; ignoring errors.

## Java / Kotlin — Spring Boot
- **Routes:** `@RestController`, `@RequestMapping`, `@GetMapping`, etc.
- **Auth:** `SecurityFilterChain` matchers (`permitAll` too broad), `@PreAuthorize`.
- **Common mistakes:** actuator endpoints exposed; CSRF disabled with cookie auth; JPQL string concatenation; entities bound directly from requests; verbose error responses.

## .NET — ASP.NET Core
- **Routes:** controllers with `[Route]`/`[HttpGet]`, minimal APIs `app.MapGet`.
- **Auth:** `[Authorize]`, `[AllowAnonymous]`, policies; check global `RequireAuthorization`.
- **Common mistakes:** `[AllowAnonymous]` on sensitive actions; `FromSqlRaw` with interpolation; `Html.Raw`; developer exception page in production; overly permissive CORS policy.

## Firebase / Supabase backends
- **Routes:** client calls straight to the database — **the security rules / RLS policies ARE the backend.**
- **Auth:** Firestore/Storage `rules`, Supabase Row Level Security policies.
- **Common mistakes:** `allow read, write: if true` or `if request.auth != null` without ownership; RLS disabled on a table; `service_role` key in client code; Cloud Functions trusting client-sent `uid`. Test by querying another user's documents with your own test account.
