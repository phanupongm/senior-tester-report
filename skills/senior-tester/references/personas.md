# Personas

Pick the personas that fit the system. **Always** include First-timer, Mobile user and Intruder. Before starting, give each persona 1–3 goals taken from the route inventory and the journeys the user named.

**Stay in character.** A persona only knows what the UI shows. Don't use code knowledge to help them succeed. If a real person would get stuck, record that you got stuck.

## Core personas

| Persona | Mindset | Typically reveals |
|---|---|---|
| **First-timer** | Never seen the app. Skims, clicks the most obvious thing, doesn't read help text | Onboarding gaps, unclear labels, missing empty states, no recovery after errors |
| **Mobile user** | ~390 px wide, thumb only, flaky connection, on-screen keyboard covers half the screen | Overflow, tiny tap targets, buttons hidden behind fixed bars or the keyboard, double-submit on slow network |
| **Intruder** | Logged in as a normal user, curious and slightly malicious. Changes IDs in URLs, replays requests, edits hidden fields | IDOR, client-side-only checks, hidden admin routes, editable prices/scores/roles |
| **Anonymous visitor** | Not logged in, opens deep links directly, hits API endpoints | Pages/APIs reachable without auth, data leaks on public pages, broken redirects after login |

## Optional personas

| Persona | Mindset | Typically reveals |
|---|---|---|
| **Power user** | Fast, keyboard, back button, multiple tabs, bookmarks | State lost on back/refresh, race conditions across tabs, missing shortcuts or bulk actions |
| **Careless typer** | Typos, pasted whitespace, mixed scripts, wrong formats | Weak validation, unhelpful errors, garbage saved to the database |
| **Low-vision / older user** | 200% zoom, keyboard or screen reader, slow reader, unsure of icons | Contrast, focus order, icon-only buttons, missing labels, timeouts too short |
| **Admin / staff** | Manages other people's data, bulk operations, exports | No confirmation on destructive actions, no undo, no audit trail, export encoding bugs |
| **Returning user** | Comes back after a week, session expired, data changed since | Expired-session handling, stale caches, confusing "what changed" |
| **International user** | Different locale, timezone, currency, RTL or non-Latin names | Date/time zone bugs, number/currency formatting, name length limits, encoding |

Add domain roles the app defines (Teacher/Student, Buyer/Seller, Doctor/Patient…) as personas with their real permissions.

## Edge input kit

Try a few of these in every form that matters. Pick what fits the field.

- Empty, only spaces, leading/trailing spaces
- Very long (1,000+ chars), very long single word (layout breaking)
- Non-Latin scripts and combining characters (Thai, Arabic, Chinese, emoji, `é` vs `é`)
- Numbers: `0`, `-1`, `1e9`, `0.1+0.2`-style decimals, `1,000.50` vs `1.000,50`, leading zeros
- Dates: Feb 29, Dec 31 → Jan 1, timezone edges, far past/future
- Duplicate actions: double-click submit, refresh after submit, browser back after submit
- Markup probe: `<b>xss-probe</b>` and `"><i>probe</i>` — must render as literal text (harmless; don't use script payloads)
- File upload (if present): wrong extension, 0 bytes, larger than limit, double extension `photo.png.html`

## Journal format (`qa-work/journal-<persona>.md`)

```
## Goal: <task>
- Tried: ...
- Expected: ...
- Got: ...
- Attempts: N   Result: success | struggled | stuck | failed
- Finding: <id or none>
```

## Friction signals (record each one)

- Needed more than 3 attempts, or had to guess
- No visible feedback after an action ("did it save?")
- Error message is technical, in the wrong language, or blames the user
- Input lost after an error or refresh
- Horizontal scrolling on mobile
- Dead end: no way forward or back except the browser's back button
- Had to read documentation to complete a basic task
