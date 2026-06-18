Priority 2 — OAuth + Action Engine: Changelog
Audit result (before writing anything)
Searched the codebase for `passport`, `oauth`, `google`, `github`, session/cookie middleware, and any existing automation/trigger logic. None existed — `/integrations/:service/connect` is a manual "paste your token" flow for GitHub/Notion read-only fetches, unrelated to login. So Part 1 and Part 2 were both implemented from scratch, per your instructions, with zero existing functionality touched beyond the explicit hooks listed below.
---
Files created
File	Purpose
`config/passport.js`	Google + GitHub Passport strategies. Account linking/dedup by email, GitHub verified-email lookup, OAuth-created users get a random unusable password hash (keeps the existing `password: required:true` invariant intact).
`routes/oauth.js`	`/auth/google`, `/auth/google/callback`, `/auth/github`, `/auth/github/callback`. Issues the same JWT shape `/login` already issues, redirects to `${FRONTEND_URL}/oauth-callback?token=...`. Each provider 503s cleanly if its env vars aren't set, instead of crashing.
`models/Workflow.js`	The workflow definition: one trigger (`event` or `schedule`) + up to 10 actions. `trigger` is its own sub-schema — a plain nested object here would hit a real, documented Mongoose bug (see "Bug avoided" below).
`models/WorkflowRun.js`	Execution history — one document per run, with per-action results.
`services/workflowEngine.js`	The Action Engine. `runAction()` executes one of 5 action types; `runWorkflow()` runs a workflow's full action list and writes history; `fireEvent()` is what existing routes call to trigger event-based workflows. Models (`Note`/`Task`/`Goal`/`User`/`sendEmail`) are injected via `registerModels()` rather than re-imported, so nothing is duplicated from server.js.
`services/scheduler.js`	Drives `schedule`-type triggers. A single cron tick every minute checks MongoDB for `nextRunAt <= now`, rather than one in-memory `node-cron` job per workflow — in-memory jobs vanish on every Render restart, the DB-persisted `nextRunAt` survives it.
`routes/workflows.js`	`GET/POST/PUT/DELETE /workflows`, `POST /workflows/:id/run`, `GET /workflows/:id/history`, `POST /workflows/ai-suggest`. Takes `auth`/`checkBlocked`/`apiLimiter`/`sanitize` as constructor arguments — reuses your existing middleware exactly, nothing reimplemented.
`CHANGELOG.md`	This file.
File modified: `server.js`
Imports — added `express-session`, `connect-mongo`, `passport`, and the new local modules.
`APP_URL` fallback — defaults to your Render URL if unset, so `config/passport.js`'s callback URL is never built from `undefined`.
Session + `passport.initialize()` — added right after `express.json()`. Used only so the OAuth2 strategies can store their CSRF `state` across the redirect to Google/GitHub and back. No other route reads/writes `req.session`; `passport.session()` is deliberately never called, so nothing about your existing stateless JWT auth changes.
User schema — added `googleId`, `githubId` (both `unique, sparse` — this is what actually prevents two users from linking the same Google/GitHub account), and `avatarUrl`.
OAuth mount — `configurePassport(User); app.use(createOAuthRouter());` right after the `User` model is defined.
6 one-line event hooks added (each wrapped in `.catch(()=>{})`, so a broken workflow can never break the original request):
`POST /notes` → fires `note_created`
`POST /goals` → fires `goal_created`
`PUT /goals/:id` (on `status:"completed"`) → fires `goal_completed`
`POST /tasks` → fires `task_created`
`PUT /tasks/:id` (on `status:"done"`) → fires `task_completed`
`POST /habits/:id/complete` (only when a completion is newly added, not removed) → fires `habit_completed`
Workflow Engine wiring — near the end of the file, after `Note`/`Task`/`Goal`/`User`/`sendEmail`/`auth`/`checkBlocked`/`apiLimiter`/`sanitize` are all already defined: `registerModels(...)`, mount `/workflows`, `startScheduler()`.
Nothing else in server.js was touched — no existing route signature, response shape, or behavior changed.
A Mongoose bug avoided
A naive `trigger: { type: {...}, event: {...}, cron: {...} }` (plain nested object) silently breaks in Mongoose: a path whose own descriptor has a `type` key set to another descriptor object (not a direct `String`/`Number`/etc.) gets misread as the type definition for the whole path, not as a nested object — this is called out in Mongoose's own docs as a known gotcha. Fixed by giving `trigger` its own explicit sub-schema.
---
New environment variables needed
You already listed `GITHUB_CLIENT_ID/SECRET`, `GOOGLE_CLIENT_ID/SECRET`, `JWT_SECRET`, `ENCRYPTION_KEY`, `APP_URL` — all used as-is. Two more, both optional with safe fallbacks so nothing breaks if you skip them for now:
`SESSION_SECRET` (falls back to `JWT_SECRET` if unset — fine for now, a dedicated value is better practice)
`FRONTEND_URL` (falls back to `https://sg-chatbot-a2h.pages.dev` — set this to wherever your frontend actually lives, since that's where users land after OAuth with their token)
New npm dependencies
```
npm install passport passport-google-oauth20 passport-github2 express-session connect-mongo node-cron
```
What I could NOT test here
This sandbox has no network access, so I couldn't `npm install` or boot the server against a real MongoDB. I verified every file with `node --check` (syntax-valid) and manually cross-checked every import/export between files and every symbol referenced in the server.js wiring. Please run it for real in your own environment before deploying — especially the full OAuth round-trip and a couple of workflow runs.
Quick usage examples
"When I create a goal, automatically create a note":
```json
POST /workflows
{ "name": "Goal note", "trigger": { "type": "event", "event": "goal_created" },
  "actions": [{ "type": "create_note", "params": { "title": "New goal logged" } }] }
```
"Every day remind me to study" (8am daily):
```json
POST /workflows
{ "name": "Study reminder", "trigger": { "type": "schedule", "cron": "0 8 * * *" },
  "actions": [{ "type": "create_task", "params": { "title": "Study time", "priority": "high" } }] }
```
Or just describe it in plain English via `POST /workflows/ai-suggest { "description": "..." }` and save whatever it returns.
