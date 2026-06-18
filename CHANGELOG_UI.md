Chat UI Upgrade — Changelog
Files
`chat.html` — modified (all 6 items below)
`server.js` — already modified earlier in this session for item 4 (violation/suspension system) and the "Productivity Coach" role used by item 3. Re-attached here so you have the complete, current pair of files together.
---
1. Attachment (+) menu — scrollable
File: `chat.html`, `.plus-menu` CSS only.
Added `max-height: min(360px, 60vh)`, `overflow-y:auto`, `scroll-behavior:smooth`, a thin themed scrollbar, and `max-width: calc(100vw - 24px)`. If you add more items later, the menu scrolls internally instead of growing past the screen edge or off the bottom on short mobile viewports. No HTML or JS changed — purely a style fix, zero risk to existing attach/voice/template/image-gen buttons.
2. Model Selector (Claude Sonnet 4.6 / GPT-4o Mini / Claude Opus 4.7 — Coming Soon)
File: `chat.html` — new HTML block + new CSS (`.ai-model-*`) + new JS block, all under fresh class/ID names so nothing collides with the existing Fast/Smart/Coding/Deep selector in the topbar.
Placed directly to the left of the Send button as requested (`.ai-model-wrap` sits between `#input` and `#sendBtn`). It's a compact icon button that opens a dropdown listing the three models, each with a "Coming Soon" badge and `opacity:.55` (visually disabled). Clicking one just shows a toast — it never touches `S.model`, `modelKey`, or any existing request payload, so your active fast/smart/coding/deep routing is completely unaffected.
3. Role Focus System UI
Files: `chat.html` (new selector) + `server.js` (one new dictionary entry, done earlier).
Added a Role dropdown in the desktop topbar (next to Persona) and matching pills in the mobile bar: General Assistant, Coder, Teacher, Researcher, Productivity Coach. Two things were actually broken before this:
There was no UI to set a role at all — `S.settings?.role` was always `undefined`.
Even the existing payload code was reading from the wrong place: the backend's `/settings` response returns `role` as a top-level field, not nested under `settings`. Fixed all 3 call sites (`doChat`, the voice-conversation handler) to read `S.role` instead.
Backend mapping — your existing `ROLE_PROMPTS` dictionary already had "Software Engineer", "Teacher", "Researcher", so the frontend's "Coder" option sends the value `"Software Engineer"` to reuse that entry exactly (no backend change needed for those three). "Productivity Coach" didn't exist, so one new entry was added to `ROLE_PROMPTS` in `server.js`. "General Assistant" sends an empty `roleKey`, which is the existing no-override default.
Selecting a role also fire-and-forgets a `POST /settings {role}` so it persists as your account default next time you sign in (silently ignored if it fails — the in-session role still works regardless).
4. Safety / Account Restriction System
Backend (`server.js`, done earlier this session):
New `User` fields: `violationCount`, `suspendedUntil`, `suspensionReason` (alongside the existing `isBlocked`/`blockedReason`).
New admin endpoint `POST /admin/users/:id/violation {reason}` — graduated, clearly-thresholded, always admin-triggered, never automatic: 1st violation = warning only, 2nd = 24h suspension, 3rd = 7-day suspension, 4th+ = permanent block (reuses your existing `isBlocked`).
New `POST /admin/users/:id/clear-violations` — fully reversible reset, so any mistake is recoverable.
`checkBlocked` middleware now also checks `suspendedUntil`, returning 403 with the reason + expiry, and silently clears it once it's actually expired.
`/status` now also returns `isBlocked`, `blockedReason`, `suspendedUntil`, `suspensionReason`.
Frontend (`chat.html`, new this turn):
New "Account Suspended / Blocked" overlay (reuses the existing `.limit-card` layout with a red accent instead of building a new modal style from scratch).
`fetchStatus()` now checks the `/status` response and shows the overlay proactively on page load if you're currently restricted.
Both `/chat` and `/chat/stream` response handling now check for `403` explicitly and show this overlay with the real reason/expiry — previously a 403 would have either been swallowed by the generic "Connection error" message or, in the non-streaming path, displayed as if the AI itself had said it.
5. Thinking Level Selector (Default / Powerful)
File: `chat.html` — new 2-option toggle in the topbar + mobile bar, new `S.thinkingLevel` state.
Previously, "powerful" mode only ever happened as a side effect of picking the "Deep Thinking" model tier (`isPowerful = S.model==='deep'`) — there was no independent control. Now `S.thinkingLevel` is its own explicit toggle, sent as-is in all 3 chat-request call sites. Backward compatibility is preserved: picking "Deep Thinking" from the model dropdown still auto-flips this toggle to Powerful, but you can now also turn Powerful on for the Fast/Smart/Coding tiers independently, or turn it back off without leaving Deep Thinking. Streaming behavior in `/chat/stream` is untouched — only the value sent in the `thinkingLevel` form field changed.
6. General
Every new interactive piece reuses the app's existing visual language (pill buttons, dropdown-with-popUp-animation, `var(--accent)`/`var(--surface-*)` tokens) — no new design system introduced.
All new JS is grouped into clearly labeled blocks (`// ══ ROLE ══`, `// ══ THINKING LEVEL ══`, `// ══ AI MODEL ══`) immediately following the existing `MODEL`/`PERSONA` blocks they parallel.
Mobile: every new desktop control has a `.mobile-bar` equivalent, hidden/shown via the same `@media (max-width:768px)` pattern already used for Persona.
Verified: extracted and ran `node --check` on the full inline `<script>` block (passes), confirmed balanced HTML tags and CSS braces, confirmed no duplicate element IDs introduced, and confirmed the existing `.plus-menu`/model-tier/persona logic is untouched aside from the explicitly listed fixes above.
Not testable here: actual rendering/click-through in a real browser (this sandbox has no browser or network) — please click through the new dropdown/toggle behavior once after deploying, especially the mobile bar on a real small screen.
