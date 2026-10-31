# 11 — Frontend specification (Next.js SOC dashboard)

Owner: P2 (Antigravity). Only interface to the backend: `04-api-contract.md` (§B). Build against mocks first.

## Stack

Next.js 15 App Router, TypeScript strict, Tailwind CSS, shadcn/ui, lucide-react icons, Recharts (charts),
`@xyflow/react` (maze graph + session link graph), `date-fns` + `date-fns-tz` (show IST, store UTC),
native `EventSource` for SSE. No other state library: React state + a small SSE context. No direct DB access.

## Backend access

- `next.config.ts` rewrites `/api/:path*` → `${CORE_API_URL}/v1/:path*` (server env, default `http://core:8090`).
  Browser only ever calls `/api/...` (same origin, cookie flows automatically).
- `NEXT_PUBLIC_USE_MOCKS=1` → `src/lib/api.ts` returns fixtures from `src/mocks/*.json` and a fake SSE emitter
  that replays `src/mocks/stream.json` every 1.5 s. Default `0`.
- `src/lib/api.ts` exposes typed functions (`getOverview()`, `listActors(params)`, …) using types from
  `src/lib/types.ts` (copied verbatim from 04).

## Layout and theme

- Dark SOC theme by default, light theme toggle. Left sidebar: Overview, Live events, Actors, Incidents,
  Maze, Honeytokens, Sensors. Top bar: global search (IP / actor label / token), live indicator (SSE connected),
  ML on/off badge, user menu.
- Severity colours (use as Tailwind tokens): low = slate/blue, medium = amber, high = orange, critical = red.
  Always pair colour with text label (accessibility).
- Behaviour class badges: human-like, scripted, AI-assisted, agent-like, unknown (icons + text).
- Every timestamp shows relative ("2 min ago") with absolute IST on hover.

## Pages

### `/login`
Email + password → `POST /api/auth/login`. Redirect to `/`. Middleware redirects unauthenticated users here.

### `/` Overview
- KPI cards: events (1 h), active actors, open incidents by severity, honeytoken hits, sensors ok/total.
- Live event feed (last 50 from SSE, pause button, colour by service).
- Events per minute chart (`/stats/timeseries`, 60 points, refresh from SSE counts).
- Top ATT&CK techniques bar chart (`/stats/techniques`).
- "Highest-risk actor" card with risk gauge, linking to profile.
- Demo-friendly: when a new critical incident arrives via SSE, show a toast with a link.

### `/events` Live events
Table: time, service, type, actor, src IP, summary, tokens. Filters: service, type, actor, IP, free text, time range.
Cursor pagination. New SSE events prepend when filters match. Row click → drawer with raw envelope JSON (pretty).

### `/actors` Actors
Table: label, risk (bar), severity, confidence, behaviour badge, services (icons), sessions, IPs, top techniques,
last seen. Sort by risk / last seen. Live updates from `actor` SSE messages.

### `/actors/[id]` Actor profile (the most important page for the demo)
1. Header: label, severity pill, risk gauge 0–100, confidence ("likely same operator · 0.93"), behaviour badge,
   first/last seen, link to incident.
2. **Linked sessions graph** (React Flow): one node per session (service icon, IP, start time); edges labelled with
   link reasons (e.g. "same SSH key", "used token from session 2"). Below, the sessions table with link score.
3. **Attack timeline**: vertical, merged events + findings + maze unlocks, grouped by session colour; findings
   show technique chip; filter by kind.
4. **ATT&CK panel**: findings grouped by tactic (columns in kill-chain order), each with technique id, name,
   points, source (rule / ml / rule+ml) and evidence link to events.
5. **Behaviour panel**: class + score bars per class; 9 features with plain-English hints
   ("Never corrected a typo", "Used output of previous command 62% of the time").
6. **Maze panel**: actor's maze graph (`/actors/{id}/maze`) with node states hidden (dashed, greyed),
   visible (outlined), visited (filled accent); stretch nodes marked. Animate newly unlocked nodes from SSE `maze`.
7. **Fingerprints**: kind / value / sessions.
8. **Profile summary (four parts)** at the top, as four cards: **Source** (IPs, ports, firewall hits, real systems
   touched — red "Touched production" badge when true), **Tools** (tool tags with evidence tooltip), **Behaviour**
   (kill-chain progress bar recon → access → post-access → lateral, class badge, interests, speed), **Timeline** link.
9. **Risk breakdown**: stacked bar of `contributions` per stage + bias, the override reason if any, weights version.
   Text: "Risk 88 = recon +4 · access +18 · post-access +31 · lateral +35 (override: honeytoken used)".
10. Timeline items with `origin = "production"` get a distinct style and label ("Firewall", "Real SSH auth", "App login").

### `/incidents` and `/incidents/[id]`
- List: severity, title, actor, status, opened, updated. Filter by status/severity.
- Detail: summary (badge "AI summary" or "template"), status selector (open/ack/contained/closed), notes,
  findings table, IOCs table (copy button, export CSV), recommended actions with buttons
  (`block_ip`, `kill_session`, `rotate_token`) behind a confirm dialog stating "lab environment only";
  action history; "Download report (.md)".
- **Feedback**: two buttons "Confirmed attacker" / "False positive" (+ checkbox "allowlist this source").
  After the call, show old risk → new risk and the new weights version in a toast.

### `/maze`
Global maze definition graph (`/maze`), legend (entry / lure / service / stretch), and a selector to overlay one
actor's state.

### `/honeytokens`
Table: token id, kind, planted at, sensitivity, seen hits, used hits, last hit, burned. Row → list of hits with
actor links.

### `/scorer`
Current single-neuron weights per stage and bias (bar chart), version history (who/which feedback changed it),
counts of confirmed / false-positive labels, learning on/off badge, "Reset to v1" (admin, confirm dialog).

### `/sensors`
Cards: sensor id, service, version, last heartbeat, status (ok / silent). Silent sensors red.

## SSE handling

`src/lib/stream.tsx`: one `EventSource('/api/stream')` in a context provider; auto-reconnect with backoff;
exposes `useStream(eventName, handler)`. Show a "Live" dot (green connected, amber reconnecting).

## Quality bar

- Loading skeletons, empty states ("No attacks yet — the decoys are listening"), error states with retry.
- Works at 1280×720 (projector) and 1920×1080. Large fonts on KPI cards for the demo.
- No secrets in client code. All analyst writes go through `/api` with the cookie.
- Components small and typed; no `any`.

## Build order

1. Types + mocks + api layer + layout + login (mock).
2. Overview + live events with mocked SSE.
3. Actors list + actor profile (timeline, ATT&CK, sessions graph).
4. Incidents + actions + report download.
5. Maze graph, honeytokens, sensors.
6. Switch `NEXT_PUBLIC_USE_MOCKS=0` against the real backend at Gate 2; fix contract mismatches by updating
   **04 first**, then both sides.
