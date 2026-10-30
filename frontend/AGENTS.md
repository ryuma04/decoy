# AGENTS.md — Next.js SOC dashboard (for Antigravity)

You are building the analyst dashboard of the Deception SOC. Root rules: `../../../AGENTS.md`.
In Antigravity, add this file (and `../../docs/11-frontend-spec.md`) to the workspace rules / context.

## Read before coding

1. `../../docs/00-overview.md` — what the product is.
2. `../../docs/04-api-contract.md` §B — every endpoint, SSE message and the TypeScript types. **This is your only
   interface to the backend.** Copy the types verbatim into `src/lib/types.ts`.
3. `../../docs/11-frontend-spec.md` — pages, components, behaviour, build order.

## Rules

- Next.js 15 App Router + TypeScript strict + Tailwind + shadcn/ui + Recharts + `@xyflow/react`. Nothing else
  without asking.
- Browser calls only `/api/...`; `next.config.ts` rewrites to `${CORE_API_URL}/v1/...`. Never call decoys,
  Postgres or the ML service.
- Start with `NEXT_PUBLIC_USE_MOCKS=1`: build fixtures in `src/mocks/` from the examples in 04 (create realistic
  data: one critical actor ACT-0007 with 4 sessions across web/ssh/k8s/beacon, two low actors, 3 incidents).
- If the real API differs from 04, do not patch around it silently: report the mismatch so 04 is fixed first.
- Do not copy or recreate the dashboards of any repo in `references/`.
- Wording: correlation is "likely same operator", behaviour classes describe behaviour, never identity.
- Response actions show a confirm dialog: "Lab environment only".
- Accessible: severity always has a text label, not colour alone; keyboard-navigable tables and dialogs.

## Structure

```text
src/app/(auth)/login/page.tsx
src/app/(soc)/layout.tsx                 sidebar + topbar + StreamProvider
src/app/(soc)/page.tsx                   overview
src/app/(soc)/events/page.tsx
src/app/(soc)/actors/page.tsx
src/app/(soc)/actors/[id]/page.tsx
src/app/(soc)/incidents/page.tsx
src/app/(soc)/incidents/[id]/page.tsx
src/app/(soc)/maze/page.tsx
src/app/(soc)/honeytokens/page.tsx
src/app/(soc)/sensors/page.tsx
src/components/…                         SeverityPill, RiskGauge, BehaviourBadge, ServiceIcon, Timeline,
                                         SessionGraph, MazeGraph, AttackMatrix, EventDrawer, KpiCard
src/lib/types.ts  api.ts  stream.tsx  format.ts (IST time helpers)
src/mocks/*.json  stream.json
middleware.ts                            redirect to /login when no session cookie
```

## Done means

Every page in 11 renders with mocks and with the real backend; `npm run build`, `npm run lint`, type-check and the
Playwright smoke test pass; the actor profile reads clearly on a 1280×720 projector.
