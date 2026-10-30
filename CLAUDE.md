# CLAUDE.md — Go backend (core + decoys)

You are building the Go backend of the Deception SOC with the backend lead. Root rules: `../../../AGENTS.md`.

## Read before coding

`docs/02-event-schema.md`, `03-database.md`, `04-api-contract.md` (contracts, frozen),
then `05-backend-implementation.md` (layout + build order), `06-decoys.md`, `07-intelligence-engine.md`,
`08-deception-maze.md`, `09-alerting-response.md`, `12-infrastructure.md`, `13-demo-and-testing.md`.

## How to work

1. Follow the build order in 05 step by step. Do not start a milestone before the previous gate passes.
2. Before a feature, check `docs/15-references-guide.md`, read the listed reference files to understand the
   approach, then write an independent design in Go. Never copy, port line by line, or import from `references/`.
3. Write the test with the feature. `go test ./...` and `go vet ./...` must pass before you finish a step.
4. When you make a design choice not in the docs, add one row to `docs/decisions.md`.
5. If a contract (02/03/04) must change, stop and ask the user first; then update the doc before the code.

## Non-negotiables

- Decoy packages (`internal/decoy/...`, `cmd/decoy-*`) must not import `os/exec`, `syscall` exec helpers,
  `net/http` clients to anything other than core, or write outside `/data` and `/tmp`.
  `scripts/check-no-exec.sh` enforces this; keep it passing.
- Every decoy limit in 08 is enforced inside the decoy too.
- Analyst JSON must match the TypeScript types in 04 exactly (snake_case, nullable fields present as `null`).
- Ingest returns fast; intel work happens off the request path.
- Correlation and rules are deterministic and unit-tested; ML is optional and time-boxed (300 ms).
- No real secrets anywhere; honeytokens only from `cmd/seed`.

## Commands

```bash
go run ./cmd/core migrate && go run ./cmd/core seed-admin && go run ./cmd/core serve
go run ./cmd/seed
go run ./cmd/decoy-ssh
go test ./... && go vet ./... && ./scripts/check-no-exec.sh
docker compose up --build core decoy-ssh postgres seed
```

## Done means

The gate in `13-demo-and-testing.md` for the current milestone passes from a clean `docker compose down -v`.
