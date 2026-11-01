# 21 — Deception SOC Bait & Divert Audit

**Audit Date**: 2026-11-01  
**Target Environment**: Linux Host (`aeteesbakehouse.com` / `aeteesadmin.aeteesbakehouse.com`)  
**Scope**: Deception SOC Project (`~/Downloads/decoy`) & Divert Proxy Integration

---

## Executive Summary

This audit assesses the state of the Deception SOC project and its divert proxy prior to placing it in front of the live Aetees Bakehouse shop. The real shop is currently active on port `3000` via systemd (`aetee-web.service`) with live customer orders routed through Cloudflare Tunnel.

The Decoy system has working core detection, threat correlation, ML input-risk scanning, and decoy daemons (SSH, Web, K8s, Beacon, Postgres). However, the **Divert Proxy daemon (`cmd/divert-proxy`)**, **False-Positive Recovery (`recovery.go`)**, **Canary Lures & Deception Tactics (`lures.go`, `tactics.go`)**, and **divert test scripts** are either missing or in draft status with compiler mismatches. 

Below is the detailed feature-by-feature audit table.

---

## Audit Matrix

| Feature | Status | Evidence | Fix Needed |
| :--- | :--- | :--- | :--- |
| **Go Toolchain & Module** | **Broken** | `backend/go/go.mod` specifies `go 1.27.1`. The host has `go version go1.26.8 linux/amd64`. Running `go test` or `go vet` aborts immediately with toolchain requirement error. | Change `go 1.27.1` to `go 1.26` in `backend/go/go.mod`. |
| **Decoy Security Constraint (`check-no-exec.sh`)** | **Compliant** | `backend/go/scripts/check-no-exec.sh` passes with exit code 0 across all decoy and divert packages. No forbidden `os/exec` or raw syscalls present. | None. Must remain green across all subsequent tasks. |
| **Tripwire Classifier (`internal/divert/tripwire.go`)** | **Partially Implemented / Test Broken** | `tripwire.go` logic exists (routes allowlist, sensitive paths, bad UAs, injection pre-checks). However, `tripwire_test.go` has compile errors (`SevNone`, `SevSoft`, `SevHard` used instead of `None`, `Soft`, `Hard`; `NewTripwire()` called without arguments; unused variables). | Align `tripwire_test.go` symbols with `types.go` definitions and ensure all normal shop routes pass as `None`. |
| **Divert Proxy Daemon (`cmd/divert-proxy` & `proxy.go`)** | **Missing** | `cmd/divert-proxy/main.go` and `internal/divert/proxy.go` do not exist. No reverse proxy listening on `:8200` to transparently route between real shop (`:3000`) and clone (`:3101`). | Implement `cmd/divert-proxy` with `httputil.ReverseProxy`, `_aet_v` tracking cookie for all visitors, no HTTP redirects, and `sensorkit` telemetry for diverted visitors (Task A). |
| **False-Positive Recovery (`internal/divert/recovery.go`)** | **Missing** | `internal/divert/recovery.go` does not exist. No auto-release mechanism for soft trips (12 clean requests / 120s), no checkout/contact write-holding (503), no verified admin login check. | Implement `recovery.go` covering auto-release, 503 write-holds for checkout/contact, and verified admin pass-through (Task C). |
| **Canary Lures & Cognitive Tactics (`lures.go`, `tactics.go`)** | **Missing** | Neither `lures.go` nor `tactics.go` exists. Fake `/.env.bak`, `/backup/` SQL dumps, false login success, and tarpitting are not implemented. Maze YAML does not link Aetees lures. | Implement `lures.go` and `tactics.go`, link `lure_aetees_env` and `lure_aetees_orders` in `backend/go/maze/maze.yaml` (Task D). |
| **Verification Script (`scripts/divert-check.sh`)** | **Missing** | `scripts/divert-check.sh` is absent from the repository. No automated script to verify transparent proxying, cookie generation, and tripwire diversion. | Implement `scripts/divert-check.sh` to validate proxy behavior locally and over test networks (Task F). |
| **Port Conflict: SOC Dashboard vs Real Shop** | **Collision Risk** | The real shop `aetee-web.service` is actively listening on `:3000`. `scripts/dev-up.sh` attempts to bind the Next.js SOC dashboard to `:3000`, causing port conflict. | Change dashboard port in `scripts/dev-up.sh` to `:3002` (or `:3300`) to guarantee zero interference with the live bakery shop. |
| **Cloudflare Tunnel Routing (`config.yml`)** | **Direct to Prod (Not Diverted)** | `~/.cloudflared/config.yml` routes `aeteesbakehouse.com`, `www.aeteesbakehouse.com`, and `aeteesadmin.aeteesbakehouse.com` directly to `http://localhost:3000`. | Update tunnel ingress config (Task E) to point main domains to proxy `:8200` and `aeteesadmin` to honeypot, strictly after checkpoint approval. |
| **Aetees Lab Simulation (`scripts/aetees-lab.sh`)** | **Ready to Run** | `scripts/aetees-lab.sh` exists and reference source is confirmed at `../references/aetee`. Needs seed output from `dev-up.sh` (`tokens.json`). | Run lab setup once Decoy `.env` and seed are initialized. |
| **Environment Configuration (`.env`)** | **Missing** | `.env` does not exist in `~/Downloads/decoy`. `.env.example` is present with placeholder sensor keys. | Populate `~/Downloads/decoy/.env` with database connection string, JWT secret, and sensor keys. |

---

## Phase 2 Implementation Roadmap (Tasks A to G)

- **Task A (Proxy Core)**: Implement `cmd/divert-proxy` and `internal/divert/proxy.go` with reverse proxy, `_aet_v` cookie, transparent upstream forwarding, and sensorkit session emission.
- **Task B (Tripwire Fix & Verification)**: Fix `backend/go/go.mod` to Go 1.26, fix `tripwire_test.go` compile errors, and verify table tests for normal shop requests and attack payloads.
- **Task C (Recovery & Write Hold)**: Implement `recovery.go` for soft-trip auto-release, safe 503 write holding on `/api/checkout`, and real admin pass-through.
- **Task D (Lures & Cognitive Tactics)**: Implement `lures.go` and `tactics.go` (canary env/backup lures, false success, tarpit) and update maze definitions.
- **Task E (Checkpoint: Tunnel & Port Preparation)**: Prepare Cloudflare Tunnel ingress configuration and ensure dashboard runs on non-conflicting port (`:3002`). *Requires explicit approval before applying.*
- **Task F (Lab Testing)**: Run full end-to-end verification using `scripts/aetees-lab.sh` and `scripts/divert-check.sh` locally.
- **Task G (Checkpoint: Live Bait Deployment)**: Route `aeteesadmin` to honeypot and main shop to shadow mode. *Requires explicit approval and owner sign-off.*
