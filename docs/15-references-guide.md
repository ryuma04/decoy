# 15 — Reference guide (what to study, where)

Rules: `../../AGENTS.md` §3. Read to learn; write our own. Note what you learned in `decisions.md`.

| Our feature | Study in | Look at | Take away (idea, not code) |
| --- | --- | --- | --- |
| SSH decoy shell | `references/cowrie` (BSD-3) | `src/cowrie/shell/`, `src/cowrie/commands/`, `etc/` config files, fake filesystem concept | Fake fs model, command emulation breadth, event ids (`cowrie.login.failed`, `cowrie.command.input`, `cowrie.client.version`, `cowrie.client.kex`, `cowrie.session.file_download`) as a checklist for our event types |
| SSH credential capture, Go style | `references/wisp` (BSD-3) | `internal/service/sshsvc/ssh.go` | x/crypto/ssh callbacks, connect/login events; note it never grants a shell |
| Event struct, high-value kinds | `references/wisp` | `internal/event/event.go`, `internal/sink/limit.go` | Flat envelope, protected rate budget for credential events, dedup |
| K8s / kubelet / IMDS / Jenkins / MCP decoys | `references/wisp` | `internal/service/k8ssvc`, `kubeletsvc`, `imdssvc`, `jenkinssvc`, `mcpsvc`, `docs/design.md` | Which endpoints attackers hit first, realistic 401 bodies |
| Honeytokens | `references/wisp` | `internal/token/` (docx, kubeconfig, MCP), README token section | Token formats that call home; per-token ids |
| Persona | `references/wisp` | `internal/persona/persona.go` | Consistent fake identity across services |
| Rule-based classification + MITRE | `references/echidra` (**AGPL**) | `classifier/rules/*.yaml`, `classifier/features/session.py`, `classifier/scoring/session.py` | Features-then-rules pipeline, evidence lists, per-rule confidence. Write our own rules |
| Sensor → hub contract, heartbeats | `references/honeywire` (**AGPL**) | `Docs/architecture/dataContracts.md`, `Hub/internal`, `SDKs/go-honeywire` | Sensor-agnostic ingest with bearer key; heartbeat → silent sensor alerts; Discord/Slack payloads |
| File canary, web router decoy | `references/honeywire` | `Sensors/official/FileCanary`, `WebRouterDecoy` | Lure placement and trigger semantics |
| Adaptive maze | `references/labyrinth` (**AGPL**) | `docs/LAYERS.md`, `docs/ARCHITECTURE.md`, `src/layer2_maze/contradictions.py`, `src/orchestrator/session_manager.py` | Escalation paths, adaptive mode, per-deploy random bait. **Skip** L3/L4 |
| AI-agent behaviour | `references/labyrinth` | `docs/THREAT_MODEL.md`, `ETHICAL_USE.md` | Agent "cognitive dependencies"; ethics boundary = decoy perimeter |
| Command / injection detection | `references/codeguard` (team's own) | `codeguard/rules.py`, `deobfuscate.py`, `injection.py`, `textclf.py`, `eval/train_injection.py` | Rule + deobfuscation + TF-IDF/LR design; may be run unmodified as an optional service (10) |

Repo facts (checked 30 Oct 2026): Cowrie Python, last commit 30 Oct 2026; Wisp Go, 2 Aug 2026; EchidraOSS Python,
23 Oct 2026; HoneyWire Go hub + Vue UI, 28 Aug 2026; LABYRINTH Go CLI + Python layers, 15 Mar 2026 (least active —
treat docs as ideas, not tested behaviour).
