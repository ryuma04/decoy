## Reference Repository Policy

The `references/` directory contains five cloned open-source repositories:

1. Cowrie
2. Wisp
3. EchidraOSS
4. HoneyWire
5. LABYRINTH

These repositories are strictly for research and technical reference.

### Strict Rules

- DO NOT use any reference repository as the project's base.
- DO NOT fork or modify the reference repositories.
- DO NOT copy or vendor their source code into the main project.
- DO NOT import their modules or dependencies as implementation shortcuts.
- DO NOT reproduce their existing dashboards.
- DO NOT execute their deployment stacks as part of the product.

### Expected Usage

Study their:
- System architecture and design decisions.
- Honeypot and decoy implementation logic.
- Honeytoken generation and triggering mechanisms.
- Event schemas and logging mechanisms.
- Session tracking and behavioural fingerprinting.
- Threat classification and detection rules.
- MITRE ATT&CK mapping.
- Distributed sensor communication.
- Adaptive deception and AI-agent interaction techniques.

Use these findings to independently design and implement our own system.

All actual product code must reside inside `deception-soc/`.

The final implementation must use:
- Next.js for frontend.
- Go for the main backend and intelligence engine.
- PostgreSQL for storage.
- FastAPI for optional AI/ML services.

Document architectural decisions and independently developed implementations.

Preserve the separation between reference material and original project code. Review applicable licenses before incorporating any third-party code or substantial code-derived material.