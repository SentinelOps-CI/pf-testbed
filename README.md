# Provability Fabric Testbed

Secure, observable, multi-tenant infrastructure for building and validating AI workflow systems.

[![Node.js](https://img.shields.io/badge/node-%3E%3D18-2f855a)](https://nodejs.org/)
[![Python](https://img.shields.io/badge/python-%3E%3D3.11-2b6cb0)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache%202.0-4a5568)](./LICENSE)

---

## Why This Repository Exists

The testbed is designed to validate AI workflow systems under realistic constraints:

- strict tenant isolation
- policy-aware tool execution
- auditable traces and evidence
- reproducible quality and security gates

It provides a practical environment for architecture hardening, scenario validation, and production-readiness checks.

## Quick Navigation

- [Quick Start](#quick-start)
- [Repository Map](#repository-map)
- [Developer Commands](#developer-commands)
- [CI and Quality Model](#ci-and-quality-model)
- [Documentation](#documentation)

## Quick Start

### Prerequisites

- Node.js 18+
- Python 3.11+ (recommended)
- Git
- Docker (optional, for full local stack)

### 1) Install Dependencies

```bash
git clone https://github.com/provability-fabric/pf-testbed.git
cd pf-testbed
npm ci
python -m pip install -r requirements.txt
python -m pip install -r testbed/tools/reporter/requirements.txt
```

### 2) Validate Baseline

```bash
npm run validate:workflows
npm run retrieval:contract-check
npm run ci:verify
```

### 3) Start Local Services

```bash
make up
make status
```

Core endpoints:

- Gateway: `http://localhost:3003`
- Ingress: `http://localhost:3001`
- Ledger: `http://localhost:3002`
- Grafana: `http://localhost:3100`
- Prometheus: `http://localhost:9090`

## Repository Map

| Area                                | Purpose                                                |
| ----------------------------------- | ------------------------------------------------------ |
| `testbed/runtime/gateway`           | Orchestration, routing, decision-path traces, metering |
| `testbed/ingress/selfserve`         | Self-serve onboarding and request validation           |
| `testbed/runtime/ledger`            | Safety case packaging and evidence workflows           |
| `testbed/runtime/retrieval-gateway` | Retrieval contracts, tenant isolation, signed receipts |
| `testbed/runtime/egress-firewall`   | Sensitive content detection and egress certificates    |
| `testbed/runtime/policy-kernel`     | Policy kernel (tests currently excluded; see CI notes) |
| `testbed/tools`                     | Security gates, probes, metering, reporting            |
| `testbed/scenarios`                 | End-to-end business and technical journey fixtures     |

## Developer Commands

### Quality and integrity

```bash
npm run validate:workflows
npm run retrieval:contract-check
npm run ci:verify
npm run typecheck
```

### Service lifecycle

```bash
make up
make down
make logs
make status
```

### Security and evidence

```bash
npm run security:test
make evidence
```

## CI and Quality Model

### Local gate: `npm run ci:verify`

This is the primary Node/TypeScript quality gate. It runs, in order:

1. `npm run validate:workflows` — Python check that workflow references resolve
2. `npm run lint` — ESLint on gateway, ingress self-serve, and ledger entrypoints
3. `npm run format:check` — Prettier on `testbed/**/*.{ts,js,json,md}`
4. `npm run typecheck` — `tsc` for gateway, ingress self-serve, and ledger projects
5. `npm test` — Jest tests under `testbed/`

After `ci:verify` passes locally, also run `npm run retrieval:contract-check` before pushing; the GitHub Actions workflow runs both plus Python reporter tests.

### Jest exclusions

Two suites are listed in `testPathIgnorePatterns` in `jest.config.js` because they target APIs that have diverged from the current runtime (`AgentRunner` / `PolicyKernel`). Re-enable them by aligning implementations or updating tests.

### GitHub Actions

Workflows live under `.github/workflows/`. The main continuous integration job is `ci.yml` (workflow integrity, `ci:verify`, retrieval contract validation, reporter pytest, security). Use that file as the source of truth for what runs in CI.

## Architectural Principles

- Contract-first boundaries between modules and services
- No imports from private internals across package boundaries
- Tenant isolation and signed evidence by default
- Deterministic local and CI behavior

## Documentation

- `docs/quickstart.md` — standard onboarding path
- `docs/quickstart_byo_agent.md` — bring-your-own-agent integration

## License

Licensed under Apache 2.0. See `LICENSE`.
