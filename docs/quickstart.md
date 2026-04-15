# Quick Start

## 1) Prerequisites

```bash
python --version
node --version
git --version
```

Recommended: Node 18+, Python 3.11+.

## 2) Clone and Install

```bash
git clone https://github.com/provability-fabric/pf-testbed.git
cd pf-testbed
npm ci
python -m pip install -r requirements.txt
python -m pip install -r testbed/tools/reporter/requirements.txt
```

## 3) Validate Tooling and Contracts

```bash
npm run validate:workflows
npm run retrieval:contract-check
npm run ci:verify
```

### What `ci:verify` includes

| Step               | Command               | Role                                               |
| ------------------ | --------------------- | -------------------------------------------------- |
| Workflow integrity | `validate:workflows`  | Validates workflow/script references               |
| Lint               | `lint`                | ESLint on gateway, self-serve ingress, ledger      |
| Format             | `format:check`        | Prettier on `testbed` sources and docs             |
| Types              | `typecheck` / `build` | TypeScript compile for gateway, ingress, ledger    |
| Tests              | `jest`                | Unit tests under `testbed/` (see exclusions below) |

Typechecking applies to the main service `tsconfig` projects; other packages (for example egress firewall) are still exercised by Jest.

### Tests not run by default

`jest.config.js` skips two files that are out of date relative to current APIs:

- `testbed/runtime/gateway/__tests__/agent-zoo.test.ts`
- `testbed/runtime/policy-kernel/__tests__/kernel.test.ts`

Restore them by updating the tests or the implementations they target, then remove the corresponding `testPathIgnorePatterns` entries.

## 4) Start Local Stack

```bash
make up
make status
```

Default endpoints:

- Gateway: `http://localhost:3003`
- Ingress: `http://localhost:3001`
- Ledger: `http://localhost:3002`
- Grafana: `http://localhost:3100`
- Prometheus: `http://localhost:9090`

## 5) Core Local Flows

```bash
# stop/start and logs
make down
make up
make logs

# security checks
npm run security:test

# evidence generation
make evidence
```

## Windows Notes

```cmd
python scripts\manage-deps.py --install
run.bat up
run.bat evidence
```

## Troubleshooting

- Dependency issues: rerun `npm ci` and Python installs.
- Service startup issues: run `make logs` and verify Docker is healthy.
- Workflow drift: run `npm run validate:workflows`.
- Contract drift: run `npm run retrieval:contract-check`.
- CI failures on format: run `npm run format` (writes fixes under `testbed/`).
- ESLint failures: run `npm run lint:fix` where auto-fix applies.
