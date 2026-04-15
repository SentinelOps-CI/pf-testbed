# BYO-Agent Quickstart

Bring your own agent and integrate it with the testbed runtime in a reproducible way.

## 1) Environment Setup

```bash
git clone https://github.com/provability-fabric/pf-testbed.git
cd pf-testbed
npm ci
python -m pip install -r requirements.txt
python -m pip install -r testbed/tools/reporter/requirements.txt
make up
make status
```

## 2) Baseline Validation

Before integrating new agent code, confirm the repo baseline is green:

```bash
npm run validate:workflows
npm run retrieval:contract-check
npm run ci:verify
```

`ci:verify` runs workflow validation, ESLint, Prettier, TypeScript builds for the main services, and Jest. See `docs/quickstart.md` for the exact breakdown and for Jest exclusions.

## 3) Minimal Agent Contract

Your agent integration should produce:

- deterministic request IDs
- tenant-aware execution context
- explicit capability usage
- auditable tool calls

Minimal request/response shape:

```json
{
  "request": {
    "tenant": "acme",
    "session_id": "session-1",
    "message": "Schedule a meeting"
  },
  "response": {
    "text": "Meeting scheduled",
    "actions": [{ "tool": "calendar", "operation": "write" }],
    "metadata": {
      "capabilities_used": ["calendar:write"]
    }
  }
}
```

## 4) Local Journey Test

1. execute one read-only action (`search`, `fetch`)
2. execute one write action (`email`, `calendar`)
3. verify observability in Grafana and Prometheus

## 5) Security and Reliability Checks

```bash
npm run security:test
```

Then verify:

- invalid signatures are rejected
- cross-tenant data access is denied
- actions produce traceable metadata

## Service Endpoints

- Gateway: `http://localhost:3003`
- Ingress: `http://localhost:3001`
- Ledger: `http://localhost:3002`
- Grafana: `http://localhost:3100`
- Prometheus: `http://localhost:9090`

## Production Readiness Checklist

- agent uses typed contracts (no ad hoc payloads)
- no hardcoded secrets
- all external calls include retries and timeout budget
- tool actions mapped to explicit capabilities
- metrics and alerts configured for key failure paths
- changes pass `npm run ci:verify` and `npm run retrieval:contract-check` before release
