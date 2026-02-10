# ClawGuard — Project Instructions

## Project Overview
ClawGuard is a security scanner for AI agent skills. It uses multi-layer analysis (static patterns, LLM semantic analysis, dependency scanning, prompt injection detection, attack chain detection, and Docker sandboxing) to catch threats that traditional security tools miss.

- **Package:** `@dribgib/clawguard` on npm (v1.0.1)
- **Repo:** https://github.com/mikecavallo/clawguard
- **Site:** https://mikecavallo.github.io/clawguard/
- **License:** MIT
- **Author:** Mike Cavallo

## Tech Stack
- TypeScript (ES Modules, NodeNext)
- Node.js >= 18
- Commander.js (CLI), Acorn (AST), Chalk (output), YAML (patterns)
- Anthropic SDK (optional — semantic analysis only, loaded dynamically)
- Vitest (testing, 120 tests across 7 files)
- ESLint (flat config, eslint.config.js)
- GitHub Actions CI (lint + build + test, Node 18/20/22 matrix)
- GitHub Pages (site + docs)

## Architecture
```
src/
  cli.ts              — CLI entry point (thin shell, delegates to commands/)
  orchestrator.ts     — Loads skills, coordinates analyzers, aggregates findings
  types.ts            — Shared interfaces (Finding, ScanResult, RiskLevel, etc.)
  config.ts           — LLM provider config (~/.config/clawguard/config.json)
  report.ts           — Report generation (JSON, Markdown, HTML)
  fetch.ts            — GitHub/URL skill fetching
  database.ts         — Known-bad skill database
  reputation.ts       — Author/skill reputation
  signing.ts          — Cryptographic skill signing
  diff.ts             — Version differential analysis
  monitor.ts          — Continuous monitoring daemon
  dashboard.ts        — Web dashboard
  tui.ts              — Interactive terminal UI
  index.ts            — Library exports
  help.ts             — Help text

  commands/
    index.ts          — Barrel exports for all command modules
    scan.ts           — scan, full, gate commands
    library.ts        — library scan command
    analysis.ts       — graph, honeypot commands
    config.ts         — config, init commands
    tools.ts          — sign, diff, reputation commands
    services.ts       — monitor, dashboard commands
    info.ts           — version, ui, help, about commands
    update.ts         — update-patterns command (fetches latest YAML from GitHub)

  analyzers/
    static.ts         — 60+ code patterns (code.yaml)
    deps.ts           — Dependency/supply chain scanner (deps.yaml)
    prompt.ts         — Prompt injection detection (prompt.yaml)
    semantic.ts       — LLM-powered intent analysis (dynamic import, optional)
    chains.ts         — Multi-skill attack chain detection
    semantic-chains.ts — LLM chain analysis (dynamic import, optional)
    honeypot.ts       — Credential access patterns
    sandbox.ts        — Docker behavioral sandbox
    intent-graph.ts   — Data flow visualization

  patterns/
    code.yaml         — 60+ code vulnerability patterns
    deps.yaml         — Known malicious packages (100+ npm, 40+ pip, 5+ go)
    prompt.yaml       — 30+ prompt injection patterns

  utils/
    ast.ts            — JS AST parsing (Acorn)
    levenshtein.ts    — String distance for typosquat detection
    registry.ts       — npm/PyPI registry validation

api/server.ts         — Known-bad database REST API (Express, auth + rate limiting)
action.yml            — GitHub Action for marketplace (composite action)
benchmark/
  run.ts              — Detection accuracy benchmark (fixtures + PINT-style)
  results.json        — Latest benchmark results
tests/                — 120 tests across 7 files
  types.test.ts       — Risk scoring, severity weights, findings summary (22 tests)
  report.test.ts      — JSON, Markdown, HTML report generation (24 tests)
  static.test.ts      — Static analyzer against fixtures (9 tests)
  orchestrator.test.ts — Skill loading, scan lifecycle, path safety (12 tests)
  chains.test.ts      — Attack chain detection (4 tests)
  deps.test.ts        — Dependency/supply chain analysis
  prompt.test.ts      — Prompt injection detection
tests/fixtures/       — 10 test skills (8 malicious + 1 chain pair + 1 safe)
docs/                 — Documentation site (6 HTML pages + shared CSS)
site/index.html       — Marketing/landing page (GitHub Pages)
skill/SKILL.md        — ClawGuard as an installable AI agent skill
```

## Key Types
```typescript
type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
type RiskLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
SEVERITY_WEIGHTS: { critical: 25, high: 10, medium: 4, low: 1, info: 0 }
RISK_THRESHOLDS: { SAFE: 10, LOW: 25, MEDIUM: 50, HIGH: 75 }
```

## Build & Run
```bash
npm run build        # tsc + copy YAML patterns to dist/
npm run dev          # tsc --watch
npm run test         # vitest (120 tests)
npm run lint         # eslint src/
npm run scan         # node dist/cli.js
npx tsx benchmark/run.ts  # run detection accuracy benchmark
```

## Benchmark Results (latest)
- **F1 Score:** 94.1%
- **Precision:** 100% (zero false positives)
- **Recall:** 88.9%
- **Accuracy:** 90% (fixtures), 93.75% (prompt injection)
- 10 fixture cases + 16 PINT-style prompt injection samples

## API Server (api/server.ts)
- Bearer token auth via `CLAWGUARD_API_KEY` env var (skipped when unset for dev)
- Rate limiting: 10 requests/min/IP on POST /report
- Persistent storage: JSON file at `$DATA_DIR/known-bad.json`
- Routes: GET /health, GET /api/v1/check/:hash, POST /api/v1/report, GET /api/v1/stats, GET /api/v1/list

## GitHub Action (action.yml)
- Composite action for CI/CD integration
- Inputs: path, severity-threshold, output-format, semantic, api-key, node-version
- Outputs: risk-level, risk-score, findings-count, report

## Path Safety
- orchestrator.ts blocks scanning system directories (/, /etc, /usr, /var, /bin, /sbin, /lib, /boot, /proc, /sys, /dev)
- Blocks scanning home directory root
- Detects and blocks symlinks pointing into restricted paths

## Rules
- No OpenClaw references anywhere — this is Mike Cavallo's project
- The site design (terminal green, glassmorphism, particles) should be preserved when updating
- Test everything — this is a security tool, credibility depends on it
- Keep patterns in YAML, not hardcoded
- Support offline-first — core scanning must work without an LLM API key
- @anthropic-ai/sdk is an optional dependency — use dynamic import() only
- Enterprise version exists at ../clawguard-enterprise (SaaS pitch, not active yet)
