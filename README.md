# Valk

> *"Choose which defenses die."*

**LLM Red Team Assessment Framework** — automated security testing for LLM deployments, AI agents, and RAG pipelines.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![Version](https://img.shields.io/badge/version-0.3.0-green.svg)](CHANGELOG.md)

---

## What Valk Does

Valk systematically maps, fingerprints, and attacks LLM endpoints. It goes beyond prompt-layer testing by automating **Special Token Injection (STI)** — injecting the model's own control tokens (`<|im_start|>`, `[INST]`, `<tool_call>`) via user input to override system prompts and hijack function calls.

**Three-phase pipeline:**

1. **Recon** — discover live API endpoints, test auth enforcement
2. **Fingerprint** — identify model family, capabilities, chat template, and special tokens
3. **Attack** — run security modules adapted to what was learned in phases 1–2

**Covers:** OWASP LLM01, LLM02, LLM04, LLM06, LLM07, LLM08, LLM09

---

## Install

```bash
git clone https://github.com/AKiileX/Valk
cd valk
pip install -r requirements.txt
```

Python 3.11+ required. No Docker needed.

---

## Quick Start

```bash
# Full scan against a local Ollama instance
python valk.py scan http://localhost:11434

# Show what would run without sending anything
python valk.py scan http://localhost:11434 --dry-run

# Scan with API key (or set VALK_API_KEY env var)
python valk.py scan https://api.example.com --api-key sk-xxx

# Only STI modules
python valk.py scan http://localhost:11434 -m "sti-*"

# Skip DoS testing, run everything else
python valk.py scan http://localhost:11434 --skip token-limit-dos

# Route through Burp for inspection
python valk.py scan http://localhost:11434 --proxy http://127.0.0.1:8080

# HTML report for client delivery
python valk.py scan http://localhost:11434 -f html -o ./output/

# SARIF output for CI/CD (GitHub Advanced Security, Azure DevOps)
python valk.py scan http://localhost:11434 -f sarif

# Aggressive jailbreaks (L3) + stealth mode
python valk.py scan http://localhost:11434 -j 3 --stealth

# Regression mode — compare against previous baseline
python valk.py scan http://localhost:11434 --regression
```

---

## Modules

### Recon
| Module | What it tests |
|--------|---------------|
| `endpoint-discovery` | Fuzz known LLM API paths, confirm chat endpoint |
| `auth-probe` | No-auth, invalid key, empty key, rate limit enforcement |

### Fingerprint
| Module | What it tests |
|--------|---------------|
| `identity-probe` | Model family detection via API field + behavioral heuristics |
| `token-recon` | STI prerequisite — canary-verify which special tokens the model processes |
| `template-inference` | Match confirmed tokens to chat template (ChatML, LLaMA, Phi) |
| `rag-detection` | Detect RAG pipelines via citation patterns + retrieval latency |
| `capability-map` | Detect tool-use, vision, JSON mode, system prompt support |

### Attack
| Module | OWASP | What it tests |
|--------|-------|---------------|
| `context-injection` | LLM01 | Persona injection — adopt unrestricted identity |
| `prompt-extraction` | LLM01 | 17+ techniques to leak system prompt |
| `sti-role-injection` | LLM01 | Inject special tokens to assume system/assistant role |
| `sti-function-hijack` | LLM07 | Inject `<tool_call>` to trigger attacker-controlled function calls |
| `sti-role-escalation` | LLM01 | Multi-turn STI privilege escalation |
| `jailbreak` | LLM01 | Leveled jailbreaks L1/L2/L3 with baseline-validated detection |
| `guardrail-bypass` | LLM01 | Base64, ROT13, hex, unicode, 12-language encoding bypass |
| `multi-turn-escalation` | LLM01 | Progressive 8-chain multi-turn escalation |
| `indirect-injection` | LLM01 | Simulated RAG/email/tool-output injection |
| `data-exfil` | LLM06 | Markdown image injection + Interactsh OOB verification |
| `output-injection` | LLM02 | XSS, SSTI, SQL, command injection in model output |
| `rag-poisoning` | LLM03 | RAG document poisoning (7 scenarios) |
| `token-limit-dos` | LLM04 | Token exhaustion DoS (opt-in only) |

---

## CLI Reference

```
python valk.py scan TARGET [OPTIONS]

Options:
  -p, --phase        Phases to run: recon, fingerprint, attack
  -m, --module       Module filter (supports * wildcard)
      --skip         Modules to skip (works without --module)
  -s, --stealth      Slow randomized requests, benign prefixes, token obfuscation
  -j, --jailbreak-level  1=safe, 2=moderate (default), 3=aggressive
  -k, --api-key      API key (or set VALK_API_KEY env var)
      --auth-header  Header name for API key (default: Authorization)
      --proxy        HTTP proxy URL (e.g. http://127.0.0.1:8080 for Burp)
      --model-hint   Skip fingerprint, assume model family (gpt/mistral/llama/...)
  -o, --output       Output directory (default: reports/)
  -f, --format       Report format: json (default), html, sarif
  -t, --timeout      Request timeout in seconds (default: 120)
      --max-tokens   Max tokens per response (default: 4096)
      --speed        Payload budget: fast (25%), auto (default), thorough (100%)
      --min-confidence  Filter report: verified, probable, indicative
      --interactsh   Interactsh server URL for OOB DNS/HTTP callback verification
      --payload-pack External payload pack directory
      --regression   Deterministic probes + diff against previous baseline
      --dry-run      Show planned modules without executing
  -v, --verbose      Show full prompts and responses
```

---

## Authentication

Pass your API key via flag or environment variable — environment variable is recommended to avoid key exposure in shell history:

```bash
export VALK_API_KEY=sk-your-key
python valk.py scan https://api.example.com
```

Custom auth headers (e.g. `X-API-Key`):

```bash
python valk.py scan https://api.example.com --api-key mytoken --auth-header X-API-Key
```

---

## Report Formats

**JSON** (default) — machine-readable, includes full evidence chains, OWASP/ATLAS tags, and remediation guidance.

**HTML** — client-ready report with executive summary, sortable findings table, and expandable evidence chains.

**SARIF v2.1.0** — integrates with GitHub Advanced Security (`upload-sarif` action) and Azure DevOps for CI/CD LLM security gates.

---

## Payload Packs

Extend Valk with community payload packs without writing Python:

```bash
python valk.py scan http://target --payload-pack ./my-payloads/
```

A pack is a directory of YAML files using the same schema as `payloads/`. Add an optional `pack.yaml` manifest with `name`, `version`, `author`, `description`.

---

## Target Types

| Target | Notes |
|--------|-------|
| Self-hosted (vLLM, Ollama, llama.cpp, LocalAI) | Full pipeline including STI — most vulnerable |
| OpenAI-compatible proxy (LiteLLM, FastChat) | All modules; STI depends on backend tokenizer |
| Cloud APIs (OpenAI, Anthropic, Google) | Jailbreak, guardrail bypass, prompt extraction |
| LLM agents / chatbots | Context injection, function hijack (if tools exposed) |

---

## Security Note

Valk is an authorized testing tool. Only use it against systems you have explicit permission to test. The `--jailbreak-level 3` and `token-limit-dos` module are high-risk — use only with written authorization.

TLS verification is disabled by default (`verify=False`) because pentest targets routinely use self-signed certificates. This is intentional.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
