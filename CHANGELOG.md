# Changelog

All notable changes to Valk are documented here.

---

## [0.3.0] — 2026-04-06 — Enterprise

### Added
- **SARIF v2.1.0 output** (`-f sarif`) — rule-per-module, integrates with GitHub Advanced Security and Azure DevOps
- **RAG detection module** — 6 probes, 8 regex patterns, retrieval latency analysis; populates `ctx.system_prompt_hints["RAG_DETECTED"]`
- **RAG poisoning module** — 7 scenarios: instruction injection, data exfiltration via documents, persona override, markdown exfil, steganographic embedding
- **Token-limit DoS module** — opt-in via `--module token-limit-dos`; repetition amplification, recursive expansion, output length bypass
- **Interactsh OOB integration** (`--interactsh`) — DNS/HTTP callback verification for data-exfil findings; upgrades findings to `verified` confidence when callbacks received
- **Capability-map module** — detects vision, tool-use, JSON mode, streaming, system prompt support
- **Endpoint enumeration depth** — v2/v3 probing, debug/admin/tokenizer endpoint detection
- **Plugin marketplace** — community payload packs via `--payload-pack`; supports `pack.yaml` manifests and multi-directory loading

---

## [0.2.0] — 2026-04-05 — Depth

### Added
- **Multi-turn escalation** — 8 chains across 7 strategies (authority gradient, normalization, cognitive overload, persona drift, technical jargon, false context, incremental desensitization)
- **Indirect injection** — 11 scenarios across 5 context types: RAG documents, email, webpage, tool output, CSV data
- **Data exfil** — 7 techniques with regex-based URI detection; markdown image injection, iframe injection, link injection
- **Output injection** — 11 scenarios across 5 types: XSS, SSTI, SQL injection, command injection, JSON injection
- **STI role escalation** — multi-turn progressive privilege escalation via special tokens
- **Stealth mode** (`--stealth`) — benign prefixes, payload fragmentation, zero-width character token obfuscation, timing noise
- **Auth probe module** — 5 tests: no-auth, invalid key, empty key, endpoint access, rate limiting
- **Regression mode** (`--regression`) — deterministic probes, JSON snapshot persistence, diff engine with improved/regressed/unchanged/new tracking
- **Adaptive payload budgeting** (`--speed fast/auto/thorough`) — engine measures avg response time from fingerprint phase and scales payload count accordingly
- **Reasoning model support** — 120s timeout default, `max_tokens 4096`, `reasoning_content` capture from Qwen/DeepSeek CoT
- **Multilingual guardrail bypass** — 12 languages including 3 low-resource (Swahili, Tamil, Amharic)

---

## [0.1.0] — 2026-04-04 — Core

### Added
- Three-phase pipeline: Recon → Fingerprint → Attack
- `core/models.py` — Pydantic data structures: `Finding`, `Evidence`, `Turn`, `ScanContext`, `ScanConfig`
- `core/session.py` — async httpx client with connection pooling, rate limiting, retry, proxy support
- `core/engine.py` — phase orchestrator, module auto-discovery, adaptive selection, baseline calibration engine
- `core/logger.py` — Rich TUI with banners, progress, colored severity output
- `core/reporter.py` — JSON + HTML report generation
- Modules: `endpoint-discovery`, `auth-probe`, `identity-probe`, `contradiction`, `knowledge-cutoff`, `token-recon`, `template-inference`, `context-injection`, `prompt-extraction`, `sti-role-injection`, `sti-function-hijack`, `jailbreak`, `guardrail-bypass`
- Payloads: `endpoints.yaml`, `special_tokens.yaml` (49 tokens, 10 families), `sti_templates.yaml` (36 payloads), `jailbreaks.yaml`, `extractions.yaml`, `personas.yaml`, `events.yaml`, `encodings.yaml`
- CLI: Typer-based with `scan` and `version` commands
- Baseline engine: static + dynamic calibration probes, refusal-flip detection to eliminate false positives
- JSON report with OWASP LLM + MITRE ATLAS mapping, full evidence chains, remediation guidance
