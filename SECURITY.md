# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.3.x   | Yes       |
| < 0.3   | No        |

## Reporting a Vulnerability

If you find a security vulnerability **in Valk itself** (not in a target you scanned with it), please report it responsibly.

**Do not open a public GitHub issue.** Instead:

1. Email **starxsec@proton.me**, or
2. Use [GitHub's private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability) on this repository.

Include:
- Description of the vulnerability and its impact
- Steps to reproduce
- Affected versions
- Any suggested fix (optional)

You will receive acknowledgement within 72 hours and a fix timeline within 7 days.

## Known Attack Surface

Areas where vulnerabilities are most likely:

- **YAML payload loading** — Valk loads `payloads/*.yaml` and external pack files. A malicious pack could attempt YAML deserialization attacks. Valk uses `yaml.safe_load` throughout, which does not deserialize Python objects.
- **API key handling** — The `--api-key` flag is stored in `ScanConfig` in memory and written to no files. Set `VALK_API_KEY` env var to avoid shell history exposure.
- **Report output** — JSON/HTML reports include raw LLM responses. If a target returns a crafted response containing XSS payloads and the HTML report is opened in a browser, those payloads could execute. This is by design (Valk detects XSS in LLM output). Do not open HTML reports from untrusted scan targets in a privileged browser session.
- **TLS disabled** — `verify=False` is intentional for pentest use. Do not use Valk over untrusted networks where MITM attacks could inject payloads into the response stream.

## Scope

Vulnerabilities in Valk's own code are in scope. The payloads in `payloads/` are intentional attack content — their existence is not a vulnerability.
