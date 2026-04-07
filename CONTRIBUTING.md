# Contributing to Valk

## The fastest way to contribute: add a payload

Payloads live in `payloads/*.yaml`. You do not need to write Python. If you've found a new jailbreak, a new special token, a new guardrail bypass encoding — add it to the appropriate YAML file and open a PR.

### YAML payload format

Each YAML file has its own top-level key (e.g. `jailbreaks`, `templates`, `techniques`). Match the existing schema in the file you're editing. At minimum, every payload entry needs:

- `id` — unique slug (e.g. `my-technique-v1`)
- `name` — human-readable name
- A prompt or payload field appropriate to the file

Look at existing entries in the file for the exact schema.

### Adding a payload pack

If your payloads are a coherent collection (e.g. a specific model family's token set, or a domain-specific jailbreak set), package them as a payload pack:

```
my-pack/
  pack.yaml          # metadata: name, version, author, description
  jailbreaks.yaml    # same schema as payloads/jailbreaks.yaml
  special_tokens.yaml
```

Test it with:
```bash
python valk.py scan http://localhost:11434 --payload-pack ./my-pack/ --module jailbreak
```

---

## Adding a new module (Python)

1. Create `modules/{phase}/your_module.py`
2. Inherit `BaseModule`, set `name`, `phase`, `owasp_llm`, `mitre_atlas`
3. Implement `async def run(self) -> list[Finding]`
4. Override `should_run(ctx)` if the module has prerequisites (e.g. needs confirmed tokens)
5. Use `self.load_payloads("your_file.yaml")` and `self.budget_payloads(payloads)` for adaptive budgeting
6. Use `self.make_finding(...)` to return results with full evidence chains
7. The engine auto-discovers it — no registration needed

See `modules/attack/jailbreak.py` for a well-commented example.

### Module checklist

- [ ] `name` is kebab-case and unique
- [ ] `should_run()` returns `False` when prerequisites are absent
- [ ] Findings only created on baseline-validated evidence (use `baseline_refusal_flipped`)
- [ ] `budget_payloads()` used so `--speed fast` works
- [ ] OWASP LLM and MITRE ATLAS tags are correct
- [ ] `remediation` field is populated on every finding

---

## Pull request guidelines

- One PR per payload file or module
- Do not include scan reports (`reports/`) in commits
- For new modules, include at least one test in `tests/`
- Payloads that are purely destructive (e.g. crash/corrupt the target app) are not accepted — DoS testing stays opt-in via `token-limit-dos`

---

## Questions

Open a GitHub Discussion for design questions before building a large module.
