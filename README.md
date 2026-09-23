# LLM Red-Team Toolkit

An offensive security testing framework for large language model (LLM)
applications — attack modules with quantified Attack Success Rate (ASR)
scoring, MITRE ATLAS-mapped Sigma detection rules, and automated HTML
findings reports. Generalized from live red-team research conducted
against a Reachy Mini Lite LLM-controlled robot (MSc dissertation,
University of Derby, 2026).

**Offense finds it. Defense catches it. One pipeline covers both.**

## Sample report

![Sample findings report](docs/assets/report-screenshot.png)

*(Screenshot of a generated report — see `reports/` after running the
toolkit for a live example.)*

## Key findings (against `llama3.2:1b`, local Ollama)

| Attack | OWASP | MITRE ATLAS | ASR | Severity |
|---|---|---|---|---|
| Identity override | LLM01 | AML.T0051.000 | 100% | High |
| Session persistence | LLM01 | AML.T0051.002 | 100% | High |
| Prompt extraction* | LLM01 | AML.T0051.000 | 50% | High |
| Config exposure | LLM02 | AML.T0040 | 100% | High |

*See caveat in `docs/findings-session-persistence.md` and the report
itself — this target has no real system prompt to leak, so this
number reflects hallucinated compliance, not confirmed data leakage.

Full write-up of the strongest finding: [`docs/findings-session-persistence.md`](docs/findings-session-persistence.md)

## What this does

This toolkit runs structured attacks against a target LLM — prompt
injection, session/context persistence, system prompt extraction, and
serving-infrastructure exposure checks — scores how often each attack
succeeds, and generates a professional findings report with MITRE
ATLAS technique mapping and Sigma detection rules for defenders.

## Why

Most public LLM red-teaming demos stop at "look, I broke the
chatbot." This toolkit goes one step further: every confirmed finding
has a matching detection rule, so the output is useful to both red
teams and blue teams — not just a proof of concept.

## Structure

```
attacks/      # Attack modules (identity override, session persistence,
              # prompt extraction, config exposure) + the test runner
detections/   # Corresponding Sigma detection rules, MITRE ATLAS-mapped
reports/      # Auto-generated HTML findings reports
targets/      # Target harness (currently: local Ollama model)
docs/         # Architecture notes and finding write-ups
```

See [`docs/architecture.md`](docs/architecture.md) for how the pieces
fit together and how to extend the toolkit with new attacks or targets.

## Background

This project generalizes techniques validated during live red-teaming
of a physical Reachy Mini Lite robot, where testing found:
- 83% false-identity acceptance rate via memory poisoning
- Cross-session persistence of injected false identities
- A critical unauthenticated management-interface exposure allowing
  system-prompt overwrite in under two seconds

Full dissertation: *"Network-Exposed Configuration Attacks on
LLM-Controlled Social Robots: A Live Red-Team Case Study of the Pollen
Robotics Reachy Mini Lite"* (2026).

## Quick start

```bash
pip install -r requirements.txt
ollama pull llama3.2:1b
ollama serve                                   # in a separate terminal
python attacks/run.py --model llama3.2:1b --verbose --report
```

The `--report` flag writes a full HTML findings report to `reports/`.

## Roadmap

- [x] Phase 0 — scaffolding & target setup
- [x] Phase 1 — offensive test runner + ASR scoring (4 attack modules)
- [x] Phase 2 — Sigma detection rules + MITRE ATLAS mapping
- [x] Phase 3 — automated HTML reporting with interpretation caveats
- [x] Phase 4 — architecture docs, finding write-up, polish

## Disclaimer

For authorized testing and research purposes only. Only run against
models and systems you own or have explicit permission to test.