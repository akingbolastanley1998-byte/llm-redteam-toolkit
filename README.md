# LLM Red-Team Toolkit

An offensive security testing framework for large language model (LLM) applications,
generalized from live red-team research conducted against a Reachy Mini Lite
LLM-controlled robot (MSc dissertation, University of Derby, 2026).

## What this does

This toolkit runs structured attacks against a target LLM — prompt injection,
memory/context poisoning, identity override, and configuration-exposure checks —
scores how often each attack succeeds (Attack Success Rate), and generates a
professional findings report with MITRE ATLAS technique mapping and detection
guidance (Sigma rules) for defenders.

**Offense finds it. Defense catches it. One pipeline covers both.**

## Why

Most public LLM red-teaming demos stop at "look, I broke the chatbot."
This toolkit goes one step further: every confirmed finding produces a
matching detection rule, so the output is useful to both red teams and
blue teams — not just a proof of concept.

## Project status

🚧 Early build — Phase 0/1 in progress.

## Structure

```
attacks/      # Attack modules (prompt injection, memory poisoning, etc.)
detections/   # Corresponding Sigma detection rules per attack class
reports/      # Generated findings reports (HTML/PDF)
targets/      # Target harness configs (e.g. local Ollama model)
docs/         # Architecture notes, threat model, writeups
```

## Background

This project generalizes techniques validated during live red-teaming of a
physical Reachy Mini Lite robot, where testing found:
- 83% false-identity acceptance rate via memory poisoning
- Cross-session persistence of injected false identities
- A critical unauthenticated management-interface exposure allowing
  system-prompt overwrite in under two seconds

Full dissertation: *"Network-Exposed Configuration Attacks on LLM-Controlled
Social Robots: A Live Red-Team Case Study of the Pollen Robotics Reachy Mini
Lite"* (2026).

## Quick start

```bash
pip install -r requirements.txt
ollama pull llama3        # or any local model of your choice
python attacks/run.py --target ollama --model llama3
```

## Roadmap

- [x] Phase 0 — scaffolding & target setup
- [x] Phase 1 — offensive test runner + ASR scoring (4 attack modules: identity
      override, session persistence, prompt extraction, config exposure)
- [x] Phase 2 — Sigma detection rules + MITRE ATLAS mapping (4 rules, one per
      attack module, in `detections/`)
- [ ] Phase 3 — automated HTML/PDF reporting
- [ ] Phase 4 — polish, writeups, diagrams

## Disclaimer

For authorized testing and research purposes only. Only run against models
and systems you own or have explicit permission to test.