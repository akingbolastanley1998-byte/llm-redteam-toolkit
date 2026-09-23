# Architecture

## Overview

The toolkit is organized into four layers, each mapping to one phase of
the build:

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐     ┌──────────────┐
│   targets/  │────▶│   attacks/   │────▶│  detections/  │     │   reports/   │
│             │     │              │     │               │     │              │
│ Talks to    │     │ Sends attack │     │ Sigma rules   │     │ Renders the  │
│ the model   │     │ prompts,     │     │ describing    │     │ AttackReport │
│ (Ollama)    │     │ scores each  │     │ what each     │     │ objects into │
│             │     │ response     │     │ attack looks  │     │ a polished   │
│             │     │ (ASR)        │     │ like in logs  │     │ HTML report  │
└─────────────┘     └──────────────┘     └───────────────┘     └──────────────┘
                            │                                          ▲
                            └──────────────────────────────────────────┘
                                   attacks/run.py orchestrates all of it
```

## Data flow

1. `attacks/run.py` instantiates a `targets/ollama_target.py` `OllamaTarget`,
   which wraps the local Ollama chat API and tracks conversation history so
   multi-turn attacks (like session persistence) can run naturally.
2. Each attack module (`attacks/*.py`) subclasses `BaseAttack`
   (`attacks/base.py`), which defines the shared `AttackResult` /
   `AttackReport` data model and the Attack Success Rate (ASR) calculation.
3. Every attack implements its own `run()` (send prompts, collect
   responses) and `judge()` (decide whether the attack succeeded).
   `config_exposure.py` is the one exception — it judges by HTTP status
   code against the serving API directly, not by grading model text.
4. `attacks/run.py` collects the resulting `AttackReport` objects and
   either prints a console summary (`--verbose` for full prompt/response
   detail) or, with `--report`, hands them to `reports/generate.py`,
   which renders them into a single self-contained HTML file.
5. `detections/*.yml` are written independently of the runtime code —
   they're the analyst deliverable, describing what each confirmed
   attack pattern would look like in a real application's logs, so a
   defender could build alerting around it. They aren't executed by
   the toolkit; they're the "what to do about it" companion to each
   attack module.

## Why the judge logic matters

The single most important design decision in this toolkit isn't the
attack prompts — it's how each `judge()` decides success. An early
version used narrow keyword matching for acceptance ("confirmed",
"understood") and silently produced a 0% false-negative score on a
target that was actually complying 75% of the time. Every judge now
defaults to **assume success unless the model explicitly refuses**,
which is the safer failure mode for a red-team tool: a false positive
gets caught on manual review, a false negative doesn't get caught at
all.

## Extending the toolkit

- **New attack module**: subclass `BaseAttack`, implement `run()` and
  `judge()`, register it in `ATTACK_REGISTRY` in `attacks/run.py`.
- **New target**: implement a class with `.send(prompt)` and `.reset()`
  matching `OllamaTarget`'s interface (e.g. to point at a hosted API
  instead of local Ollama).
- **New detection rule**: add a `.yml` file to `detections/` following
  the existing Sigma structure — title, logsource, detection, tags
  (OWASP + MITRE ATLAS), falsepositives, level.
