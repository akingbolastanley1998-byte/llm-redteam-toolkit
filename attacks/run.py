"""
Main entry point — run attack modules against a target and print results.

Usage:
    python attacks/run.py --target ollama --model llama3
"""

import argparse
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from targets.ollama_target import OllamaTarget
from attacks.identity_override import IdentityOverrideAttack
from attacks.session_persistence import SessionPersistenceAttack
from attacks.config_exposure import ConfigExposureAttack
from attacks.prompt_extraction import PromptExtractionAttack

ATTACK_REGISTRY = [
    IdentityOverrideAttack,
    SessionPersistenceAttack,
    PromptExtractionAttack,
    ConfigExposureAttack,
]


def main():
    parser = argparse.ArgumentParser(description="LLM Red-Team Toolkit")
    parser.add_argument("--target", choices=["ollama"], default="ollama")
    parser.add_argument("--model", default="llama3", help="Model name for the target")
    parser.add_argument("--host", default="http://localhost:11434")
    parser.add_argument("--verbose", action="store_true", help="Print each prompt and raw response")
    args = parser.parse_args()

    if args.target == "ollama":
        target = OllamaTarget(model=args.model, host=args.host)

    print(f"Running attacks against {args.model} via {args.target}...\n")

    reports = []
    for attack_cls in ATTACK_REGISTRY:
        attack = attack_cls(target)
        print(f"[*] Running {attack.name} ({attack.owasp_id})...")
        report = attack.run()
        reports.append(report)

        if args.verbose:
            for r in report.results:
                mark = "SUCCEEDED" if r.succeeded else "resisted"
                print(f"    [{mark}] Prompt: {r.prompt}")
                if r.notes:
                    print(f"        Notes: {r.notes}")
                print(f"        Response: {r.response[:200]}{'...' if len(r.response) > 200 else ''}\n")

        print(f"    ASR: {report.asr:.0%}  |  Severity: {report.severity}\n")

    print("=" * 50)
    print("Summary")
    print("=" * 50)
    for r in reports:
        print(f"{r.attack_name:25s} {r.owasp_id:8s} ASR={r.asr:.0%}  ({r.severity})")


if __name__ == "__main__":
    main()