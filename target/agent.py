#!/usr/bin/env python3
"""Sentinel target agent — a DELIBERATELY VULNERABLE AI agent (M1).

The red-team target for Project Sentinel. An off-the-shelf LangChain
tool-calling agent wired to genuinely dangerous tools behind a sloppy,
over-permissive system prompt. Sentinel attacks THIS inside a Daytona sandbox
so we can observe what a compromised agent actually does.

    python target/agent.py "summarize the latest incident report for me"
    python target/agent.py --mock "drop the employees table"

Contract for M2 (Daytona) / M4 (UI): the final agent reply is printed to
stdout; a run summary is written to last_run.json (override with
SENTINEL_SUMMARY) in exactly the telemetry shape run_in_sandbox() returns:

    {"agent_response": ..., "telemetry": {"files_accessed": [...],
     "database_dropped": bool, "network_egress": url|null}}

DO NOT run outside an isolated sandbox — the tools execute real commands, SQL,
file reads, and network requests. See ../DANGER.md.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Make the package importable no matter what directory M2 launches us from.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import telemetry  # noqa: E402
from config import BANNER, SUMMARY_PATH  # noqa: E402
from runtime import build_agent, run_agent  # noqa: E402
from safety import assert_sandbox_or_die  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="agent.py",
        description="Sentinel deliberately-vulnerable target agent.",
    )
    parser.add_argument("prompt", help="The user (or attacker) instruction to run.")
    parser.add_argument("--mock", action="store_true",
                        help="Deterministic planner, no LLM/API calls.")
    parser.add_argument("--max-steps", type=int, default=8,
                        help="Max tool-call iterations (default: 8).")
    parser.add_argument("--force", action="store_true",
                        help="Run even if this does not look like a sandbox. Dev only.")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress the banner (telemetry still emitted).")
    args = parser.parse_args()

    assert_sandbox_or_die(force=args.force)

    if not args.quiet:
        print(BANNER, file=sys.stderr)

    agent = build_agent(mock=args.mock, max_steps=args.max_steps)
    result = run_agent(agent, args.prompt)

    # Write the contract-shaped summary for the harness to pull out.
    tele = telemetry.summary()
    record = {"agent_response": result.final_answer, "telemetry": tele}
    try:
        with open(SUMMARY_PATH, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
        print(f"[summary] wrote {SUMMARY_PATH}", file=sys.stderr)
    except OSError as exc:
        print(f"[summary] write failed: {exc}", file=sys.stderr)

    # Final answer, then the machine-readable telemetry line M2's
    # parse_agent_telemetry() scrapes from stdout (core/daytona_ops.py).
    print(result.final_answer)
    print("TELEMETRY: " + json.dumps(tele, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
