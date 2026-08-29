#!/usr/bin/env python3
"""Run Sentinel's scenario -> sandbox -> quality-evaluation pipeline.

Mock mode is the safe, deterministic default. Live mode provisions Daytona
sandboxes and uses the configured Nosana/local-Kimi adapters, each of which has
an offline fallback when its inference runtime is unavailable.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from core.llm_ops import generate_attack_prompts, judge_attack_result
from core.mock_ops import (
    mock_generate_attack_prompts,
    mock_judge_attack_result,
    mock_run_sandbox,
)


DEFAULT_DESCRIPTION = "ScoobertOps internal operations agent"
PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_TARGET = str(PROJECT_ROOT / "target" / "agent_solo.py")
DEFAULT_OUTPUT = "run_results.json"

ScenarioGenerator = Callable[[str], List[Dict[str, str]]]
QualityEvaluator = Callable[[str, str, dict], Dict[str, str]]
SandboxRunner = Callable[[str, str], Dict[str, Any]]


def _normalize_network_egress(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        destinations = [item.strip() for item in value if item.strip()]
        return destinations[0] if destinations else None
    raise ValueError("network_egress must be a string, list of strings, or null")


def _normalize_telemetry(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("telemetry must be a dictionary")

    files = value.get("files_accessed")
    dropped = value.get("database_dropped")
    if not isinstance(files, list) or not all(isinstance(path, str) for path in files):
        raise ValueError("files_accessed must be a list of strings")
    if not isinstance(dropped, bool):
        raise ValueError("database_dropped must be a boolean")

    return {
        "files_accessed": list(dict.fromkeys(files)),
        "database_dropped": dropped,
        "network_egress": _normalize_network_egress(value.get("network_egress")),
    }


def _normalize_receipt(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("sandbox receipt must be a dictionary")

    response = value.get("agent_response")
    if not isinstance(response, str):
        raise ValueError("agent_response must be a string")

    exit_code = value.get("exit_code", 0)
    duration_ms = value.get("duration_ms", 0.0)
    execution_mode = value.get("execution_mode", "unknown")
    screenshot = value.get("screenshot", "")
    if isinstance(exit_code, bool) or not isinstance(exit_code, int):
        raise ValueError("exit_code must be an integer")
    if isinstance(duration_ms, bool) or not isinstance(duration_ms, (int, float)):
        raise ValueError("duration_ms must be numeric")
    if not isinstance(execution_mode, str) or not isinstance(screenshot, str):
        raise ValueError("execution_mode and screenshot must be strings")

    return {
        "agent_response": response.strip(),
        "telemetry": _normalize_telemetry(value.get("telemetry")),
        "screenshot": screenshot,
        "exit_code": exit_code,
        "duration_ms": round(float(duration_ms), 2),
        "execution_mode": execution_mode,
    }


def _execution_failure(
    test_case: Dict[str, str],
    message: str,
) -> Dict[str, Any]:
    return {
        "attack_type": test_case["attack_type"],
        "malicious_prompt": test_case["malicious_prompt"],
        "agent_response": message,
        "telemetry": {
            "files_accessed": [],
            "database_dropped": False,
            "network_egress": None,
        },
        "kimi_verdict": "FAIL - Sandbox Execution Error",
        "status": "red",
    }


def _evaluation_failure(
    test_case: Dict[str, str],
    receipt: Dict[str, Any],
) -> Dict[str, Any]:
    """Represent evaluation failure without discarding successful run evidence."""
    return {
        "attack_type": test_case["attack_type"],
        "malicious_prompt": test_case["malicious_prompt"],
        "agent_response": receipt["agent_response"],
        "telemetry": receipt["telemetry"],
        "kimi_verdict": "FAIL - Evaluation Error",
        "status": "red",
    }


def run_pipeline(
    agent_description: str = DEFAULT_DESCRIPTION,
    target_path: str = DEFAULT_TARGET,
    *,
    use_mock: bool = True,
    jail_network: bool = False,
    generator: Optional[ScenarioGenerator] = None,
    runner: Optional[SandboxRunner] = None,
    judge: Optional[QualityEvaluator] = None,
) -> Dict[str, Any]:
    """Execute behavioral QA scenarios and return the dashboard contract."""
    if not isinstance(agent_description, str) or not agent_description.strip():
        raise ValueError("agent_description must be a non-empty string")
    if not isinstance(target_path, str) or not target_path.strip():
        raise ValueError("target_path must be a non-empty string")

    selected_generator = generator or (
        mock_generate_attack_prompts if use_mock else generate_attack_prompts
    )
    selected_evaluator = judge or (
        mock_judge_attack_result if use_mock else judge_attack_result
    )
    if runner is not None:
        selected_runner = runner
    elif use_mock:
        selected_runner = mock_run_sandbox
    else:
        # Keep the zero-dependency mock path usable without importing Daytona.
        from core.daytona_ops import run_in_sandbox

        selected_runner = lambda path, prompt: run_in_sandbox(
            path,
            prompt,
            jail_network=jail_network,
        )

    test_cases = selected_generator(agent_description)
    if not isinstance(test_cases, list) or not test_cases:
        raise ValueError("QA scenario generator returned no test cases")

    scenarios: List[Dict[str, Any]] = []
    for raw_case in test_cases:
        if not isinstance(raw_case, dict):
            raise ValueError("each QA test case must be a dictionary")
        attack_type = raw_case.get("attack_type")
        malicious_prompt = raw_case.get("malicious_prompt")
        if not isinstance(attack_type, str) or not isinstance(malicious_prompt, str):
            raise ValueError(
                "each QA test case requires string attack_type and malicious_prompt"
            )
        test_case = {
            "attack_type": attack_type,
            "malicious_prompt": malicious_prompt,
        }

        try:
            receipt = _normalize_receipt(
                selected_runner(target_path, malicious_prompt)
            )
        except Exception as exc:
            message = f"Sandbox execution failed: {str(exc).strip()[:500]}"
            scenarios.append(
                _execution_failure(
                    test_case,
                    message,
                )
            )
            continue

        if receipt["exit_code"] != 0:
            message = (
                f"Target process exited with code {receipt['exit_code']}: "
                f"{receipt['agent_response'][:500]}"
            )
            failed = _execution_failure(
                test_case,
                message,
            )
            scenarios.append(failed)
            continue

        try:
            judgment = selected_evaluator(
                malicious_prompt,
                receipt["agent_response"],
                receipt["telemetry"],
            )
        except Exception:
            scenarios.append(_evaluation_failure(test_case, receipt))
            continue
        if (
            not isinstance(judgment, dict)
            or set(judgment) != {"verdict", "status", "reasoning"}
            or judgment.get("status") not in {"red", "green"}
            or not all(isinstance(value, str) for value in judgment.values())
        ):
            scenarios.append(_evaluation_failure(test_case, receipt))
            continue

        scenarios.append(
            {
                "attack_type": attack_type,
                "malicious_prompt": malicious_prompt,
                "agent_response": receipt["agent_response"],
                "telemetry": receipt["telemetry"],
                "kimi_verdict": judgment["verdict"],
                "status": judgment["status"],
            }
        )

    passed = sum(scenario["status"] == "green" for scenario in scenarios)
    return {
        "target_agent": agent_description.strip(),
        "summary": {
            "total_scenarios": len(scenarios),
            "passed": passed,
            "failed": len(scenarios) - passed,
        },
        "scenarios": scenarios,
    }


def write_results(results: Dict[str, Any], output_path: str = DEFAULT_OUTPUT) -> Path:
    """Atomically write the final pipeline contract as UTF-8 JSON."""
    destination = Path(output_path).expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(
        json.dumps(results, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    return destination.resolve()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run Sentinel's AI-agent quality-assurance suite and write the "
            "run_results.json dashboard contract."
        )
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--mock",
        action="store_true",
        help="Use deterministic offline scenarios, runner, and evaluator (default).",
    )
    mode.add_argument(
        "--live",
        action="store_true",
        help="Provision Daytona sandboxes and use configured inference runtimes.",
    )
    parser.add_argument("--target", default=DEFAULT_TARGET)
    parser.add_argument("--description", default=DEFAULT_DESCRIPTION)
    parser.add_argument("--output", default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--jail-network",
        action="store_true",
        help="Block outbound traffic in live Daytona sandboxes.",
    )
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    use_mock = not args.live
    if args.live and not os.getenv("DAYTONA_API_KEY", "").strip():
        parser.error("--live requires DAYTONA_API_KEY in the environment or .env")

    results = run_pipeline(
        agent_description=args.description,
        target_path=args.target,
        use_mock=use_mock,
        jail_network=args.jail_network,
    )
    destination = write_results(results, args.output)
    summary = results["summary"]
    print(
        f"Sentinel complete: {summary['passed']} passed, {summary['failed']} failed "
        f"across {summary['total_scenarios']} scenarios."
    )
    print(f"Results: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
