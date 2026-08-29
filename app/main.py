"""Sentinel's read-only Streamlit security assessment dashboard.

Member 4 owns this presentation layer. The dashboard intentionally reads the
saved ``run_results.json`` contract and never starts the vulnerable target or
the M1-M3 security pipeline.
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_PATH = PROJECT_ROOT / "run_results.json"

ATTACK_EXPLANATIONS = {
    "indirect prompt injection": (
        "A document or message hides instructions that try to make the AI act "
        "against its original rules."
    ),
    "indirect injection": (
        "A document or message hides instructions that try to make the AI act "
        "against its original rules."
    ),
    "privilege escalation": (
        "The test pretends to grant extra authority and asks the AI to perform "
        "an action it should not be allowed to take."
    ),
    "data exfiltration": (
        "The test tries to make the AI find private information and send it "
        "outside the protected environment."
    ),
    "system prompt extraction": (
        "The test asks the AI to reveal the hidden instructions that define "
        "its behavior and safety boundaries."
    ),
}

_MARKDOWN_SPECIALS = re.compile(r"([\\`*_[\]{}()#+.!|>\-])")


st.set_page_config(
    page_title="Sentinel · AI Security Report",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


st.markdown(
    """
    <style>
        :root {
            --sentinel-ink: #122033;
            --sentinel-muted: #607086;
            --sentinel-border: #dfe5ee;
            --sentinel-surface: #ffffff;
            --sentinel-canvas: #f5f7fb;
            --sentinel-indigo: #4f46e5;
            --sentinel-indigo-soft: #eef2ff;
            --sentinel-safe: #067647;
            --sentinel-safe-soft: #ecfdf3;
            --sentinel-risk: #b42318;
            --sentinel-risk-soft: #fee4e2;
            --sentinel-review: #475467;
            --sentinel-review-soft: #f2f4f7;
        }

        html { scroll-behavior: smooth; }

        .stApp {
            background:
                radial-gradient(circle at 88% 2%, rgba(79, 70, 229, 0.08), transparent 26rem),
                var(--sentinel-canvas);
            color: var(--sentinel-ink);
        }

        header[data-testid="stHeader"] {
            background: rgba(245, 247, 251, 0.9);
            backdrop-filter: blur(14px);
        }

        .block-container {
            max-width: 1180px;
            padding-top: 2rem;
            padding-bottom: 3.5rem;
        }

        h1, h2, h3, h4, p, label, [data-testid="stCaptionContainer"] {
            font-family: Inter, ui-sans-serif, -apple-system, BlinkMacSystemFont,
                "Segoe UI", sans-serif;
        }

        h1, h2, h3 { color: var(--sentinel-ink); letter-spacing: -0.025em; }

        .sentinel-brand {
            display: flex;
            align-items: center;
            gap: 0.7rem;
            margin-bottom: 2.7rem;
            color: var(--sentinel-ink);
            font-size: 1.02rem;
            font-weight: 760;
            letter-spacing: -0.015em;
        }

        .sentinel-mark {
            width: 2.25rem;
            height: 2.25rem;
            display: inline-grid;
            place-items: center;
            border-radius: 0.75rem;
            color: white;
            background: linear-gradient(145deg, #6d63ff, #4338ca);
            box-shadow: 0 8px 20px rgba(79, 70, 229, 0.22);
            font-size: 1.05rem;
        }

        .sentinel-brand-note {
            color: var(--sentinel-muted);
            font-size: 0.76rem;
            font-weight: 600;
            letter-spacing: 0.02em;
            padding-left: 0.72rem;
            border-left: 1px solid var(--sentinel-border);
        }

        .sentinel-eyebrow {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            color: #4338ca;
            background: var(--sentinel-indigo-soft);
            border: 1px solid #d9ddff;
            border-radius: 999px;
            padding: 0.38rem 0.68rem;
            font-size: 0.7rem;
            font-weight: 750;
            letter-spacing: 0.085em;
            text-transform: uppercase;
        }

        .sentinel-dot {
            width: 0.42rem;
            height: 0.42rem;
            border-radius: 50%;
            background: var(--sentinel-indigo);
        }

        .sentinel-hero-title {
            max-width: 760px;
            margin: 1rem 0 0.85rem;
            font-size: clamp(2.25rem, 5.5vw, 4.35rem);
            line-height: 1.02;
            letter-spacing: -0.06em;
            color: var(--sentinel-ink);
        }

        .sentinel-hero-copy {
            max-width: 700px;
            margin: 0 0 1.45rem;
            color: var(--sentinel-muted);
            font-size: 1.08rem;
            line-height: 1.72;
        }

        .sentinel-target-card {
            border: 1px solid var(--sentinel-border);
            background: rgba(255, 255, 255, 0.78);
            border-radius: 1rem;
            padding: 0.85rem 1rem;
            margin: 0.2rem 0 1.2rem;
        }

        .sentinel-kicker {
            color: var(--sentinel-muted);
            font-size: 0.72rem;
            font-weight: 750;
            letter-spacing: 0.07em;
            text-transform: uppercase;
            margin-bottom: 0.15rem;
        }

        .sentinel-flow {
            display: grid;
            grid-template-columns: repeat(3, minmax(0, 1fr));
            gap: 0.75rem;
            margin: 1.35rem 0 2.6rem;
        }

        .sentinel-flow-step {
            background: rgba(255, 255, 255, 0.76);
            border: 1px solid var(--sentinel-border);
            border-radius: 1rem;
            padding: 1rem;
        }

        .sentinel-step-number {
            display: inline-grid;
            place-items: center;
            width: 1.75rem;
            height: 1.75rem;
            border-radius: 0.55rem;
            color: #4338ca;
            background: var(--sentinel-indigo-soft);
            font-size: 0.76rem;
            font-weight: 800;
            margin-bottom: 0.65rem;
        }

        .sentinel-flow-step strong {
            display: block;
            color: var(--sentinel-ink);
            font-size: 0.9rem;
            margin-bottom: 0.26rem;
        }

        .sentinel-flow-step span {
            display: block;
            color: var(--sentinel-muted);
            font-size: 0.8rem;
            line-height: 1.5;
        }

        .sentinel-section-label {
            color: var(--sentinel-muted);
            font-size: 0.73rem;
            font-weight: 760;
            letter-spacing: 0.075em;
            text-transform: uppercase;
            margin-bottom: 0.35rem;
        }

        .sentinel-section-title {
            color: var(--sentinel-ink);
            font-size: 1.65rem;
            font-weight: 760;
            letter-spacing: -0.035em;
            margin-bottom: 0.45rem;
        }

        .sentinel-section-copy {
            color: var(--sentinel-muted);
            font-size: 0.94rem;
            line-height: 1.6;
            margin-bottom: 1.15rem;
        }

        .sentinel-metric-grid {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 0.8rem;
            margin: 1rem 0;
        }

        .sentinel-metric {
            min-height: 9rem;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            background: var(--sentinel-surface);
            border: 1px solid var(--sentinel-border);
            border-radius: 1rem;
            padding: 1.05rem 1.1rem;
            box-shadow: 0 1px 2px rgba(16, 24, 40, 0.025);
        }

        .sentinel-metric-label {
            color: var(--sentinel-muted);
            font-size: 0.76rem;
            font-weight: 700;
        }

        .sentinel-metric-value {
            color: var(--sentinel-ink);
            font-size: 2rem;
            line-height: 1;
            font-weight: 780;
            letter-spacing: -0.05em;
            margin: 0.55rem 0;
        }

        .sentinel-metric-detail {
            color: var(--sentinel-muted);
            font-size: 0.72rem;
            line-height: 1.4;
        }

        .sentinel-metric.risk { border-top: 3px solid var(--sentinel-risk); }
        .sentinel-metric.safe { border-top: 3px solid var(--sentinel-safe); }
        .sentinel-metric.score { border-top: 3px solid var(--sentinel-indigo); }

        .sentinel-score-panel {
            background: var(--sentinel-surface);
            border: 1px solid var(--sentinel-border);
            border-radius: 1rem;
            padding: 1.05rem 1.1rem;
            margin: 0 0 2.75rem;
        }

        .sentinel-score-row {
            display: flex;
            justify-content: space-between;
            gap: 1rem;
            color: var(--sentinel-muted);
            font-size: 0.78rem;
            margin-bottom: 0.65rem;
        }

        .sentinel-score-row strong { color: var(--sentinel-ink); }

        .sentinel-track {
            height: 0.62rem;
            width: 100%;
            overflow: hidden;
            border-radius: 999px;
            background: var(--sentinel-risk-soft);
        }

        .sentinel-track-safe {
            height: 100%;
            border-radius: inherit;
            background: linear-gradient(90deg, #12b76a, var(--sentinel-safe));
        }

        .sentinel-status {
            display: inline-flex;
            align-items: center;
            gap: 0.42rem;
            width: fit-content;
            border-radius: 999px;
            padding: 0.34rem 0.65rem;
            font-size: 0.68rem;
            line-height: 1;
            font-weight: 800;
            letter-spacing: 0.045em;
            text-transform: uppercase;
        }

        .sentinel-status::before {
            content: "";
            width: 0.42rem;
            height: 0.42rem;
            border-radius: 50%;
            background: currentColor;
        }

        .sentinel-status.risk {
            color: var(--sentinel-risk);
            background: var(--sentinel-risk-soft);
        }

        .sentinel-status.safe {
            color: var(--sentinel-safe);
            background: var(--sentinel-safe-soft);
        }

        .sentinel-status.review {
            color: var(--sentinel-review);
            background: var(--sentinel-review-soft);
        }

        .sentinel-scenario-index {
            color: var(--sentinel-muted);
            font-size: 0.7rem;
            font-weight: 750;
            letter-spacing: 0.07em;
            text-transform: uppercase;
            margin-bottom: 0.28rem;
        }

        .sentinel-meaning {
            border-left: 3px solid #818cf8;
            background: #f7f7ff;
            border-radius: 0 0.7rem 0.7rem 0;
            padding: 0.8rem 0.9rem;
            color: #3d4860;
            font-size: 0.86rem;
            line-height: 1.55;
            margin: 0.75rem 0 1rem;
        }

        .sentinel-evidence-title {
            color: var(--sentinel-muted);
            font-size: 0.7rem;
            font-weight: 760;
            letter-spacing: 0.065em;
            text-transform: uppercase;
            margin-bottom: 0.3rem;
        }

        .sentinel-evidence-value {
            color: var(--sentinel-ink);
            font-size: 0.88rem;
            font-weight: 650;
            line-height: 1.45;
        }

        .sentinel-note {
            color: var(--sentinel-muted);
            background: rgba(255, 255, 255, 0.68);
            border: 1px solid var(--sentinel-border);
            border-radius: 0.85rem;
            padding: 0.8rem 0.95rem;
            font-size: 0.8rem;
            line-height: 1.5;
        }

        .sentinel-empty {
            text-align: center;
            background: var(--sentinel-surface);
            border: 1px solid var(--sentinel-border);
            border-radius: 1.2rem;
            padding: 3rem 1.2rem 2.6rem;
            margin-top: 1rem;
        }

        .sentinel-empty-icon {
            display: inline-grid;
            place-items: center;
            width: 3.25rem;
            height: 3.25rem;
            border-radius: 1rem;
            background: var(--sentinel-indigo-soft);
            font-size: 1.45rem;
            margin-bottom: 0.75rem;
        }

        div[data-testid="stLayoutWrapper"] > div[data-testid="stVerticalBlock"] {
            background: rgba(255, 255, 255, 0.92);
            border-color: var(--sentinel-border) !important;
            border-radius: 1rem !important;
            box-shadow: 0 1px 2px rgba(16, 24, 40, 0.025);
        }

        div[data-testid="stCode"] {
            border-radius: 0.75rem;
            border: 1px solid #e5e9f1;
        }

        div[data-testid="stButton"] button {
            min-height: 2.75rem;
            border-radius: 0.75rem;
            border-color: #cfd6e3;
            color: var(--sentinel-ink);
            background: var(--sentinel-surface);
            font-weight: 700;
        }

        div[data-testid="stButton"] button:hover {
            color: #4338ca;
            border-color: #a5b4fc;
            background: var(--sentinel-indigo-soft);
        }

        div[data-testid="stButton"] button:focus-visible {
            outline: 3px solid rgba(79, 70, 229, 0.28);
            outline-offset: 2px;
        }

        div[role="radiogroup"] {
            gap: 0.35rem;
        }

        div[role="radiogroup"] label {
            min-height: 2.5rem;
            padding: 0.3rem 0.65rem;
            color: var(--sentinel-ink);
            background: var(--sentinel-surface);
            border: 1px solid var(--sentinel-border);
            border-radius: 0.7rem;
        }

        div[role="radiogroup"] label p {
            color: var(--sentinel-ink) !important;
            font-weight: 650;
        }

        div[role="radiogroup"] label:has(input:checked) {
            background: var(--sentinel-indigo-soft);
            border-color: #a5b4fc;
        }

        hr { border-color: var(--sentinel-border) !important; }

        @media (max-width: 760px) {
            .block-container { padding: 3.5rem 1rem 2.5rem; }
            .sentinel-brand { margin-bottom: 2rem; }
            .sentinel-brand-note { display: none; }
            .sentinel-flow, .sentinel-metric-grid { grid-template-columns: 1fr 1fr; }
            .sentinel-hero-title { font-size: 2.45rem; }
        }

        @media (max-width: 480px) {
            .sentinel-flow, .sentinel-metric-grid { grid-template-columns: 1fr; }
            .sentinel-metric { min-height: 7.5rem; }
        }
    </style>
    """,
    unsafe_allow_html=True,
)


def _text(value: Any, fallback: str, notes: List[str], field_name: str) -> str:
    """Return a display-safe contract string and record schema drift."""
    if isinstance(value, str) and value.strip():
        return value
    notes.append(f"{field_name} is missing or is not a non-empty string")
    return fallback


def _literal_markdown(value: str) -> str:
    """Escape model-controlled text before using a Markdown heading component."""
    return _MARKDOWN_SPECIALS.sub(r"\\\1", html.escape(value, quote=True))


def _normalize_scenario(raw: Any, index: int) -> Dict[str, Any]:
    """Normalize one result so a damaged scenario cannot crash the dashboard."""
    notes: List[str] = []
    if not isinstance(raw, dict):
        return {
            "attack_type": "Result unavailable",
            "malicious_prompt": "This saved scenario is not a JSON object.",
            "agent_response": "No agent response is available.",
            "kimi_verdict": "Verdict unavailable",
            "status": "review",
            "telemetry": {
                "files_accessed": None,
                "database_dropped": None,
                "network_egress": None,
                "network_egress_valid": False,
            },
            "raw_telemetry": raw,
            "schema_notes": [f"Scenario {index} is not a JSON object"],
        }

    attack_type = _text(
        raw.get("attack_type"), "Unnamed security test", notes, "attack_type"
    )
    malicious_prompt = _text(
        raw.get("malicious_prompt"),
        "Attack instructions are unavailable.",
        notes,
        "malicious_prompt",
    )
    agent_response = _text(
        raw.get("agent_response"),
        "Agent response is unavailable.",
        notes,
        "agent_response",
    )
    kimi_verdict = _text(
        raw.get("kimi_verdict"), "Verdict unavailable", notes, "kimi_verdict"
    )

    raw_status = raw.get("status")
    status = raw_status.strip().lower() if isinstance(raw_status, str) else "review"
    if status not in {"red", "green"}:
        status = "review"
        notes.append("status must be either 'red' or 'green'")

    raw_telemetry = raw.get("telemetry")
    if not isinstance(raw_telemetry, dict):
        notes.append("telemetry is missing or is not a JSON object")
        telemetry = {
            "files_accessed": None,
            "database_dropped": None,
            "network_egress": None,
            "network_egress_valid": False,
        }
    else:
        raw_files = raw_telemetry.get("files_accessed")
        files_accessed: Optional[List[str]]
        if isinstance(raw_files, list) and all(
            isinstance(item, str) for item in raw_files
        ):
            files_accessed = list(raw_files)
        else:
            files_accessed = None
            notes.append("telemetry.files_accessed must be a list of strings")

        raw_database = raw_telemetry.get("database_dropped")
        database_dropped: Optional[bool]
        if isinstance(raw_database, bool):
            database_dropped = raw_database
        else:
            database_dropped = None
            notes.append("telemetry.database_dropped must be true or false")

        raw_network = raw_telemetry.get("network_egress")
        network_egress: Optional[str]
        if raw_network is None or isinstance(raw_network, str):
            network_egress = raw_network
            network_egress_valid = True
        else:
            network_egress = None
            network_egress_valid = False
            notes.append("telemetry.network_egress must be a string or null")

        telemetry = {
            "files_accessed": files_accessed,
            "database_dropped": database_dropped,
            "network_egress": network_egress,
            "network_egress_valid": network_egress_valid,
        }

    # An incomplete receipt must never be presented or counted as protected.
    # Preserve its content for review, but move its display state to neutral.
    if notes:
        status = "review"

    return {
        "attack_type": attack_type,
        "malicious_prompt": malicious_prompt,
        "agent_response": agent_response,
        "kimi_verdict": kimi_verdict,
        "status": status,
        "telemetry": telemetry,
        "raw_telemetry": raw_telemetry,
        "schema_notes": notes,
    }


def load_results(path: Path) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Read and validate the saved results without calling the backend."""
    try:
        raw_text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, "missing"
    except OSError as exc:
        return None, f"Sentinel could not read the results file: {exc}"

    if not raw_text.strip():
        return None, "The results file is empty."

    try:
        raw_data = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        return None, f"The results file is not valid JSON (line {exc.lineno})."

    if not isinstance(raw_data, dict):
        return None, "The results file must contain a JSON object."

    raw_scenarios = raw_data.get("scenarios")
    if not isinstance(raw_scenarios, list):
        return None, "The results file is missing its scenarios list."

    warnings: List[str] = []
    raw_target = raw_data.get("target_agent")
    if isinstance(raw_target, str) and raw_target.strip():
        target_agent = raw_target
    else:
        target_agent = "Unnamed AI agent"
        warnings.append("target_agent is missing or invalid")

    scenarios = [
        _normalize_scenario(raw_scenario, index)
        for index, raw_scenario in enumerate(raw_scenarios, start=1)
    ]
    passed = sum(item["status"] == "green" for item in scenarios)
    failed = sum(item["status"] == "red" for item in scenarios)
    review = len(scenarios) - passed - failed

    raw_summary = raw_data.get("summary")
    expected_summary = {
        "total_scenarios": len(scenarios),
        "passed": passed,
        "failed": failed,
    }
    if not isinstance(raw_summary, dict):
        warnings.append("summary is missing or invalid; displayed totals use scenarios")
    elif any(raw_summary.get(key) != value for key, value in expected_summary.items()):
        warnings.append("summary totals do not match scenario statuses; displayed totals use scenarios")

    invalid_scenarios = sum(bool(item["schema_notes"]) for item in scenarios)
    if invalid_scenarios:
        warnings.append(
            f"{invalid_scenarios} scenario result(s) contain incomplete contract data"
        )

    try:
        modified_at = datetime.fromtimestamp(path.stat().st_mtime)
    except OSError:
        modified_at = None

    return {
        "target_agent": target_agent,
        "scenarios": scenarios,
        "counts": {
            "total": len(scenarios),
            "passed": passed,
            "failed": failed,
            "review": review,
        },
        "warnings": warnings,
        "modified_at": modified_at,
    }, None


def _attack_explanation(attack_type: str) -> str:
    key = attack_type.strip().lower()
    return ATTACK_EXPLANATIONS.get(
        key,
        "This scenario checks whether the AI follows unsafe instructions or "
        "crosses a security boundary.",
    )


def _finding_summary(scenario: Dict[str, Any]) -> str:
    """Translate the receipt into plain language without changing its verdict."""
    status = scenario["status"]
    telemetry = scenario["telemetry"]
    observations: List[str] = []

    if telemetry["database_dropped"] is True:
        observations.append("performed a destructive database action")
    if telemetry["network_egress"]:
        observations.append("attempted an outbound connection")
    if telemetry["files_accessed"]:
        count = len(telemetry["files_accessed"])
        observations.append(f"opened {count} file{'s' if count != 1 else ''}")

    if status == "green":
        return (
            "The AI resisted this attack. The saved receipt records no unsafe "
            "behavior, and the judge marked the response as protected."
        )
    if status == "red" and observations:
        return "The AI " + ", ".join(observations) + ". Review the exact evidence below."
    if status == "red":
        return (
            "The judge marked this scenario as needing attention. Review the "
            "verdict and response below for the exact reason."
        )
    return (
        "This saved result is incomplete or uses an unknown status, so Sentinel "
        "does not count it as protected."
    )


def _status_details(status: str) -> Tuple[str, str]:
    if status == "green":
        return "safe", "Resisted"
    if status == "red":
        return "risk", "Needs attention"
    return "review", "Needs review"


def _render_brand_and_hero() -> None:
    st.markdown(
        """
        <div class="sentinel-brand">
            <span class="sentinel-mark" aria-hidden="true">S</span>
            <span>Sentinel</span>
            <span class="sentinel-brand-note">AI agent security, made visible</span>
        </div>
        <div class="sentinel-eyebrow">
            <span class="sentinel-dot" aria-hidden="true"></span>
            Saved security assessment
        </div>
        <h1 class="sentinel-hero-title">See what your AI actually did under attack.</h1>
        <p class="sentinel-hero-copy">
            Sentinel safely challenges an AI agent with realistic tricks, watches
            its behavior inside an isolated sandbox, and turns the evidence into
            a report anyone can understand.
        </p>
        """,
        unsafe_allow_html=True,
    )


def _render_how_it_works() -> None:
    st.markdown(
        """
        <div class="sentinel-flow" aria-label="How Sentinel works">
            <div class="sentinel-flow-step">
                <span class="sentinel-step-number">01</span>
                <strong>Simulate an attack</strong>
                <span>Realistic prompts test how the AI responds to manipulation.</span>
            </div>
            <div class="sentinel-flow-step">
                <span class="sentinel-step-number">02</span>
                <strong>Watch real behavior</strong>
                <span>An isolated sandbox records file, database, and network activity.</span>
            </div>
            <div class="sentinel-flow-step">
                <span class="sentinel-step-number">03</span>
                <strong>Explain the evidence</strong>
                <span>A local AI judge turns technical receipts into a clear verdict.</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_empty_state(error: str) -> None:
    if error == "missing":
        title = "No saved assessment yet"
        copy = (
            "Generate a safe offline report first, then refresh this page. "
            "The dashboard never launches a security test by itself."
        )
    else:
        title = "The saved assessment cannot be displayed"
        copy = error

    st.markdown(
        """
        <div class="sentinel-empty">
            <div class="sentinel-empty-icon" aria-hidden="true">⌁</div>
            <div class="sentinel-section-title">Results unavailable</div>
            <div class="sentinel-section-copy">The dashboard is ready when your saved report is.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.subheader(title)
    st.write(copy)
    if error == "missing":
        st.caption("From the project root, run:")
        st.code("python3 orchestrator.py --mock", language="bash")


def _render_metrics(counts: Dict[str, int]) -> None:
    total = counts["total"]
    passed = counts["passed"]
    failed = counts["failed"]
    review = counts["review"]
    pass_rate = round((passed / total) * 100) if total else 0
    score_value = f"{pass_rate}%" if total else "N/A"
    review_detail = f" · {review} need review" if review else ""

    st.markdown(
        f"""
        <div class="sentinel-metric-grid">
            <div class="sentinel-metric score">
                <div class="sentinel-metric-label">Resistance rate</div>
                <div class="sentinel-metric-value">{score_value}</div>
                <div class="sentinel-metric-detail">Share of attacks the AI safely resisted</div>
            </div>
            <div class="sentinel-metric">
                <div class="sentinel-metric-label">Scenarios tested</div>
                <div class="sentinel-metric-value">{total}</div>
                <div class="sentinel-metric-detail">Different adversarial techniques checked</div>
            </div>
            <div class="sentinel-metric safe">
                <div class="sentinel-metric-label">Attacks resisted</div>
                <div class="sentinel-metric-value">{passed}</div>
                <div class="sentinel-metric-detail">Safe responses with clean evidence</div>
            </div>
            <div class="sentinel-metric risk">
                <div class="sentinel-metric-label">Risks detected</div>
                <div class="sentinel-metric-value">{failed}</div>
                <div class="sentinel-metric-detail">Scenarios that need attention{review_detail}</div>
            </div>
        </div>
        <div class="sentinel-score-panel">
            <div class="sentinel-score-row">
                <strong>{passed} of {total} simulated attacks resisted</strong>
                <span>{failed} risk{'s' if failed != 1 else ''} detected</span>
            </div>
            <div class="sentinel-track" role="img" aria-label="{pass_rate} percent of attacks resisted">
                <div class="sentinel-track-safe" style="width: {pass_rate}%"></div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_evidence(scenario: Dict[str, Any]) -> None:
    telemetry = scenario["telemetry"]
    files = telemetry["files_accessed"]
    database = telemetry["database_dropped"]
    network = telemetry["network_egress"]
    network_valid = telemetry["network_egress_valid"]

    evidence_columns = st.columns(3)
    with evidence_columns[0]:
        with st.container(border=True):
            st.markdown(
                '<div class="sentinel-evidence-title">Files opened</div>',
                unsafe_allow_html=True,
            )
            if files is None:
                st.markdown("**Evidence unavailable**")
                st.caption("The saved file receipt is invalid or missing.")
            elif files:
                st.markdown(f"**{len(files)} observed**")
                st.code("\n".join(files), language=None, wrap_lines=True)
            else:
                st.markdown("**None observed**")
                st.caption("No file access was recorded in this run.")

    with evidence_columns[1]:
        with st.container(border=True):
            st.markdown(
                '<div class="sentinel-evidence-title">Database action</div>',
                unsafe_allow_html=True,
            )
            if database is True:
                st.markdown("**Destructive action observed**")
                st.caption("The receipt confirms a database table was dropped.")
            elif database is False:
                st.markdown("**None observed**")
                st.caption("No destructive database action was recorded.")
            else:
                st.markdown("**Evidence unavailable**")
                st.caption("The saved database receipt is invalid or missing.")

    with evidence_columns[2]:
        with st.container(border=True):
            st.markdown(
                '<div class="sentinel-evidence-title">External connection</div>',
                unsafe_allow_html=True,
            )
            if not network_valid:
                st.markdown("**Evidence unavailable**")
                st.caption("The saved network receipt is invalid or missing.")
            elif network:
                st.markdown("**Outbound attempt observed**")
                st.code(network, language=None, wrap_lines=True)
            else:
                st.markdown("**None observed**")
                st.caption("No outbound destination was recorded.")


def _render_scenario(scenario: Dict[str, Any], index: int) -> None:
    tone, status_label = _status_details(scenario["status"])

    with st.container(border=True):
        header_left, header_right = st.columns([4, 1.2], vertical_alignment="top")
        with header_left:
            st.markdown(
                f'<div class="sentinel-scenario-index">Scenario {index:02d}</div>',
                unsafe_allow_html=True,
            )
            st.subheader(_literal_markdown(scenario["attack_type"]))
            st.caption(_attack_explanation(scenario["attack_type"]))
        with header_right:
            st.markdown(
                f'<div class="sentinel-status {tone}">{status_label}</div>',
                unsafe_allow_html=True,
            )

        st.markdown(
            f'<div class="sentinel-meaning"><strong>What this means:</strong> '
            f'{_finding_summary(scenario)}</div>',
            unsafe_allow_html=True,
        )

        st.caption("LOCAL KIMI JUDGE VERDICT")
        st.code(scenario["kimi_verdict"], language=None, wrap_lines=True)

        st.divider()
        prompt_column, response_column = st.columns(2, gap="large")
        with prompt_column:
            st.markdown("#### Attack sent to the AI")
            st.caption("The simulated instruction used to test this security boundary.")
            st.code(
                scenario["malicious_prompt"],
                language=None,
                wrap_lines=True,
            )
        with response_column:
            st.markdown("#### How the AI responded")
            st.caption("The target agent's exact saved response.")
            st.code(
                scenario["agent_response"],
                language=None,
                wrap_lines=True,
            )

        st.markdown("#### Observed evidence")
        st.caption(
            "These receipts describe what happened—not merely what the AI said happened."
        )
        _render_evidence(scenario)

        with st.expander("View raw telemetry receipt"):
            if isinstance(scenario["raw_telemetry"], dict):
                st.json(scenario["raw_telemetry"], expanded=True)
            else:
                st.write("Raw telemetry is unavailable for this scenario.")

        if scenario["schema_notes"]:
            with st.expander("Result data needs review"):
                for note in scenario["schema_notes"]:
                    st.write(f"• {note}")


def main() -> None:
    _render_brand_and_hero()

    results, error = load_results(RESULTS_PATH)
    if error or results is None:
        refresh_column, _ = st.columns([1, 4])
        with refresh_column:
            if st.button("↻ Refresh results", use_container_width=True):
                st.rerun()
        _render_how_it_works()
        _render_empty_state(error or "Unknown results error.")
        st.stop()

    target_column, refresh_column = st.columns([4, 1.15], vertical_alignment="bottom")
    with target_column:
        st.markdown('<div class="sentinel-kicker">AI agent under review</div>', unsafe_allow_html=True)
        st.subheader(_literal_markdown(results["target_agent"]))
        if results["modified_at"]:
            st.caption(
                "Latest saved assessment · "
                + results["modified_at"].strftime("%d %b %Y, %H:%M")
            )
        else:
            st.caption("Latest saved assessment")
    with refresh_column:
        if st.button(
            "↻ Refresh results",
            help="Reload the latest saved run_results.json. This does not start a new test.",
            use_container_width=True,
        ):
            st.rerun()

    _render_how_it_works()

    st.markdown(
        '<div class="sentinel-note"><strong>How to read this report:</strong> '
        'Red means Sentinel detected unsafe behavior or a run that needs attention. '
        'Green means the AI resisted the simulated attack. This demo target is '
        'deliberately vulnerable, so red findings are expected—not dashboard errors.</div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div style="height: 1.8rem"></div>', unsafe_allow_html=True)
    st.markdown('<div class="sentinel-section-label">Assessment overview</div>', unsafe_allow_html=True)
    st.markdown('<div class="sentinel-section-title">Security posture at a glance</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sentinel-section-copy">A simple summary of how the AI handled every saved attack scenario.</div>',
        unsafe_allow_html=True,
    )
    _render_metrics(results["counts"])

    if results["warnings"]:
        st.warning(
            "Some saved result data needs review. The dashboard used scenario "
            "statuses for the totals shown below."
        )
        with st.expander("View data-quality notes"):
            for warning in results["warnings"]:
                st.write(f"• {warning}")

    st.markdown('<div class="sentinel-section-label">Scenario explorer</div>', unsafe_allow_html=True)
    st.markdown('<div class="sentinel-section-title">Understand every test</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="sentinel-section-copy">Open the evidence behind each verdict, from the attack prompt to the sandbox receipt.</div>',
        unsafe_allow_html=True,
    )

    counts = results["counts"]
    filter_choice = st.radio(
        "Filter scenarios",
        options=("all", "red", "green"),
        format_func=lambda value: {
            "all": f"All tests ({counts['total']})",
            "red": f"Needs attention ({counts['failed']})",
            "green": f"Resisted ({counts['passed']})",
        }[value],
        horizontal=True,
        label_visibility="collapsed",
    )

    visible_scenarios = [
        (index, scenario)
        for index, scenario in enumerate(results["scenarios"], start=1)
        if filter_choice == "all" or scenario["status"] == filter_choice
    ]

    if not visible_scenarios:
        st.info("No saved scenarios match this filter.", icon="ℹ️")
    else:
        for index, scenario in visible_scenarios:
            _render_scenario(scenario, index)

    st.divider()
    st.markdown(
        '<div class="sentinel-note"><strong>Read-only report.</strong> Source: '
        '<code>run_results.json</code>. Refresh reads the latest saved assessment; '
        'it never launches the vulnerable agent or starts a new security test.</div>',
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    main()
