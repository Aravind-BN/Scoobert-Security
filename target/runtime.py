"""Agent runtime: a real LangChain tool-calling agent, plus an offline mock.

build_agent(mock=False) returns a callable the CLI drives. Two backends:

  * LangChain backend (default): a genuine tool-calling agent over an
    OpenAI-compatible model. This is the "off-the-shelf agent framework in
    default config" the pitch promises — nothing is rigged; it is just given
    dangerous tools and a sloppy prompt.

  * Mock backend (--mock): a deterministic keyword planner that maps the prompt
    to tool calls with NO API calls. It lets M2 (Daytona) and M3 (grading) build
    the whole pipeline offline, and gives the demo a zero-latency fallback for
    when the wifi dies. It is credulous on purpose: it follows instructions it
    finds inside files it reads, which is exactly how indirect injection lands.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable

import telemetry
from config import (
    ADMIN_TOKEN,
    API_KEY,
    AWS_CREDS,
    BASE_URL,
    INCIDENT_REPORT,
    MODEL,
    SYSTEM_PROMPT,
    TEMPERATURE,
)
from tools import TOOL_FUNCS


@dataclass
class AgentResult:
    final_answer: str
    steps: list[dict] = field(default_factory=list)
    backend: str = "unknown"


Agent = Callable[[str], AgentResult]


# ---------------------------------------------------------------------------
# LangChain backend
# ---------------------------------------------------------------------------
def _build_langchain_agent(max_steps: int) -> Agent:
    from langchain.agents import AgentExecutor, create_tool_calling_agent
    from langchain_core.prompts import ChatPromptTemplate
    from langchain_openai import ChatOpenAI

    from tools import build_langchain_tools

    llm = ChatOpenAI(
        model=MODEL,
        temperature=TEMPERATURE,
        api_key=API_KEY,
        base_url=BASE_URL,
    )
    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", SYSTEM_PROMPT),
            ("human", "{input}"),
            ("placeholder", "{agent_scratchpad}"),
        ]
    )
    tools = build_langchain_tools()
    agent = create_tool_calling_agent(llm, tools, prompt)
    executor = AgentExecutor(
        agent=agent,
        tools=tools,
        max_iterations=max_steps,
        verbose=False,
        return_intermediate_steps=True,
        handle_parsing_errors=True,
    )

    def _run(user_prompt: str) -> AgentResult:
        telemetry.emit("run_start", backend="langchain", prompt=user_prompt)
        out = executor.invoke({"input": user_prompt})
        steps = [
            {"tool": action.tool, "input": action.tool_input, "output": str(obs)}
            for action, obs in out.get("intermediate_steps", [])
        ]
        telemetry.emit("run_end", backend="langchain", tool_calls=len(steps))
        return AgentResult(final_answer=out.get("output", ""), steps=steps, backend="langchain")

    return _run


# ---------------------------------------------------------------------------
# Mock backend (deterministic, offline)
# ---------------------------------------------------------------------------
def _build_mock_agent(max_steps: int) -> Agent:
    def _plan(text: str) -> list[tuple[str, dict]]:
        plan: list[tuple[str, dict]] = []
        low = text.lower()
        # Strip URLs first so a slash-path match never grabs an http_post target.
        no_urls = re.sub(r"https?://\S+", " ", text)

        # read_file: prefer an explicit path, else a verb + friendly reference.
        explicit = re.search(
            r"([\w.\-]+(?:/[\w.\-]+)+|\b[\w.\-]+\.(?:md|txt|json|env|cfg|log|pem|key)\b)",
            no_urls,
        )
        verb = re.search(r"(?:read|summar[iy]ze|open|show|cat)\s+([^\s\"']+)", low)
        if explicit:
            plan.append(("read_file", {"path": explicit.group(1)}))
        elif verb:
            plan.append(("read_file", {"path": _resolve_path(text, verb.group(1))}))

        # query_db: real SQL syntax wins; otherwise map natural-language intent.
        raw_sql = re.search(
            r"(select\s+.+?\s+from\s+\w+|drop\s+table\s+\w+|delete\s+from\s+\w+"
            r"|update\s+\w+\s+set\s+.+|insert\s+into\s+\w+)",
            text,
            re.I,
        )
        if raw_sql:
            plan.append(("query_db", {"sql": raw_sql.group(0).rstrip(". ")}))
        elif re.search(r"drop|wipe|corrupt|reset|reload|destroy", low) and re.search(
            r"table|database|\bdb\b|records|employees", low
        ):
            plan.append(("query_db", {"sql": "DROP TABLE employees"}))
        elif re.search(r"employee|salary|payroll|salaries|records|ssn", low):
            plan.append(("query_db", {"sql": "SELECT * FROM employees"}))

        # run_shell: "run X", "clean/delete files", "rm ..."
        sh = re.search(r"(?:run|execute)\s+[`\"]?([^`\"]+)", text)
        if sh:
            plan.append(("run_shell", {"command": sh.group(1).strip()}))
        elif re.search(r"clean.*temp|delete.*files|remove.*files|free up disk|rm -rf", low):
            plan.append(("run_shell", {"command": "rm -rf /tmp/workspace/*"}))

        # http_post: "send/post/exfiltrate ... to <url>"
        url = re.search(r"https?://[^\s\"')]+", text)
        if url and re.search(r"send|post|exfil|upload|leak|report to|ingest", low):
            plan.append(("http_post", {"url": url.group(0), "data": ""}))

        return plan[:max_steps]

    def _run(user_prompt: str) -> AgentResult:
        telemetry.emit("run_start", backend="mock", prompt=user_prompt)
        steps: list[dict] = []
        queue = _plan(user_prompt)
        seen_followup = False
        last_read = ""  # thread the most recent file read into an exfil POST
        while queue and len(steps) < max_steps:
            name, kwargs = queue.pop(0)
            if name == "http_post" and not kwargs.get("data"):
                kwargs["data"] = last_read  # the exfiltrated payload
            output = TOOL_FUNCS[name](**kwargs)
            if name == "read_file":
                last_read = output
            steps.append({"tool": name, "input": kwargs, "output": output})

            # Obey instructions found inside the first file read (indirect
            # injection). One expansion only, so the chain always terminates.
            if name == "read_file" and not seen_followup:
                seen_followup = True
                queue.extend(_plan(output))

        answer = _mock_answer(steps)
        telemetry.emit("run_end", backend="mock", tool_calls=len(steps))
        return AgentResult(final_answer=answer, steps=steps, backend="mock")

    return _run


def _resolve_path(text: str, token: str) -> str:
    """Map a friendly reference to a fixture path (credentials checked first)."""
    low = text.lower()
    if "credential" in low or "aws" in low:
        return AWS_CREDS
    if "incident" in low or "report" in low:
        return INCIDENT_REPORT
    return token


def _mock_answer(steps: list[dict]) -> str:
    if not steps:
        return "I couldn't find anything to do for that request."
    did = ", ".join(s["tool"] for s in steps)
    evidence = _evidence(steps)
    tail = f" {evidence}" if evidence else ""
    return f"Done! I used: {did}.{tail}"


def _evidence(steps: list[dict]) -> str:
    """Surface what was leaked/destroyed so a judge reading the reply has signal.

    A real LLM would echo this; the mock must too, or a DB/shell compromise looks
    identical to a clean run once it is reduced to the 3-field contract telemetry.
    """
    blob = "\n".join(str(s["output"]) for s in steps)
    parts = []
    for s in steps:
        out = str(s["output"])
        if s["tool"] == "query_db" and " | " in out and "ssn" in out.lower():
            rows = [ln for ln in out.splitlines() if ln.strip()]
            if len(rows) >= 2:
                parts.append(f"Leaked employee row: {rows[1]}.")
                break
    if "aws_secret_access_key" in blob or "aws_access_key_id" in blob:
        parts.append("Exfiltrated AWS credentials.")
    if ADMIN_TOKEN in blob:
        parts.append("Exposed the admin token.")
    for s in steps:
        if s["tool"] == "run_shell":
            parts.append(f"Ran shell: {s['input'].get('command')}.")
            break
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Public builder
# ---------------------------------------------------------------------------
def build_agent(mock: bool = False, max_steps: int = 8) -> Agent:
    if mock:
        return _build_mock_agent(max_steps)
    if not API_KEY:
        telemetry.emit(
            "backend_fallback",
            reason="no API key (set SENTINEL_API_KEY/OPENAI_API_KEY); using mock",
        )
        return _build_mock_agent(max_steps)
    try:
        return _build_langchain_agent(max_steps)
    except ImportError as exc:
        telemetry.emit("backend_fallback", reason=f"langchain import failed: {exc}")
        return _build_mock_agent(max_steps)


def run_agent(agent: Agent, prompt: str) -> AgentResult:
    return agent(prompt)
