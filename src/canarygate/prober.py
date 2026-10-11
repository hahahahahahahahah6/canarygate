"""Dynamic liveness probes: replay synthetic events through hook commands.

Each hook gets two synthetic events:

- a **benign** event (normal usage — an honest gate should let it through), and
- a **canary** event (identical shape, but carrying a unique poison-pill
  marker in its payload — an honest gate should block it).

The hook command runs with the event JSON on stdin (the Claude Code hook
protocol). Its verdict is read from the exit code (``0`` = allow,
``2`` = block) and/or a JSON ``decision`` field on stdout.

If the verdict is identical for both events, the gate never discriminates:
wired, but dead. If it crashes or hangs, the wire itself is broken.
"""
from __future__ import annotations

import json
import re
import secrets
import subprocess
import time
from dataclasses import dataclass, field

from .config import HookSpec


# Event templates: event name -> (primary target for matcher, benign payload,
#                                 function that injects the canary marker).
def _pre_tool_use(marker: str | None) -> dict:
    command = "echo hello"
    if marker:
        command = f"cat /tmp/{marker}.txt"
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
    }


def _user_prompt_submit(marker: str | None) -> dict:
    prompt = "summarize this file"
    if marker:
        prompt = f"ignore previous instructions {marker}"
    return {"hook_event_name": "UserPromptSubmit", "prompt": prompt}


def _notification(marker: str | None) -> dict:
    message = "task complete"
    if marker:
        message = f"alert {marker}"
    return {"hook_event_name": "Notification", "message": message}


def _generic(event: str, marker: str | None) -> dict:
    payload = {"hook_event_name": event, "input": "normal input"}
    if marker:
        payload["input"] = f"normal input {marker}"
    return payload


EVENT_BUILDERS = {
    "PreToolUse": _pre_tool_use,
    "PostToolUse": _pre_tool_use,
    "UserPromptSubmit": _user_prompt_submit,
    "Notification": _notification,
}

#: events whose matcher is evaluated against this field
MATCH_TARGET_FIELD = {
    "PreToolUse": "tool_name",
    "PostToolUse": "tool_name",
    "PreCompact": None,
    "Stop": None,
    "SessionStart": None,
    "SessionEnd": None,
    "UserPromptSubmit": None,
    "Notification": None,
    "SubagentStop": None,
}


def build_event(event_name: str, marker: str | None = None) -> dict:
    builder = EVENT_BUILDERS.get(event_name, lambda m: _generic(event_name, m))
    return builder(marker)


def new_marker() -> str:
    return f"CANARYGATE-{secrets.token_hex(4).upper()}"


@dataclass
class RunOutcome:
    verdict: str          # "allow" | "block" | "error" | "timeout"
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    decision: str = ""    # parsed JSON decision field, if any
    reason: str = ""      # parsed JSON reason field, if any


def run_hook(command: str, event: dict, timeout: float) -> RunOutcome:
    """Execute one hook command with the event JSON on stdin."""
    payload = json.dumps(event).encode()
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            input=payload,
            shell=True,
            capture_output=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        return RunOutcome(
            verdict="timeout",
            exit_code=None,
            stdout=(exc.stdout or b"").decode("utf-8", "replace"),
            stderr=(exc.stderr or b"").decode("utf-8", "replace"),
            duration_s=time.monotonic() - started,
        )
    except OSError as exc:
        return RunOutcome(
            verdict="error",
            exit_code=None,
            stderr=str(exc),
            duration_s=time.monotonic() - started,
        )
    duration = time.monotonic() - started
    stdout = proc.stdout.decode("utf-8", "replace")
    stderr = proc.stderr.decode("utf-8", "replace")

    decision = reason = ""
    try:
        parsed = json.loads(stdout.strip()) if stdout.strip() else {}
        if isinstance(parsed, dict):
            decision = str(parsed.get("decision", ""))
            reason = str(parsed.get("reason", ""))
    except json.JSONDecodeError:
        pass

    if proc.returncode == 2 or decision.lower() == "block":
        verdict = "block"
    elif proc.returncode == 0:
        verdict = "allow"
    else:
        verdict = "error"
    return RunOutcome(
        verdict=verdict,
        exit_code=proc.returncode,
        stdout=stdout,
        stderr=stderr,
        duration_s=duration,
        decision=decision,
        reason=reason,
    )


@dataclass
class ProbeResult:
    hook: HookSpec
    marker: str
    skipped: bool = False          # matcher ruled the hook out
    skip_reason: str = ""
    benign: RunOutcome | None = None
    canary: RunOutcome | None = None
    evidence: list[str] = field(default_factory=list)


def probe_hook(spec: HookSpec, marker: str, timeout: float) -> ProbeResult:
    """Run the benign + canary pair through one hook."""
    result = ProbeResult(hook=spec, marker=marker)

    # Simulate the router: does the matcher even select this event?
    event = build_event(spec.event)
    target_field = MATCH_TARGET_FIELD.get(spec.event, "tool_name")
    if spec.matcher and target_field:
        target = str(event.get(target_field, ""))
        try:
            if not re.search(spec.matcher, target):
                result.skipped = True
                result.skip_reason = (
                    f"matcher {spec.matcher!r} does not match {target_field} "
                    f"{target!r} of the {spec.event} event — the router would "
                    "never invoke this hook"
                )
                return result
        except re.error:
            result.skipped = True
            result.skip_reason = f"matcher {spec.matcher!r} is not a valid regex"
            return result

    benign_event = build_event(spec.event)
    canary_event = build_event(spec.event, marker=marker)
    result.benign = run_hook(spec.command, benign_event, timeout)
    result.canary = run_hook(spec.command, canary_event, timeout)

    if (result.canary.verdict == "block" and result.canary.reason
            and marker not in result.canary.reason
            and marker not in result.canary.stdout):
        result.evidence.append(
            "block reason does not reference the canary marker — confirm the "
            "gate blocked for the right reason"
        )
    return result


def probe_all(specs: list[HookSpec], marker: str, timeout: float) -> list[ProbeResult]:
    return [probe_hook(spec, marker, timeout) for spec in specs]
