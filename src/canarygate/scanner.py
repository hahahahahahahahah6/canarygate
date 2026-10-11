"""Static wiring analysis: does the hook entry look like it can ever fire?

A hook can be dead before it ever runs:

- ``command`` is empty or points at a binary/script that does not exist
  (typo'd path, uninstalled tool, moved script);
- ``matcher`` is not a valid regex;
- ``matcher`` never matches the event it is registered for (typo'd tool
  name, over-narrow pattern) — the router will silently skip the hook;
- the script itself is an unconditional ``approve`` (no blocking branch at
  all), so it can never discriminate.

These are heuristics over config text plus light script inspection; the
dynamic proof comes from :mod:`canarygate.prober`.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from .config import HookSpec


@dataclass
class Finding:
    severity: str   # "error" | "warning" | "info"
    code: str       # machine-readable, e.g. "command-not-found"
    message: str    # human-readable explanation
    fix: str = ""   # suggested remediation


def _resolve_command(command: str, base_dir: Path) -> tuple[bool, str]:
    """Best-effort check that the command's executable part exists.

    Returns (ok, detail). Never executes anything.
    """
    if not command or not command.strip():
        return False, "command is empty"
    try:
        parts = shlex.split(command, posix=True)
    except ValueError as exc:
        return False, f"cannot parse command: {exc}"
    if not parts:
        return False, "command is empty"

    exe = parts[0]
    # `python3 -m module ...` — module existence is checked at probe time
    if exe in ("python", "python3") and len(parts) > 2 and parts[1] == "-m":
        mod = parts[2]
        return True, f"python -m {mod} (checked at probe time)"
    # if a later token looks like a script path, that file must exist —
    # `python3 /missing/gate.py` is a broken wire even though python3 is fine
    script_tok = None
    for tok in parts[1:]:
        if tok.startswith("-"):
            continue
        if "/" in tok or "\\" in tok or tok.endswith((".py", ".sh", ".js", ".ts", ".rb")):
            script_tok = tok
            break
    if script_tok is not None:
        for cand in (Path(script_tok), base_dir / script_tok):
            if cand.is_file():
                return True, f"script file: {cand}"
        return False, f"script file not found: {script_tok}"
    # absolute or relative path to an executable script
    if "/" in exe or "\\" in exe:
        for cand in (Path(exe), base_dir / exe):
            if cand.is_file():
                return True, f"script file: {cand}"
        return False, f"script file not found: {exe}"
    # bare executable name -> search PATH
    import shutil

    found = shutil.which(exe)
    if found:
        return True, f"found on PATH: {found}"
    return False, f"executable not on PATH: {exe}"


def _inspect_script(command: str, base_dir: Path) -> list[Finding]:
    """Heuristic read of the hook script looking for 'never discriminates'."""
    findings: list[Finding] = []
    try:
        parts = shlex.split(command, posix=True)
    except ValueError:
        return findings
    script_path: Path | None = None
    for tok in parts:
        for cand in (Path(tok), base_dir / tok):
            if cand.is_file() and cand.suffix in (".py", ".sh", ".js", ".ts", ".rb"):
                script_path = cand
                break
        if script_path:
            break
    if script_path is None:
        return findings
    try:
        text = script_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    has_block_branch = bool(
        re.search(r"sys\.exit\(\s*2\s*\)|exit\s+2|['\"]decision['\"]\s*:\s*['\"]block['\"]"
                  r"|\bdeny\b|\breject\b", text, re.IGNORECASE)
    )
    has_condition = bool(re.search(r"^\s*(if|elif|case|when)\b", text, re.MULTILINE))
    always_approve = bool(
        re.search(r"['\"]decision['\"]\s*:\s*['\"]approve['\"]", text)
    ) or re.search(r"sys\.exit\(\s*0\s*\)\s*$", text, re.MULTILINE)

    if always_approve and not has_block_branch:
        findings.append(
            Finding(
                severity="warning",
                code="static-unconditional-approve",
                message=(
                    f"{script_path}: appears to always approve — no blocking "
                    "branch found in the script."
                ),
                fix=("Add a branch that blocks/denies when the gate's condition "
                     "is met, and re-run `canarygate probe` to confirm it fires."),
            )
        )
    elif not has_condition and not has_block_branch:
        findings.append(
            Finding(
                severity="info",
                code="static-no-branches",
                message=(
                    f"{script_path}: no conditional logic detected; verify it "
                    "can actually discriminate."
                ),
                fix="Re-run with `canarygate probe` — the canary test is the proof.",
            )
        )
    return findings


def scan_hook(spec: HookSpec) -> list[Finding]:
    """Static checks for one hook spec."""
    findings: list[Finding] = []
    base_dir = Path(spec.source).parent if spec.source else Path.cwd()

    # 1. command wiring
    ok, detail = _resolve_command(spec.command, base_dir)
    if not ok:
        findings.append(
            Finding(
                severity="error",
                code="command-not-found",
                message=f"{spec.name}: {detail}",
                fix=("Fix the command path, install the missing tool, or remove "
                     "the hook entry if it is stale."),
            )
        )

    # 2. matcher validity
    try:
        pattern = re.compile(spec.matcher) if spec.matcher else None
    except re.error as exc:
        findings.append(
            Finding(
                severity="error",
                code="matcher-invalid-regex",
                message=f"{spec.name}: matcher is not a valid regex: {exc}",
                fix="Fix the regex so the router can evaluate it.",
            )
        )
        pattern = None

    if pattern is None and not spec.matcher:
        findings.append(
            Finding(
                severity="info",
                code="matcher-catch-all",
                message=f"{spec.name}: empty matcher — hook fires on every {spec.event} event.",
                fix="Narrow the matcher if the gate is meant for specific tools only.",
            )
        )

    # 3. script heuristics
    findings.extend(_inspect_script(spec.command, base_dir))
    return findings


def scan_all(specs: list[HookSpec]) -> dict[str, list[Finding]]:
    """Static scan of every hook spec, keyed by hook name."""
    return {spec.name: scan_hook(spec) for spec in specs}
