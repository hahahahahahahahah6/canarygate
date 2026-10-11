"""Load and normalize hook configurations.

Primary input: a Claude Code ``settings.json`` (or ``.claude/settings.json``)
``hooks`` section::

    {
      "hooks": {
        "PreToolUse": [
          {"matcher": "Bash",
           "hooks": [{"type": "command", "command": "python3 .claude/hooks/guard.py"}]}
        ],
        "Stop": [
          {"matcher": "", "hooks": [{"type": "command", "command": "./hooks/review.sh"}]}
        ]
      }
    }

Every (event, matcher, command) triple becomes one :class:`HookSpec` that
canarygate probes independently.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class HookSpec:
    """One configured hook command, ready to be probed."""

    name: str            # e.g. "PreToolUse[Bash]#0"
    event: str           # hook event name, e.g. "PreToolUse"
    matcher: str         # regex matched against the tool name (may be "")
    command: str         # shell command run for the hook
    source: str = ""     # settings file path, for reporting
    raw: dict = field(default_factory=dict)


class ConfigError(Exception):
    """The settings file is missing or unusable."""


def load_settings(path: str | Path) -> list[HookSpec]:
    """Parse a settings.json file into a list of HookSpec."""
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"settings file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{p}: invalid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{p}: top-level JSON must be an object")
    return normalize(data.get("hooks", {}), source=str(p))


def load_generic(hooks: list[dict], source: str = "<inline>") -> list[HookSpec]:
    """Build HookSpecs from a plain list of {event, matcher, command} dicts."""
    return normalize(_generic_to_sections(hooks), source=source)


def _generic_to_sections(hooks: list[dict]) -> dict:
    sections: dict[str, list[dict]] = {}
    for entry in hooks:
        if not isinstance(entry, dict):
            continue
        sections.setdefault(entry.get("event", "PreToolUse"), []).append(entry)
    return sections


def normalize(sections: dict, source: str = "") -> list[HookSpec]:
    """Flatten the ``hooks`` section into HookSpecs."""
    specs: list[HookSpec] = []
    if not isinstance(sections, dict):
        raise ConfigError(f"{source}: 'hooks' section must be an object")
    for event, entries in sections.items():
        if not isinstance(entries, list):
            raise ConfigError(f"{source}: hooks[{event!r}] must be a list")
        for i, entry in enumerate(entries):
            if not isinstance(entry, dict):
                raise ConfigError(f"{source}: hooks[{event!r}][{i}] must be an object")
            matcher = entry.get("matcher", "")
            for j, hook in enumerate(entry.get("hooks", [])):
                if not isinstance(hook, dict):
                    raise ConfigError(
                        f"{source}: hooks[{event!r}][{i}].hooks[{j}] must be an object"
                    )
                command = hook.get("command", "")
                name = f"{event}[{matcher or '*'}]#{j}"
                specs.append(
                    HookSpec(
                        name=name,
                        event=event,
                        matcher=str(matcher or ""),
                        command=str(command or ""),
                        source=source,
                        raw=hook,
                    )
                )
    return specs
