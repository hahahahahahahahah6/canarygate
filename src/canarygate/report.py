"""Report rendering: human text table and machine-readable JSON."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .analyzer import ALIVE, DEAD, GateResult


STATUS_GLYPH = {ALIVE: "OK", DEAD: "DEAD", "OVERFIRE": "OVER", "MISCONFIGURED": "CFG!"}


def text_report(results: list[GateResult], marker: str) -> str:
    lines: list[str] = []
    lines.append("canarygate liveness report")
    lines.append(f"canary marker: {marker}")
    lines.append("")
    lines.append(f"{'HOOK':<32} {'STATUS':<14} EVIDENCE")
    lines.append("-" * 78)
    for res in results:
        glyph = STATUS_GLYPH.get(res.status, "?")
        first = res.evidence[0] if res.evidence else "-"
        lines.append(f"{res.hook.name:<32} {glyph:<14} {first[:60]}")
        for extra in res.evidence[1:]:
            lines.append(f"{'':<48} {extra[:60]}")
        for warn in res.warnings:
            lines.append(f"{'':<48} ! {warn[:58]}")
    lines.append("")
    dead = [r for r in results if r.status != ALIVE]
    if dead:
        lines.append(f"{len(dead)} of {len(results)} gate(s) need attention:")
        for res in dead:
            lines.append(f"  * {res.hook.name} [{res.status}]")
            for fix in res.fixes:
                lines.append(f"      fix: {fix}")
    else:
        lines.append(f"All {len(results)} gate(s) alive.")
    return "\n".join(lines) + "\n"


def json_report(results: list[GateResult], marker: str, settings: str) -> str:
    payload = {
        "tool": "canarygate",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "settings": settings,
        "canary_marker": marker,
        "summary": {
            "total": len(results),
            "alive": sum(1 for r in results if r.status == ALIVE),
            "dead": sum(1 for r in results if r.status == DEAD),
            "needs_attention": sum(1 for r in results if r.status != ALIVE),
        },
        "gates": [
            {
                "name": r.hook.name,
                "event": r.hook.event,
                "matcher": r.hook.matcher,
                "command": r.hook.command,
                "status": r.status,
                "evidence": r.evidence,
                "fixes": r.fixes,
                "warnings": r.warnings,
            }
            for r in results
        ],
    }
    return json.dumps(payload, indent=2) + "\n"
