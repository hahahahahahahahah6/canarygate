"""Verdict synthesis: static findings + probe outcomes -> one gate status.

Statuses:

- ``ALIVE`` — the gate discriminated: benign allowed, canary blocked.
- ``WIRED-BUT-DEAD`` — the config is legal but the gate never actually
  protects: the matcher never selects the event, the command cannot run, or
  the hook returns the same verdict for benign and canary events.
- ``OVERFIRE`` — blocks the benign event too; a gate that blocks everything
  will be disabled by its users, which is a slow form of death.
- ``MISCONFIGURED`` — the entry itself is broken (empty command, bad JSON
  shape, invalid regex).

Every result carries the concrete evidence and a fix suggestion, because a
red verdict without a next step is just anxiety.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .config import HookSpec
from .prober import ProbeResult
from .scanner import Finding

ALIVE = "ALIVE"
DEAD = "WIRED-BUT-DEAD"
OVERFIRE = "OVERFIRE"
MISCONFIGURED = "MISCONFIGURED"


@dataclass
class GateResult:
    hook: HookSpec
    status: str
    evidence: list[str] = field(default_factory=list)
    fixes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            out.append(item)
    return out


def analyze(spec: HookSpec, findings: list[Finding], probe: ProbeResult) -> GateResult:
    evidence: list[str] = []
    fixes: list[str] = []
    warnings: list[str] = []

    for finding in findings:
        if finding.severity == "error":
            evidence.append(finding.message)
            if finding.fix:
                fixes.append(finding.fix)
        elif finding.severity == "warning":
            warnings.append(finding.message)
            if finding.fix:
                fixes.append(finding.fix)
        else:
            warnings.append(finding.message)

    # Fatal static problems decide the verdict on their own.
    static_errors = [f for f in findings if f.severity == "error"]
    if static_errors:
        first = static_errors[0]
        if first.code == "command-not-found":
            status = DEAD
        elif first.code in ("matcher-invalid-regex",):
            status = MISCONFIGURED
        else:
            status = DEAD
        return GateResult(spec, status, _dedupe(evidence), _dedupe(fixes), _dedupe(warnings))

    if probe.skipped:
        return GateResult(
            spec,
            DEAD,
            [probe.skip_reason],
            ["Fix the matcher (or the event registration) so the canary event "
             "actually routes to this hook."],
            _dedupe(warnings),
        )

    benign = probe.benign
    canary = probe.canary
    assert benign is not None and canary is not None

    # Broken wire: the hook cannot even run to completion.
    for label, outcome in (("benign", benign), ("canary", canary)):
        if outcome.verdict == "timeout":
            return GateResult(
                spec, DEAD,
                [f"hook timed out on the {label} event — it never produced a verdict"],
                ["Check for blocking stdin reads or network calls in the hook; "
                 "a hook must answer quickly or the runner gives up on it."],
                _dedupe(warnings),
            )
        if outcome.verdict == "error":
            detail = (outcome.stderr.strip() or outcome.stdout.strip() or
                      f"exit code {outcome.exit_code}")
            return GateResult(
                spec, DEAD,
                [f"hook crashed on the {label} event: {detail[:300]}"],
                ["Run the hook command by hand with a sample event JSON on stdin "
                 "and fix the crash; a hook that exits non-zero protects nothing."],
                _dedupe(warnings),
            )

    if benign.verdict == "block" and canary.verdict == "block":
        return GateResult(
            spec, OVERFIRE,
            ["hook blocked the benign event too — it discriminates nothing, "
             "it just says no"],
            ["Narrow the gate's condition so normal usage passes; an "
             "always-no gate gets disabled, which is death by another name."],
            _dedupe(warnings),
        )

    if benign.verdict == "block" and canary.verdict == "allow":
        return GateResult(
            spec, OVERFIRE,
            ["hook blocked the benign event but allowed the canary — the gate "
             "is inverted"],
            ["The gate's condition is backwards: swap the allow/block branches "
             "and re-probe."],
            _dedupe(warnings),
        )

    if canary.verdict == "allow":
        # benign allowed, canary allowed -> never discriminates
        return GateResult(
            spec, DEAD,
            ["hook returned 'allow' for both the benign event and the canary "
             f"event carrying marker {probe.marker} — it never discriminates"],
            ["Make the hook inspect its input and block when it sees the "
             "condition it exists for; then re-run `canarygate probe` until "
             "the canary is blocked."],
            _dedupe(warnings + probe.evidence),
        )

    # canary blocked, benign allowed -> alive
    evidence.append(
        f"benign event allowed in {benign.duration_s:.2f}s, canary event blocked "
        f"in {canary.duration_s:.2f}s"
    )
    warnings.extend(probe.evidence)
    return GateResult(spec, ALIVE, _dedupe(evidence), _dedupe(fixes), _dedupe(warnings))


def analyze_all(specs: list[HookSpec],
                findings: dict[str, list[Finding]],
                probes: list[ProbeResult]) -> list[GateResult]:
    probe_by_name = {p.hook.name: p for p in probes}
    return [
        analyze(spec, findings.get(spec.name, []), probe_by_name[spec.name])
        for spec in specs
    ]
