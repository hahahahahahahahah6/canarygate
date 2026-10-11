# canarygate

A hook/gate **liveness validator**. It replays synthetic benign and canary (poison-pill) events through every hook in your `settings.json` and tells you which gates are **wired-but-dead**: the config is legal, the dashboard is green, but the gate never actually fires.

> The motivating case, from a real dev.to postmortem by yuhaolin2005: *"A gate that has quietly stopped discriminating is worse than no gate, because it still prints a verdict."* Their hook returned green on every run — and had not actually executed in weeks.

## Install

```bash
pip install canarygate
```

Zero dependencies — stdlib only. Requires Python 3.9+.

## Usage

```bash
# Full check: static wiring scan + canary probes for every hook
canarygate run --settings ~/.claude/settings.json

# Static wiring analysis only (no hook execution)
canarygate scan --settings settings.json

# Probe a single hook
canarygate probe --settings settings.json --hook 'PreToolUse[Bash]#0'

# Machine-readable report for CI
canarygate run --settings settings.json --format json > gates.json

# Scaffold an example project (one alive gate, one dead gate) to try it on
canarygate init
```

Exit codes are CI-friendly: `0` = all gates alive, `1` = a gate needs attention, `2` = fatal error (e.g. unreadable config).

### How it works

1. **Scan (static).** Each `(event, matcher, command)` triple in the `hooks` section is checked: does the command resolve (binary on PATH, script file exists)? Is the matcher a valid regex? Plus light script heuristics — a hook script with no blocking branch at all is flagged as suspicious.
2. **Probe (dynamic).** canarygate synthesizes two events per hook — a benign one and a canary one carrying a unique `CANARYGATE-XXXX` marker in its payload — and runs the real hook command with each event JSON on stdin (the Claude Code hook protocol: exit `0` = allow, exit `2` = block).
3. **Verdict.** The verdicts are compared:

| Status | Meaning |
|---|---|
| `ALIVE` | Benign allowed, canary blocked — the gate discriminates. |
| `WIRED-BUT-DEAD` | Same verdict on both events; or the matcher never routes to the hook; or the command is missing, crashes, or hangs. |
| `OVERFIRE` | Blocks the benign event too — a gate that says no to everything gets disabled, which is death by another name. |
| `MISCONFIGURED` | The entry itself is broken (bad regex, empty command). |

Every non-green result ships with the concrete evidence and a fix suggestion.

### Example

```
canarygate liveness report
canary marker: CANARYGATE-9F2A1B3C

HOOK                             STATUS         EVIDENCE
------------------------------------------------------------------------------
PreToolUse[Bash]#0               OK             benign event allowed in 0.07s, canary event blocked in 0.07s
PreToolUse[Bash]#1               DEAD           hook returned 'allow' for both the benign event and the cana
PreToolUse[Bashh]#0              DEAD           matcher 'Bashh' does not match tool_name 'Bash' of the PreTo

2 of 3 gate(s) need attention:
  * PreToolUse[Bash]#1 [WIRED-BUT-DEAD]
      fix: Make the hook inspect its input and block when it sees the
      condition it exists for; then re-run `canarygate probe` until
      the canary is blocked.
  * PreToolUse[Bashh]#0 [WIRED-BUT-DEAD]
      fix: Fix the matcher (or the event registration) so the canary event
      actually routes to this hook.
```

## Differentiation

This sits next to two sibling tools, and they test different things:

- **vs deny-probe** (penetration tester for `deny` rules): deny-probe asks *"do my rules stop the attack?"* — it finds bypass routes around your policy. canarygate asks *"is the wire even connected?"* — it finds gates that look healthy but never execute. A perfect deny rule behind a dead hook still protects nothing.
- **vs agent-guard** (runtime protection): agent-guard is the shield — hooks that watch the agent live. canarygate audits the shield rack itself: the wiring, the matchers, and whether each hook still discriminates.

## CI example

```yaml
- name: Check hook liveness
  run: |
    pip install canarygate
    canarygate run --settings .claude/settings.json
```

## License

MIT — see `LICENSE`.
