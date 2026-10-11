"""Command-line interface for canarygate.

Commands:
  run     scan + canary probes for every hook (default); exit 1 if any gate
          is wired-but-dead, misconfigured, or overfiring
  scan    static wiring analysis only
  probe   run the benign/canary pair through one hook (or all hooks)
  init    scaffold an example settings.json + example hooks (one alive, one dead)

Exit codes: 0 = all gates alive; 1 = a gate needs attention; 2 = fatal error.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analyzer import ALIVE, analyze_all
from .config import ConfigError, HookSpec, load_settings
from .prober import new_marker, probe_all, probe_hook
from .report import json_report, text_report
from .scanner import scan_all

DEFAULT_TIMEOUT = 10.0

EXAMPLE_SETTINGS = """\
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "python3 hooks/alive_gate.py" },
          { "type": "command", "command": "python3 hooks/dead_gate.py" }
        ]
      }
    ]
  }
}
"""

ALIVE_GATE = '''\
"""Example of an ALIVE gate: blocks input containing the canary marker."""
import json
import sys


def main() -> int:
    event = json.loads(sys.stdin.read() or "{}")
    command = event.get("tool_input", {}).get("command", "")
    if "CANARYGATE-" in command:
        print(json.dumps({
            "decision": "block",
            "reason": f"canary marker detected in command: {command[:80]}",
        }))
        return 2
    print(json.dumps({"decision": "approve"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

DEAD_GATE = '''\
"""Example of a WIRED-BUT-DEAD gate: approves everything, always."""
import json
import sys


def main() -> int:
    sys.stdin.read()  # event ignored entirely
    print(json.dumps({"decision": "approve"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def _parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="canarygate",
        description="Hook/gate liveness validator: canary probes that catch "
                    "wired-but-dead gates.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command")

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--settings", default="settings.json",
                       help="settings.json with a hooks section (default: settings.json)")
        p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                       help=f"per-hook probe timeout in seconds (default: {DEFAULT_TIMEOUT})")
        p.add_argument("--marker",
                       help="canary marker string (default: random per run)")
        p.add_argument("--format", choices=["text", "json"], default="text",
                       help="report format (default: text)")
        p.add_argument("--hook",
                       help="only check the hook with this name (e.g. 'PreToolUse[Bash]#0')")

    run_p = sub.add_parser("run", help="scan + probe every hook (default)")
    add_common(run_p)
    scan_p = sub.add_parser("scan", help="static wiring analysis only")
    add_common(scan_p)
    probe_p = sub.add_parser("probe", help="run canary probes")
    add_common(probe_p)
    init_p = sub.add_parser("init", help="scaffold example settings + hooks")
    init_p.add_argument("--dir", default=".",
                        help="directory to scaffold into (default: .)")

    # `canarygate` with no subcommand == `canarygate run`
    effective = list(argv)
    if not effective or effective[0] not in {"run", "scan", "probe", "init",
                                             "-h", "--help", "--version"}:
        effective = ["run"] + effective
    return parser.parse_args(effective)


def _load_specs(args: argparse.Namespace) -> list[HookSpec]:
    specs = load_settings(args.settings)
    if args.hook:
        specs = [s for s in specs if s.name == args.hook]
        if not specs:
            raise ConfigError(f"no hook named {args.hook!r} in {args.settings}")
    if not specs:
        raise ConfigError(f"no hooks configured in {args.settings}")
    return specs


def cmd_run(args: argparse.Namespace) -> int:
    try:
        specs = _load_specs(args)
    except ConfigError as exc:
        print(f"canarygate: error: {exc}", file=sys.stderr)
        return 2
    marker = args.marker or new_marker()
    findings = scan_all(specs)
    probes = probe_all(specs, marker, args.timeout)
    results = analyze_all(specs, findings, probes)
    if args.format == "json":
        print(json_report(results, marker, args.settings), end="")
    else:
        print(text_report(results, marker), end="")
    return 0 if all(r.status == ALIVE for r in results) else 1


def cmd_scan(args: argparse.Namespace) -> int:
    try:
        specs = _load_specs(args)
    except ConfigError as exc:
        print(f"canarygate: error: {exc}", file=sys.stderr)
        return 2
    findings = scan_all(specs)
    if args.format == "json":
        import json as _json
        print(_json.dumps({s.name: [f.__dict__ for f in findings[s.name]]
                           for s in specs}, indent=2))
        problems = sum(1 for s in specs for f in findings[s.name]
                       if f.severity == "error")
        return 1 if problems else 0
    problems = 0
    for spec in specs:
        for finding in findings[spec.name]:
            problems += finding.severity == "error"
            tag = {"error": "ERROR", "warning": "WARN", "info": "info"}[finding.severity]
            print(f"[{tag}] {spec.name}: {finding.message}")
            if finding.fix:
                print(f"        fix: {finding.fix}")
    if not any(findings[s.name] for s in specs):
        print("No static wiring problems found.")
    return 1 if problems else 0


def cmd_probe(args: argparse.Namespace) -> int:
    # probe is the dynamic half of run; share the same verdict logic
    return cmd_run(args)


def cmd_init(args: argparse.Namespace) -> int:
    root = Path(args.dir)
    hooks_dir = root / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    (hooks_dir / "alive_gate.py").write_text(ALIVE_GATE, encoding="utf-8")
    (hooks_dir / "dead_gate.py").write_text(DEAD_GATE, encoding="utf-8")
    settings_path = root / "settings.json"
    if settings_path.exists():
        print(f"canarygate: {settings_path} already exists, not overwritten")
    else:
        settings_path.write_text(EXAMPLE_SETTINGS, encoding="utf-8")
        print(f"canarygate: wrote {settings_path}")
    print(f"canarygate: wrote {hooks_dir / 'alive_gate.py'}")
    print(f"canarygate: wrote {hooks_dir / 'dead_gate.py'}")
    print("Try: canarygate run --settings " + str(settings_path))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(sys.argv[1:] if argv is None else argv)
    command = args.command or "run"
    if command == "scan":
        return cmd_scan(args)
    if command == "probe":
        return cmd_probe(args)
    if command == "init":
        return cmd_init(args)
    return cmd_run(args)


if __name__ == "__main__":
    sys.exit(main())
