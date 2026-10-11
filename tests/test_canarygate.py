"""Smoke tests for canarygate: every failure class must be caught, and a
healthy gate must pass. Run with: python -m unittest discover -s tests"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC))

from canarygate import __version__  # noqa: E402
from canarygate.analyzer import (ALIVE, DEAD, MISCONFIGURED, OVERFIRE,  # noqa: E402
                                 analyze_all)
from canarygate.cli import main as cli_main  # noqa: E402
from canarygate.config import ConfigError, load_settings  # noqa: E402
from canarygate.prober import (build_event, probe_all, probe_hook,  # noqa: E402
                               run_hook)
from canarygate.report import json_report, text_report  # noqa: E402
from canarygate.scanner import scan_all  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MARKER = "CANARYGATE-TEST1234"
TIMEOUT = 8.0


def _specs(name):
    """Load a fixture settings file with FIXTURES placeholder resolved."""
    path = FIXTURES / name
    text = path.read_text(encoding="utf-8").replace("FIXTURES", str(FIXTURES))
    tmp = Path(tempfile.mkdtemp()) / name
    tmp.write_text(text, encoding="utf-8")
    return load_settings(tmp)


def _analyze(name, timeout=TIMEOUT, marker=MARKER):
    specs = _specs(name)
    findings = scan_all(specs)
    probes = probe_all(specs, marker, timeout)
    return specs, analyze_all(specs, findings, probes)


class TestConfig(unittest.TestCase):
    def test_parses_claude_code_settings(self):
        specs = _specs("settings_mixed.json")
        self.assertEqual(len(specs), 6)
        names = [s.name for s in specs]
        self.assertIn("PreToolUse[Bash]#0", names)
        self.assertIn("PreToolUse[Bashh]#0", names)
        self.assertEqual(specs[0].event, "PreToolUse")
        self.assertEqual(specs[0].matcher, "Bash")

    def test_rejects_invalid_json(self):
        with self.assertRaises(ConfigError):
            _specs("settings_bad.json")

    def test_rejects_missing_file(self):
        with self.assertRaises(ConfigError):
            load_settings(FIXTURES / "nope.json")


class TestScanner(unittest.TestCase):
    def test_flags_missing_command(self):
        specs = _specs("settings_mixed.json")
        findings = scan_all(specs)
        missing = [s for s in specs if "does-not-exist" in s.command]
        self.assertEqual(len(missing), 1)
        codes = [f.code for f in findings[missing[0].name]]
        self.assertIn("command-not-found", codes)
        self.assertTrue(any(f.severity == "error"
                            for f in findings[missing[0].name]))

    def test_flags_invalid_matcher_regex(self):
        from canarygate.config import HookSpec
        spec = HookSpec(name="t", event="PreToolUse", matcher="([",
                        command="echo hi")
        findings = scan_all([spec])
        self.assertIn("matcher-invalid-regex",
                      [f.code for f in findings["t"]])

    def test_static_heuristic_catches_unconditional_approve(self):
        from canarygate.config import HookSpec
        spec = HookSpec(name="t", event="PreToolUse", matcher="Bash",
                        command=f"python3 {FIXTURES}/dead_gate.py")
        findings = scan_all([spec])
        codes = [f.code for f in findings["t"]]
        self.assertIn("static-unconditional-approve", codes)

    def test_alive_gate_passes_static_scan(self):
        from canarygate.config import HookSpec
        spec = HookSpec(name="t", event="PreToolUse", matcher="Bash",
                        command=f"python3 {FIXTURES}/alive_gate.py")
        findings = scan_all([spec])
        errors = [f for f in findings["t"] if f.severity == "error"]
        self.assertEqual(errors, [])


class TestProber(unittest.TestCase):
    def _spec(self, fixture, matcher="Bash"):
        from canarygate.config import HookSpec
        return HookSpec(name="t", event="PreToolUse", matcher=matcher,
                        command=f"python3 {FIXTURES}/{fixture}")

    def test_alive_gate_blocks_canary_allows_benign(self):
        result = probe_hook(self._spec("alive_gate.py"), MARKER, TIMEOUT)
        self.assertFalse(result.skipped)
        self.assertEqual(result.benign.verdict, "allow")
        self.assertEqual(result.canary.verdict, "block")
        self.assertIn(MARKER, result.canary.reason)

    def test_typo_matcher_is_router_skipped(self):
        result = probe_hook(self._spec("alive_gate.py", matcher="Bashh"),
                            MARKER, TIMEOUT)
        self.assertTrue(result.skipped)
        self.assertIn("Bashh", result.skip_reason)

    def test_crash_reports_error_verdict(self):
        outcome = run_hook(f"python3 {FIXTURES}/crash_gate.py",
                           build_event("PreToolUse"), TIMEOUT)
        self.assertEqual(outcome.verdict, "error")

    def test_timeout_reports_timeout_verdict(self):
        outcome = run_hook(f"python3 {FIXTURES}/slow_gate.py",
                           build_event("PreToolUse"), 1.0)
        self.assertEqual(outcome.verdict, "timeout")


class TestAnalyzer(unittest.TestCase):
    def test_full_mixed_matrix(self):
        specs, results = _analyze("settings_mixed.json")
        by_name = {r.hook.name: r.status for r in results}
        self.assertEqual(by_name["PreToolUse[Bash]#0"], ALIVE)        # alive_gate
        self.assertEqual(by_name["PreToolUse[Bash]#1"], DEAD)         # dead_gate
        self.assertEqual(by_name["PreToolUse[Bash]#2"], DEAD)         # crash_gate
        self.assertEqual(by_name["PreToolUse[Bash]#3"], OVERFIRE)     # overfire_gate
        self.assertEqual(by_name["PreToolUse[Bash]#4"], DEAD)         # missing file
        self.assertEqual(by_name["PreToolUse[Bashh]#0"], DEAD)        # typo matcher

    def test_dead_gate_evidence_names_marker(self):
        _, results = _analyze("settings_dead.json")
        self.assertEqual(results[0].status, DEAD)
        self.assertIn(MARKER, results[0].evidence[0])
        self.assertTrue(results[0].fixes)

    def test_timeout_gate_is_dead(self):
        specs = _specs("settings_alive.json")
        spec = specs[0]
        from canarygate.config import HookSpec
        slow = HookSpec(name="slow", event="PreToolUse", matcher="Bash",
                        command=f"python3 {FIXTURES}/slow_gate.py")
        findings = scan_all([slow])
        probes = probe_all([slow], MARKER, 1.0)
        (result,) = analyze_all([slow], findings, probes)
        self.assertEqual(result.status, DEAD)
        self.assertIn("timed out", result.evidence[0])

    def test_inverted_gate_is_overfire(self):
        # overfire blocks benign too -> flagged, not celebrated
        _, results = _analyze("settings_mixed.json")
        overfire = [r for r in results if "overfire" in r.hook.command][0]
        self.assertEqual(overfire.status, OVERFIRE)


class TestReport(unittest.TestCase):
    def test_json_report_schema(self):
        _, results = _analyze("settings_dead.json")
        payload = json.loads(json_report(results, MARKER, "settings.json"))
        self.assertEqual(payload["tool"], "canarygate")
        self.assertIn("summary", payload)
        self.assertEqual(payload["summary"]["total"], 1)
        self.assertEqual(payload["summary"]["dead"], 1)
        gate = payload["gates"][0]
        for key in ("name", "event", "matcher", "command", "status",
                    "evidence", "fixes", "warnings"):
            self.assertIn(key, gate)

    def test_text_report_lists_fixes(self):
        _, results = _analyze("settings_dead.json")
        text = text_report(results, MARKER)
        self.assertIn("DEAD", text)
        self.assertIn("fix:", text)


class TestCLI(unittest.TestCase):
    def _settings_path(self, name):
        path = FIXTURES / name
        text = path.read_text(encoding="utf-8").replace("FIXTURES", str(FIXTURES))
        tmp = Path(tempfile.mkdtemp()) / name
        tmp.write_text(text, encoding="utf-8")
        return str(tmp)

    def test_cli_exit_zero_when_alive(self):
        rc = cli_main(["run", "--settings", self._settings_path("settings_alive.json"),
                       "--marker", MARKER, "--timeout", str(TIMEOUT)])
        self.assertEqual(rc, 0)

    def test_cli_exit_one_when_dead(self):
        rc = cli_main(["run", "--settings", self._settings_path("settings_dead.json"),
                       "--marker", MARKER, "--timeout", str(TIMEOUT)])
        self.assertEqual(rc, 1)

    def test_cli_exit_two_on_bad_config(self):
        rc = cli_main(["run", "--settings", str(FIXTURES / "settings_bad.json")])
        self.assertEqual(rc, 2)

    def test_cli_json_format_is_parseable(self):
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = cli_main(["run", "--settings",
                           self._settings_path("settings_dead.json"),
                           "--marker", MARKER, "--format", "json"])
        self.assertEqual(rc, 1)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["summary"]["needs_attention"], 1)

    def test_init_scaffolds_example(self):
        with tempfile.TemporaryDirectory() as tmp:
            rc = cli_main(["init", "--dir", tmp])
            self.assertEqual(rc, 0)
            self.assertTrue((Path(tmp) / "settings.json").is_file())
            self.assertTrue((Path(tmp) / "hooks" / "alive_gate.py").is_file())
            self.assertTrue((Path(tmp) / "hooks" / "dead_gate.py").is_file())

    def test_cli_subprocess_end_to_end(self):
        env = dict(os.environ, PYTHONPATH=str(SRC))
        proc = subprocess.run(
            [sys.executable, "-m", "canarygate", "run",
             "--settings", self._settings_path("settings_dead.json"),
             "--marker", MARKER, "--timeout", str(TIMEOUT)],
            capture_output=True, text=True, env=env, cwd=str(FIXTURES),
        )
        self.assertEqual(proc.returncode, 1)
        self.assertIn("WIRED-BUT-DEAD", proc.stdout)


if __name__ == "__main__":
    unittest.main()
