"""Crashes on every invocation."""
import sys


def main() -> int:
    sys.stdin.read()
    raise RuntimeError("boom: hook misconfigured")


if __name__ == "__main__":
    sys.exit(main())
