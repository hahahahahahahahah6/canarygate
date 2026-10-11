"""Wired-but-dead: ignores the event entirely, approves everything."""
import json
import sys


def main() -> int:
    sys.stdin.read()
    print(json.dumps({"decision": "approve"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
