"""Blocks everything, including benign events."""
import json
import sys


def main() -> int:
    sys.stdin.read()
    print(json.dumps({"decision": "block", "reason": "no"}))
    return 2


if __name__ == "__main__":
    sys.exit(main())
