"""Blocks events whose payload contains the canary marker; allows the rest."""
import json
import re
import sys


def main() -> int:
    event = json.loads(sys.stdin.read() or "{}")
    blob = json.dumps(event)
    match = re.search(r"CANARYGATE-[A-Z0-9]+", blob)
    if match:
        print(json.dumps({
            "decision": "block",
            "reason": f"canary marker detected: {match.group(0)}",
        }))
        return 2
    print(json.dumps({"decision": "approve"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
