"""Hangs: never produces a verdict in time."""
import sys
import time


def main() -> int:
    sys.stdin.read()
    time.sleep(60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
