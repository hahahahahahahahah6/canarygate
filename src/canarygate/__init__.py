"""canarygate: hook/gate liveness validator.

A gate that looks wired but never actually fires is worse than no gate at
all, because it still prints a verdict. canarygate replays synthetic benign
and canary (poison-pill) events through each configured hook command and
reports which gates are wired-but-dead.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
