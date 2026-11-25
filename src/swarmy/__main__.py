"""`python -m swarmy` entry point — delegates to the CLI (arch §3.1)."""

from swarmy.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
