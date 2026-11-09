"""Project-root entry point for the deterministic scan pipeline."""

import os
from project_env import tool_environment

os.environ.update(tool_environment())

from pipeline.scan.run_scan import main


if __name__ == "__main__":
    raise SystemExit(main())
