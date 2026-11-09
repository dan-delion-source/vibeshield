"""Start the VibeShield local dashboard."""
import os
from project_env import tool_environment

os.environ.update(tool_environment())

from dashboard.server import main
if __name__ == '__main__':
    main()
