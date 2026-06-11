# Author: TK
# Date: 11-06-2026
# Purpose: Main CLI launcher for the project.

import asyncio

from honeypot.ssh_honeypot import start_honeypot
from dashboard.app import run_dashboard


async def main():
    dashboard_task = asyncio.to_thread(run_dashboard)
    honeypot_task = start_honeypot()

    await asyncio.gather(honeypot_task, dashboard_task)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] HoneyTrack stopped.")

