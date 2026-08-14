"""Exercise the real Python client against the Windows daemon named pipe."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

from bindings.python.umc import Client


async def _connect_with_retry(endpoint: str) -> Client:
    deadline = time.monotonic() + 30
    last_error = None
    while time.monotonic() < deadline:
        try:
            return await Client.connect(endpoint, "windows-ci")
        except (ConnectionError, FileNotFoundError, OSError, TimeoutError) as error:
            last_error = error
            await asyncio.sleep(0.25)
    raise RuntimeError(f"timed out connecting to {endpoint}: {last_error}")


async def _run(binary: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="umc-windows-control-") as directory:
        root = Path(directory)
        endpoint = rf"\\.\pipe\umc-ci-{os.getpid()}"
        config = root / "node.json"
        config.write_text(
            json.dumps(
                {
                    "data_dir": str(root / "data"),
                    "control_socket": endpoint,
                    "carriers": [],
                }
            ),
            encoding="utf-8",
        )
        subprocess.run(
            [str(binary), "--init", "--config", str(config)],
            check=True,
            capture_output=True,
            text=True,
        )
        daemon = subprocess.Popen([str(binary), "--config", str(config)])
        try:
            async with await _connect_with_retry(endpoint) as client:
                status = await client.get_status()
                if not status:
                    raise RuntimeError("NodeAdmin.GetStatus returned an empty payload")
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=10)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=10)


def main() -> int:
    if os.name != "nt":
        print("Windows named-pipe smoke test skipped on non-Windows host")
        return 0
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} PATH_TO_UMCD", file=sys.stderr)
        return 2
    asyncio.run(_run(Path(sys.argv[1])))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
