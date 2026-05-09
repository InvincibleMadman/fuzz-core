
from __future__ import annotations

import os

import uvicorn

from .api.app import create_app
from .config import ConfigStore


def main() -> None:
    config_path = os.environ.get("FUZZ_CORE_CONFIG", "./config.yaml")
    config = ConfigStore(config_path).get()
    uvicorn.run(
        create_app(config_path),
        host=config.server.http.host,
        port=config.server.http.port,
        reload=False,
    )


if __name__ == "__main__":
    main()
