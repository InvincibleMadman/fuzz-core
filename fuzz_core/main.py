from __future__ import annotations

import uvicorn

from .api.app import create_app
from .config import load_config

app = create_app()


def main() -> None:
    cfg = load_config()
    uvicorn.run(
        app,
        host=cfg.server.host,
        port=cfg.server.port,
        reload=False,
    )


if __name__ == "__main__":
    main()