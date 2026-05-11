from __future__ import annotations

import uvicorn

from .config import settings


if __name__ == "__main__":
    uvicorn.run(
        "iptfw.main:app",
        host=settings.bind_host,
        port=settings.bind_port,
        log_level=settings.log_level.lower(),
    )
