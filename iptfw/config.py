from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    bind_host: str = os.getenv("IPTFW_BIND_HOST", "127.0.0.1")
    bind_port: int = int(os.getenv("IPTFW_BIND_PORT", "8088"))
    data_dir: Path = Path(os.getenv("IPTFW_DATA_DIR", "/var/lib/iptfw"))
    log_level: str = os.getenv("IPTFW_LOG_LEVEL", "INFO")
    admin_password: str | None = os.getenv("IPTFW_ADMIN_PASSWORD")
    dev_mode: bool = os.getenv("IPTFW_DEV_MODE", "0") == "1"
    polling_interval_seconds: int = int(os.getenv("IPTFW_POLLING_INTERVAL", "10"))
    iptables_bin: str = os.getenv("IPTFW_IPTABLES_BIN", "iptables")
    iptables_save_bin: str = os.getenv("IPTFW_IPTABLES_SAVE_BIN", "iptables-save")
    iptables_restore_bin: str = os.getenv("IPTFW_IPTABLES_RESTORE_BIN", "iptables-restore")

    @property
    def db_path(self) -> Path:
        return self.data_dir / "iptfw.sqlite3"

    @property
    def backup_dir(self) -> Path:
        return self.data_dir / "backups"

    @property
    def secret_path(self) -> Path:
        return self.data_dir / "session.secret"


settings = Settings()
