from __future__ import annotations

import hashlib
import re
from pathlib import Path

from .iptables import Iptables, IptablesError


BACKUP_RE = re.compile(r"^[a-zA-Z0-9_.:-]+$")


class BackupManager:
    def __init__(self, backup_dir: Path, db, iptables: Iptables) -> None:
        self.backup_dir = backup_dir
        self.db = db
        self.iptables = iptables
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def create(self, reason: str) -> int:
        content = self.iptables.save_rules()
        digest = hashlib.sha256(content.encode()).hexdigest()
        filename = f"{_utc_slug()}-{digest[:12]}.rules"
        path = self.backup_dir / filename
        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
        with self.db.connect() as conn:
            cur = conn.execute(
                "INSERT INTO backups(filename, sha256, size_bytes, reason) VALUES (?, ?, ?, ?)",
                (filename, digest, path.stat().st_size, reason),
            )
            return int(cur.lastrowid)

    def list(self) -> list[dict]:
        with self.db.connect() as conn:
            return [dict(r) for r in conn.execute("SELECT * FROM backups ORDER BY id DESC")]

    def content(self, backup_id: int) -> str:
        row = self._row(backup_id)
        return self._path(row["filename"]).read_text(encoding="utf-8")

    def restore(self, backup_id: int) -> None:
        content = self.content(backup_id)
        self._verify_content(content)
        rollback = self.iptables.save_rules()
        self.iptables.validate_restore(content)
        try:
            self.iptables.apply_restore(content)
        except IptablesError:
            self.iptables.apply_restore(rollback)
            raise

    def _row(self, backup_id: int):
        with self.db.connect() as conn:
            row = conn.execute("SELECT * FROM backups WHERE id = ?", (backup_id,)).fetchone()
        if not row:
            raise FileNotFoundError("backup not found")
        return row

    def _path(self, filename: str) -> Path:
        if not BACKUP_RE.match(filename):
            raise ValueError("invalid backup filename")
        path = (self.backup_dir / filename).resolve()
        if self.backup_dir.resolve() not in path.parents:
            raise ValueError("invalid backup path")
        return path

    def _verify_content(self, content: str) -> None:
        if "*filter" not in content or "COMMIT" not in content:
            raise IptablesError("backup does not look like iptables-save output")
        self.iptables.validate_restore(content)


def _utc_slug() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
