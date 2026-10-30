import os
import re
import shutil
import sqlite3
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .core import DB_PATH


BACKUP_ROOT = Path(os.environ.get("PANEL_BACKUP_DIR", "/var/backups/proxy-panel"))
ENV_FILE = Path(os.environ.get("PANEL_ENV_FILE", "/etc/proxy-panel.env"))
RETENTION_DAYS = max(1, int(os.environ.get("PANEL_BACKUP_RETENTION", "14")))


def main():
    BACKUP_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(BACKUP_ROOT, 0o700)
    stamp = datetime.now(ZoneInfo("Asia/Singapore")).strftime("%Y-%m-%d")
    destination = BACKUP_ROOT / stamp
    destination.mkdir(mode=0o700, exist_ok=True)
    os.chmod(destination, 0o700)

    db_temp = destination / "panel.db.tmp"
    with sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True) as source, sqlite3.connect(db_temp) as target:
        source.backup(target)
    os.chmod(db_temp, 0o600)
    os.replace(db_temp, destination / "panel.db")

    env_temp = destination / "proxy-panel.env.tmp"
    shutil.copyfile(ENV_FILE, env_temp)
    os.chmod(env_temp, 0o600)
    os.replace(env_temp, destination / "proxy-panel.env")

    dated = sorted(
        path for path in BACKUP_ROOT.iterdir()
        if path.is_dir() and re.fullmatch(r"\d{4}-\d{2}-\d{2}", path.name)
    )
    for expired in dated[:-RETENTION_DAYS]:
        shutil.rmtree(expired)


if __name__ == "__main__":
    main()
