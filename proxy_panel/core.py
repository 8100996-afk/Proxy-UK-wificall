import base64
import fcntl
import json
import os
import secrets
import sqlite3
import subprocess
import tempfile
import time
import urllib.parse
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import requests
from cryptography.fernet import Fernet


BASE_DIR = Path(os.environ.get("PANEL_DATA_DIR", "/var/lib/proxy-panel"))
DB_PATH = BASE_DIR / "panel.db"
XRAY_CONFIG = Path(os.environ.get("XRAY_CONFIG", "/usr/local/etc/xray/config.json"))
NODE_DOMAIN = os.environ.get("NODE_DOMAIN", "node.example.com")
XRAY_API = "127.0.0.1:10085"
GIB = 1024 ** 3
TIB = 1024 ** 4


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _fernet():
    return Fernet(os.environ["FERNET_KEY"].encode())


def encrypt(value):
    return _fernet().encrypt((value or "").encode()).decode()


def decrypt(value):
    return _fernet().decrypt(value.encode()).decode() if value else ""


@contextmanager
def db():
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db():
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS socks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                username_enc TEXT NOT NULL DEFAULT '',
                password_enc TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'disabled',
                exit_ip TEXT,
                latency_ms INTEGER,
                fail_count INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                last_checked_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                vless_uuid TEXT NOT NULL,
                trojan_password TEXT NOT NULL,
                request_key TEXT UNIQUE,
                quota_gb REAL NOT NULL DEFAULT 1000,
                used_bytes INTEGER NOT NULL DEFAULT 0,
                direct_used_bytes INTEGER NOT NULL DEFAULT 0,
                quota_exceeded INTEGER NOT NULL DEFAULT 0,
                quota_period_start TEXT,
                stats_last_bytes INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS subscription_socks (
                subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
                socks_id INTEGER NOT NULL REFERENCES socks(id) ON DELETE CASCADE,
                position INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(subscription_id, socks_id)
            );
            CREATE TABLE IF NOT EXISTS secondary_plans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                parent_subscription_id INTEGER NOT NULL REFERENCES subscriptions(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                default_speed_mbps INTEGER NOT NULL DEFAULT 10,
                default_quota_gb REAL NOT NULL DEFAULT 100,
                default_valid_days INTEGER NOT NULL DEFAULT 30,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS activation_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plan_id INTEGER NOT NULL REFERENCES secondary_plans(id) ON DELETE CASCADE,
                code TEXT NOT NULL UNIQUE,
                speed_mbps INTEGER NOT NULL,
                quota_gb REAL NOT NULL,
                valid_days INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'unused',
                token TEXT UNIQUE,
                vless_uuid TEXT,
                trojan_password TEXT,
                activated_at TEXT,
                expires_at TEXT,
                used_bytes INTEGER NOT NULL DEFAULT 0,
                parent_period_bytes INTEGER NOT NULL DEFAULT 0,
                stats_last_bytes INTEGER NOT NULL DEFAULT 0,
                quota_exceeded INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_activation_codes_plan ON activation_codes(plan_id);
            CREATE INDEX IF NOT EXISTS idx_activation_codes_expiry ON activation_codes(expires_at);
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                level TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS wifi_call_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                carrier TEXT NOT NULL,
                endpoint TEXT,
                port500_ok INTEGER NOT NULL DEFAULT 0,
                port4500_ok INTEGER NOT NULL DEFAULT 0,
                ok INTEGER NOT NULL DEFAULT 0,
                latency_ms INTEGER,
                detail TEXT,
                checked_at TEXT NOT NULL,
                checked_at_epoch INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_wifi_call_carrier_time
                ON wifi_call_checks(carrier, checked_at_epoch DESC);
            CREATE TABLE IF NOT EXISTS wifi_access (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                vless_uuid TEXT NOT NULL,
                trojan_password TEXT NOT NULL,
                speed_mbps INTEGER NOT NULL DEFAULT 5,
                used_bytes INTEGER NOT NULL DEFAULT 0,
                stats_last_bytes INTEGER NOT NULL DEFAULT 0,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_wifi_access_name_nocase
                ON wifi_access(name COLLATE NOCASE);
            """
        )
        conn.execute(
            "INSERT OR IGNORE INTO settings(key,value) VALUES('admin_password_hash',?)",
            (os.environ["ADMIN_PASSWORD_HASH"],),
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(subscriptions)")}
        if "status" not in columns:
            conn.execute("ALTER TABLE subscriptions ADD COLUMN status TEXT NOT NULL DEFAULT 'unchecked'")
        if "last_checked_at" not in columns:
            conn.execute("ALTER TABLE subscriptions ADD COLUMN last_checked_at TEXT")
        if "last_error" not in columns:
            conn.execute("ALTER TABLE subscriptions ADD COLUMN last_error TEXT")
        if "request_key" not in columns:
            conn.execute("ALTER TABLE subscriptions ADD COLUMN request_key TEXT")
        if "quota_gb" not in columns:
            conn.execute("ALTER TABLE subscriptions ADD COLUMN quota_gb REAL NOT NULL DEFAULT 1000")
        if "used_bytes" not in columns:
            conn.execute("ALTER TABLE subscriptions ADD COLUMN used_bytes INTEGER NOT NULL DEFAULT 0")
        if "quota_exceeded" not in columns:
            conn.execute("ALTER TABLE subscriptions ADD COLUMN quota_exceeded INTEGER NOT NULL DEFAULT 0")
        if "quota_period_start" not in columns:
            conn.execute("ALTER TABLE subscriptions ADD COLUMN quota_period_start TEXT")
        if "stats_last_bytes" not in columns:
            conn.execute("ALTER TABLE subscriptions ADD COLUMN stats_last_bytes INTEGER NOT NULL DEFAULT 0")
        if "direct_used_bytes" not in columns:
            conn.execute("ALTER TABLE subscriptions ADD COLUMN direct_used_bytes INTEGER NOT NULL DEFAULT 0")
            conn.execute("UPDATE subscriptions SET direct_used_bytes=used_bytes")
        code_columns = {row["name"] for row in conn.execute("PRAGMA table_info(activation_codes)")}
        if "parent_period_bytes" not in code_columns:
            conn.execute("ALTER TABLE activation_codes ADD COLUMN parent_period_bytes INTEGER NOT NULL DEFAULT 0")
        conn.execute(
            "UPDATE subscriptions SET quota_period_start=? WHERE quota_period_start IS NULL",
            (quota_period_start(),),
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_name_nocase "
            "ON subscriptions(name COLLATE NOCASE)"
        )
        conn.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_subscriptions_request_key "
            "ON subscriptions(request_key) WHERE request_key IS NOT NULL"
        )
        defaults = {
            "server_traffic_quota_tb": "2",
            "server_traffic_action": "limit",
            "server_traffic_limit_mbps": "10",
            "server_traffic_used_bytes": "0",
            "server_traffic_period_start": quota_period_start(),
        }
        conn.executemany(
            "INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)",
            defaults.items(),
        )


def add_event(level, message):
    with db() as conn:
        conn.execute(
            "INSERT INTO events(level,message,created_at) VALUES(?,?,?)",
            (level, message[:500], now()),
        )
        conn.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 200)")


def get_setting(key):
    with db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return row["value"] if row else None


def set_setting(key, value):
    with db() as conn:
        conn.execute(
            "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def quota_period_start(reference=None):
    current = (reference or datetime.now(timezone.utc)).astimezone(ZoneInfo("Asia/Singapore"))
    local_start = current.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    return local_start.astimezone(timezone.utc).isoformat(timespec="seconds")


def server_traffic_status(conn=None):
    owns_connection = conn is None
    if owns_connection:
        context = db()
        conn = context.__enter__()
    try:
        values = {row["key"]: row["value"] for row in conn.execute(
            "SELECT key,value FROM settings WHERE key LIKE 'server_traffic_%'"
        )}
        quota_tb = max(0.001, float(values.get("server_traffic_quota_tb", "2")))
        used = max(0, int(values.get("server_traffic_used_bytes", "0")))
        quota_bytes = int(quota_tb * TIB)
        return {
            "quota_tb": quota_tb,
            "quota_bytes": quota_bytes,
            "used_bytes": used,
            "percent": min(100, round(used * 100 / quota_bytes, 2)) if quota_bytes else 100,
            "exceeded": used >= quota_bytes,
            "action": values.get("server_traffic_action", "limit"),
            "limit_mbps": max(1, int(values.get("server_traffic_limit_mbps", "10"))),
            "period_start": values.get("server_traffic_period_start", quota_period_start()),
        }
    finally:
        if owns_connection:
            context.__exit__(None, None, None)


def collect_xray_traffic(rebuild_on_change=True):
    """Read cumulative Xray counters without resetting live proxy state."""
    BASE_DIR.mkdir(parents=True, exist_ok=True)
    # Lock the existing database file so root-initiated rebuilds cannot leave a
    # root-owned sidecar lock that blocks the unprivileged timer service.
    with open(DB_PATH, "rb") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"collected": 0, "changed": False}

        totals = {}
        try:
            result = subprocess.run(
                [
                    "/usr/local/bin/xray", "api", "statsquery",
                    f"--server={XRAY_API}", "-pattern", "user>>>",
                ],
                capture_output=True,
                text=True,
                timeout=8,
            )
            if result.returncode == 0 and result.stdout.strip():
                payload = json.loads(result.stdout)
                for item in payload.get("stat", []):
                    parts = item.get("name", "").split(">>>")
                    if len(parts) == 4 and parts[0] == "user" and parts[2] == "traffic":
                        email = parts[1]
                        totals[email] = totals.get(email, 0) + int(item.get("value", 0))
        except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
            pass

        period = quota_period_start()
        changed = False
        collected = 0
        with db() as conn:
            expired = conn.execute(
                "DELETE FROM activation_codes WHERE status='active' AND expires_at<=?", (now(),)
            ).rowcount
            if expired:
                changed = True
            rows = conn.execute("SELECT * FROM subscriptions ORDER BY id").fetchall()
            period_changed = any(sub["quota_period_start"] != period for sub in rows)
            if period_changed:
                conn.execute("UPDATE subscriptions SET direct_used_bytes=0,used_bytes=0,quota_exceeded=0")
                conn.execute("UPDATE activation_codes SET parent_period_bytes=0")
                changed = True

            children = conn.execute(
                "SELECT * FROM activation_codes WHERE status='active' ORDER BY id"
            ).fetchall()
            for child in children:
                email = f"child-{child['id']}@proxy.local"
                last_total = int(child["stats_last_bytes"] or 0)
                current_total = totals.get(email)
                delta = 0
                if current_total is not None:
                    delta = current_total - last_total if current_total >= last_total else current_total
                    collected += delta
                    last_total = current_total
                used = int(child["used_bytes"] or 0) + delta
                parent_period_bytes = int(child["parent_period_bytes"] or 0) + delta
                exceeded = used >= float(child["quota_gb"]) * GIB
                if exceeded != bool(child["quota_exceeded"]):
                    changed = True
                conn.execute(
                    """UPDATE activation_codes SET used_bytes=?,parent_period_bytes=?,
                       stats_last_bytes=?,quota_exceeded=? WHERE id=?""",
                    (used, parent_period_bytes, last_total, int(exceeded), child["id"]),
                )

            for sub in rows:
                direct_used = 0 if period_changed else int(sub["direct_used_bytes"] or 0)
                old_exceeded = bool(sub["quota_exceeded"])
                email = f"sub-{sub['id']}@proxy.local"
                last_total = int(sub["stats_last_bytes"] or 0)
                current_total = totals.get(email)
                delta = 0
                if current_total is not None:
                    delta = current_total - last_total if current_total >= last_total else current_total
                    collected += delta
                    last_total = current_total
                direct_used += delta
                child_period = conn.execute(
                    """SELECT COALESCE(SUM(a.parent_period_bytes),0) FROM activation_codes a
                       JOIN secondary_plans p ON p.id=a.plan_id WHERE p.parent_subscription_id=?""",
                    (sub["id"],),
                ).fetchone()[0]
                used = direct_used + int(child_period or 0)
                new_exceeded = used >= float(sub["quota_gb"]) * GIB
                if new_exceeded != old_exceeded:
                    changed = True
                conn.execute(
                    """UPDATE subscriptions SET used_bytes=?,direct_used_bytes=?,quota_exceeded=?,
                       quota_period_start=?,stats_last_bytes=?,updated_at=? WHERE id=?""",
                    (used, direct_used, int(new_exceeded), period, last_total, now(), sub["id"]),
                )

            wifi_accounts = conn.execute("SELECT * FROM wifi_access ORDER BY id").fetchall()
            for account in wifi_accounts:
                email = f"wifi-{account['id']}@proxy.local"
                last_total = int(account["stats_last_bytes"] or 0)
                current_total = totals.get(email)
                delta = 0
                if current_total is not None:
                    delta = current_total - last_total if current_total >= last_total else current_total
                    collected += delta
                    last_total = current_total
                conn.execute(
                    "UPDATE wifi_access SET used_bytes=used_bytes+?,stats_last_bytes=?,updated_at=? WHERE id=?",
                    (delta, last_total, now(), account["id"]),
                )

            server = server_traffic_status(conn)
            old_server_exceeded = server["exceeded"]
            server_used = server["used_bytes"]
            if server["period_start"] != period:
                server_used = 0
            server_used += collected
            conn.execute(
                "INSERT INTO settings(key,value) VALUES('server_traffic_used_bytes',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(server_used),),
            )
            conn.execute(
                "INSERT INTO settings(key,value) VALUES('server_traffic_period_start',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (period,),
            )
            if (server_used >= server["quota_bytes"]) != old_server_exceeded:
                changed = True

        if changed and rebuild_on_change:
            rebuild_xray(collect_stats=False)
            add_event("warning", "订阅流量额度状态已变化，Xray 已自动更新")
        return {"collected": collected, "changed": changed}


def test_socks(host, port, username="", password="", timeout=12):
    quoted_user = urllib.parse.quote(username, safe="")
    quoted_pass = urllib.parse.quote(password, safe="")
    auth = f"{quoted_user}:{quoted_pass}@" if username or password else ""
    proxy = f"socks5h://{auth}{host}:{int(port)}"
    started = time.monotonic()
    try:
        response = requests.get(
            "https://www.cloudflare.com/cdn-cgi/trace",
            proxies={"http": proxy, "https": proxy},
            timeout=timeout,
            headers={"User-Agent": "ProxyPanel/1.0"},
        )
        response.raise_for_status()
        fields = dict(
            line.split("=", 1) for line in response.text.splitlines() if "=" in line
        )
        exit_ip = fields.get("ip", "unknown")
        latency = int((time.monotonic() - started) * 1000)
        return True, exit_ip, latency, None
    except Exception as exc:
        return False, None, None, str(exc)[:240]


def check_one(socks_id):
    with db() as conn:
        row = conn.execute("SELECT * FROM socks WHERE id=?", (socks_id,)).fetchone()
    if not row:
        return False, "代理不存在"
    ok, exit_ip, latency, error = test_socks(
        row["host"], row["port"], decrypt(row["username_enc"]), decrypt(row["password_enc"])
    )
    deleted = False
    with db() as conn:
        current = conn.execute("SELECT * FROM socks WHERE id=?", (socks_id,)).fetchone()
        if not current:
            return False, "代理不存在"
        if ok:
            conn.execute(
                "UPDATE socks SET status='active',exit_ip=?,latency_ms=?,fail_count=0,last_error=NULL,last_checked_at=? WHERE id=?",
                (exit_ip, latency, now(), socks_id),
            )
        else:
            failures = current["fail_count"] + 1
            if failures >= 3:
                conn.execute("DELETE FROM socks WHERE id=?", (socks_id,))
                deleted = True
            else:
                conn.execute(
                    "UPDATE socks SET status='disabled',fail_count=?,last_error=?,last_checked_at=? WHERE id=?",
                    (failures, error, now(), socks_id),
                )
    if deleted:
        add_event("warning", f"SOCKS5 {row['name']} 连续失败 3 次，已自动删除")
    elif not ok:
        add_event("warning", f"SOCKS5 {row['name']} 检测失败，已停用：{error}")
    return ok, (f"出口 {exit_ip}，{latency} ms" if ok else error)


def xray_config():
    with db() as conn:
        conn.execute("DELETE FROM activation_codes WHERE status='active' AND expires_at<=?", (now(),))
        subs = conn.execute("SELECT * FROM subscriptions WHERE enabled=1 ORDER BY id").fetchall()
        children = conn.execute(
            """SELECT a.*,p.parent_subscription_id,p.name AS plan_name
               FROM activation_codes a JOIN secondary_plans p ON p.id=a.plan_id
               JOIN subscriptions s ON s.id=p.parent_subscription_id
               WHERE a.status='active' AND a.quota_exceeded=0 AND a.expires_at>?
                 AND s.enabled=1 ORDER BY a.id""",
            (now(),),
        ).fetchall()
        socks_rows = conn.execute("SELECT * FROM socks WHERE status='active' ORDER BY id").fetchall()
        links = conn.execute(
            "SELECT subscription_id,socks_id FROM subscription_socks ORDER BY position,socks_id"
        ).fetchall()
        wifi_accounts = conn.execute(
            "SELECT * FROM wifi_access WHERE enabled=1 ORDER BY id"
        ).fetchall()
        server_traffic = server_traffic_status(conn)
    active_ids = {r["id"] for r in socks_rows}
    assigned = {}
    for link in links:
        if link["socks_id"] in active_ids:
            assigned.setdefault(link["subscription_id"], []).append(link["socks_id"])

    users_vless = []
    users_trojan = []
    main_emails = []
    child_emails = []
    # Dedicated Wi-Fi Calling accounts are deliberately unable to carry web,
    # downloads, DNS, speed tests or any traffic except IKE/IPsec UDP 500/4500.
    rules = []
    for account in wifi_accounts:
        email = f"wifi-{account['id']}@proxy.local"
        users_vless.append({"id": account["vless_uuid"], "email": email})
        users_trojan.append({"password": account["trojan_password"], "email": email})
        rules.append({
            "type": "field", "network": "udp", "port": "500,4500",
            "user": [email], "outboundTag": f"wifi-limit-{account['id']}",
            "ruleTag": f"wifi-dedicated-{account['id']}",
        })
        rules.append({
            "type": "field", "user": [email], "outboundTag": "blocked",
            "ruleTag": f"wifi-dedicated-block-{account['id']}",
        })

    # Normal subscriptions keep their existing London Wi-Fi Calling exception.
    rules.append(
        {
            "type": "field",
            "network": "udp",
            "port": "500,4500",
            "outboundTag": "uk-direct",
            "ruleTag": "wifi-calling-via-london",
        }
    )
    wifi_prefix_length = len(rules)
    balancers = []
    parent_routes = {}
    parent_limited = {sub["id"]: bool(sub["quota_exceeded"]) for sub in subs}
    limited_subs = []
    limited_children = []
    for sub in subs:
        email = f"sub-{sub['id']}@proxy.local"
        main_emails.append((sub["id"], email))
        users_vless.append({"id": sub["vless_uuid"], "email": email})
        users_trojan.append({"password": sub["trojan_password"], "email": email})
        if sub["quota_exceeded"]:
            limited_subs.append(sub["id"])
            rules.append(
                {"type": "field", "network": "tcp", "user": [email], "outboundTag": f"limited-sub-{sub['id']}"}
            )
            # The local limiter handles TCP.  Block non-Wi-Fi-Calling UDP once
            # the shared parent quota is exhausted so UDP cannot bypass it.
            rules.append(
                {"type": "field", "network": "udp", "user": [email], "outboundTag": "blocked"}
            )
        ids = assigned.get(sub["id"], [])[:3]
        if len(ids) == 1:
            # A single selected SOCKS5 is pinned directly.  This avoids the
            # observatory warm-up window falling back to the server IP after a
            # user explicitly switches exits.
            parent_routes[sub["id"]] = {"outboundTag": f"socks-{ids[0]}"}
        elif ids:
            tag = f"balancer-sub-{sub['id']}"
            # Prefer the lowest-latency healthy exit.  This avoids sending every
            # other connection through a temporarily slow SOCKS server while
            # retaining automatic failover across up to three selected exits.
            ranked_ids = sorted(
                ids,
                key=lambda socks_id: next(
                    (row["latency_ms"] or 999999 for row in socks_rows if row["id"] == socks_id),
                    999999,
                ),
            )
            balancers.append(
                {
                    "tag": tag,
                    "selector": [f"socks-{sid}" for sid in ranked_ids],
                    "fallbackTag": "uk-direct",
                    "strategy": {
                        "type": "leastLoad",
                        "settings": {
                            "expected": 1,
                            "maxRTT": "1s",
                            "tolerance": 0.1,
                            "baselines": ["100ms", "500ms"],
                            "costs": [
                                {
                                    "regexp": False,
                                    "match": f"socks-{socks_id}",
                                    "value": rank * 10,
                                }
                                for rank, socks_id in enumerate(ranked_ids)
                            ],
                        },
                    },
                }
            )
            parent_routes[sub["id"]] = {"balancerTag": tag}
        else:
            parent_routes[sub["id"]] = {"outboundTag": "uk-direct"}
        rules.append({"type": "field", "user": [email], **parent_routes[sub["id"]]})

    for child in children:
        email = f"child-{child['id']}@proxy.local"
        child_emails.append((child["id"], email))
        users_vless.append({"id": child["vless_uuid"], "email": email})
        users_trojan.append({"password": child["trojan_password"], "email": email})
        limited_children.append(child["id"])
        rules.append(
            {"type": "field", "network": "tcp", "user": [email], "outboundTag": f"limited-child-{child['id']}"}
        )
        if parent_limited.get(child["parent_subscription_id"]):
            rules.append(
                {"type": "field", "network": "udp", "user": [email], "outboundTag": "blocked"}
            )
        else:
            # The TCP limiter does not implement SOCKS5 UDP ASSOCIATE.  Route
            # child UDP through the same selected parent exit so XUDP works;
            # UDP 500/4500 was already captured by the first London rule.
            rules.append({
                "type": "field", "network": "udp", "user": [email],
                **parent_routes.get(child["parent_subscription_id"], {"outboundTag": "uk-direct"}),
            })

    if server_traffic["exceeded"]:
        global_rules = []
        if server_traffic["action"] == "disconnect":
            for _, email in main_emails + child_emails:
                global_rules.append({"type": "field", "user": [email], "outboundTag": "blocked"})
        else:
            for sub_id, email in main_emails:
                global_rules.append({
                    "type": "field", "network": "tcp", "user": [email],
                    "outboundTag": f"server-limit-sub-{sub_id}",
                })
                global_rules.append({
                    "type": "field", "network": "udp", "user": [email],
                    "outboundTag": "blocked",
                })
            for child_id, email in child_emails:
                global_rules.append({
                    "type": "field", "network": "tcp", "user": [email],
                    "outboundTag": f"server-limit-child-{child_id}",
                })
                global_rules.append({
                    "type": "field", "network": "udp", "user": [email],
                    "outboundTag": "blocked",
                })
        # Keep Wi-Fi Calling's London UDP route first; enforce the server-wide
        # policy before every per-account route.
        rules[wifi_prefix_length:wifi_prefix_length] = global_rules

    outbounds = [
        {"tag": "blocked", "protocol": "blackhole", "settings": {}},
        {"tag": "uk-direct", "protocol": "freedom", "settings": {}},
    ]
    for account in wifi_accounts:
        outbounds.append(
            {
                "tag": f"wifi-limit-{account['id']}",
                "protocol": "socks",
                "settings": {
                    "address": "127.0.0.1", "port": 11080,
                    "user": f"wifi-{account['id']}", "pass": "local-quota-limiter",
                },
            }
        )
    for sub_id in limited_subs:
        outbounds.append(
            {
                "tag": f"limited-sub-{sub_id}",
                "protocol": "socks",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 11080,
                    "user": f"sub-{sub_id}",
                    "pass": "local-quota-limiter",
                },
            }
        )
    for child_id in limited_children:
        outbounds.append(
            {
                "tag": f"limited-child-{child_id}",
                "protocol": "socks",
                "settings": {
                    "address": "127.0.0.1",
                    "port": 11080,
                    "user": f"child-{child_id}",
                    "pass": "local-quota-limiter",
                },
            }
        )
    if server_traffic["exceeded"] and server_traffic["action"] == "limit":
        for sub_id, _ in main_emails:
            outbounds.append(
                {
                    "tag": f"server-limit-sub-{sub_id}",
                    "protocol": "socks",
                    "settings": {
                        "address": "127.0.0.1", "port": 11080,
                        "user": f"server-sub-{sub_id}", "pass": "local-quota-limiter",
                    },
                }
            )
        for child_id, _ in child_emails:
            outbounds.append(
                {
                    "tag": f"server-limit-child-{child_id}",
                    "protocol": "socks",
                    "settings": {
                        "address": "127.0.0.1", "port": 11080,
                        "user": f"server-child-{child_id}", "pass": "local-quota-limiter",
                    },
                }
            )
    for row in socks_rows:
        settings = {"address": row["host"], "port": row["port"]}
        username = decrypt(row["username_enc"])
        password = decrypt(row["password_enc"])
        if username or password:
            settings.update({"user": username, "pass": password})
        outbounds.append({"tag": f"socks-{row['id']}", "protocol": "socks", "settings": settings})

    return {
        "log": {"access": "none", "loglevel": "warning"},
        "api": {"tag": "api", "listen": XRAY_API, "services": ["StatsService"]},
        "stats": {},
        "policy": {
            "levels": {
                "0": {"statsUserUplink": True, "statsUserDownlink": True}
            }
        },
        "inbounds": [
            {
                "tag": "vless-in",
                "listen": "127.0.0.1",
                "port": 10001,
                "protocol": "vless",
                "settings": {"users": users_vless, "decryption": "none"},
                "streamSettings": {"method": "websocket", "security": "none", "wsSettings": {"path": "/vless"}},
            },
            {
                "tag": "vless-xhttp-in",
                "listen": "127.0.0.1",
                "port": 10003,
                "protocol": "vless",
                "settings": {"users": users_vless, "decryption": "none"},
                "streamSettings": {
                    "method": "xhttp", "security": "none",
                    "xhttpSettings": {"path": "/xhttp", "mode": "auto"},
                },
            },
            {
                "tag": "trojan-in",
                "listen": "127.0.0.1",
                "port": 10002,
                "protocol": "trojan",
                "settings": {"users": users_trojan},
                "streamSettings": {"method": "websocket", "security": "none", "wsSettings": {"path": "/trojan"}},
            },
        ],
        "outbounds": outbounds,
        "routing": {"domainStrategy": "AsIs", "rules": rules, "balancers": balancers},
        "observatory": {
            "subjectSelector": ["socks-"],
            "probeUrl": "https://www.cloudflare.com/cdn-cgi/trace",
            "probeInterval": "30s",
            "enableConcurrency": True,
        },
    }


def rebuild_xray(restart=True, collect_stats=True):
    if restart and collect_stats:
        collect_xray_traffic(rebuild_on_change=False)
    XRAY_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(xray_config(), ensure_ascii=False, indent=2)
    # Health checks run frequently. Do not tear down active TCP/UDP sessions
    # when the generated configuration is byte-for-byte unchanged.
    try:
        unchanged = XRAY_CONFIG.read_text() == payload
    except FileNotFoundError:
        unchanged = False
    if unchanged:
        check_subscriptions()
        return False
    fd, candidate = tempfile.mkstemp(prefix="config-", suffix=".json", dir=XRAY_CONFIG.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(payload)
        result = subprocess.run(
            ["/usr/local/bin/xray", "run", "-test", "-config", candidate],
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode:
            raise RuntimeError((result.stderr or result.stdout).strip())
        os.replace(candidate, XRAY_CONFIG)
        os.chmod(XRAY_CONFIG, 0o640)
        if restart:
            subprocess.run(["sudo", "/bin/systemctl", "restart", "xray"], check=True, timeout=30)
        check_subscriptions()
        return True
    finally:
        if os.path.exists(candidate):
            os.unlink(candidate)


def check_all():
    init_db()
    with db() as conn:
        ids = [r["id"] for r in conn.execute("SELECT id FROM socks ORDER BY id")]
    for socks_id in ids:
        check_one(socks_id)
    rebuild_xray()
    add_event("info", f"定时检测完成，共检查 {len(ids)} 个 SOCKS5")


def check_subscriptions():
    with db() as conn:
        subs = conn.execute("SELECT * FROM subscriptions ORDER BY id").fetchall()
        for sub in subs:
            count = conn.execute(
                """SELECT COUNT(*) FROM subscription_socks ss
                   JOIN socks s ON s.id=ss.socks_id
                   WHERE ss.subscription_id=? AND s.status='active'""",
                (sub["id"],),
            ).fetchone()[0]
            if not sub["enabled"]:
                status, error = "disabled", "订阅已停用"
            elif sub["quota_exceeded"]:
                status, error = "limited", "本月流量已达额度，当前限速 10 Mbps"
            elif count:
                try:
                    decoded = base64.b64decode(subscription_text(sub)).decode()
                    valid = "vless://" in decoded and "trojan://" in decoded
                except Exception:
                    valid = False
                status, error = ("healthy", None) if valid else ("error", "订阅内容生成失败")
            else:
                status, error = "fallback", "SOCKS5 不可用，已自动回落伦敦服务器出口"
            conn.execute(
                "UPDATE subscriptions SET status=?,last_error=?,last_checked_at=? WHERE id=?",
                (status, error, now(), sub["id"]),
            )


def subscription_text(sub):
    label = urllib.parse.quote(sub["name"], safe="")
    host = NODE_DOMAIN
    encoded_host = urllib.parse.quote(host, safe="")
    tls = f"security=tls&allowInsecure=0&host={encoded_host}&sni={encoded_host}&fp=chrome"
    xhttp_h3 = (
        f"vless://{sub['vless_uuid']}@{host}:443?encryption=none&{tls}"
        f"&type=xhttp&path=%2Fxhttp&mode=auto&alpn=h3&packetEncoding=xudp#{label}-VLESS-XHTTP-H3"
    )
    xhttp_h2 = (
        f"vless://{sub['vless_uuid']}@{host}:443?encryption=none&{tls}"
        f"&type=xhttp&path=%2Fxhttp&mode=auto&alpn=h2&packetEncoding=xudp#{label}-VLESS-XHTTP-H2"
    )
    vless = f"vless://{sub['vless_uuid']}@{host}:443?encryption=none&{tls}&type=ws&path=%2Fvless&packetEncoding=xudp#{label}-VLESS-WS"
    trojan = f"trojan://{urllib.parse.quote(sub['trojan_password'], safe='')}@{host}:443?{tls}&type=ws&path=%2Ftrojan#{label}-Trojan-WS"
    raw = f"{xhttp_h3}\n{xhttp_h2}\n{vless}\n{trojan}\n"
    return base64.b64encode(raw.encode()).decode()


def clash_subscription_text(sub, wifi_only=False):
    """Return a Mihomo/Clash Meta profile for Clash Verge and compatible apps."""
    host = NODE_DOMAIN
    xhttp_h3_name = f"{sub['name']}-VLESS-XHTTP-H3"
    xhttp_h2_name = f"{sub['name']}-VLESS-XHTTP-H2"
    vless_name = f"{sub['name']}-VLESS-WS"
    trojan_name = f"{sub['name']}-Trojan-WS"

    def quoted(value):
        # A JSON string is also a valid YAML scalar and safely handles names,
        # passwords and other user-controlled values without another dependency.
        return json.dumps(str(value), ensure_ascii=False)

    routing_rules = (
        "  - DST-PORT,500,PROXY\n  - DST-PORT,4500,PROXY\n  - MATCH,DIRECT"
        if wifi_only else "  - MATCH,PROXY"
    )
    return f"""mixed-port: 7890
allow-lan: false
mode: rule
log-level: warning
ipv6: false
unified-delay: true
tcp-concurrent: true
find-process-mode: strict
global-client-fingerprint: chrome

proxies:
  - name: {quoted(xhttp_h3_name)}
    type: vless
    server: {quoted(host)}
    port: 443
    uuid: {quoted(sub['vless_uuid'])}
    network: xhttp
    tls: true
    udp: true
    servername: {quoted(host)}
    client-fingerprint: chrome
    packet-encoding: xudp
    alpn:
      - h3
    xhttp-opts:
      path: /xhttp
      host: {quoted(host)}
      mode: auto
  - name: {quoted(xhttp_h2_name)}
    type: vless
    server: {quoted(host)}
    port: 443
    uuid: {quoted(sub['vless_uuid'])}
    network: xhttp
    tls: true
    udp: true
    servername: {quoted(host)}
    client-fingerprint: chrome
    packet-encoding: xudp
    alpn:
      - h2
    xhttp-opts:
      path: /xhttp
      host: {quoted(host)}
      mode: auto
  - name: {quoted(vless_name)}
    type: vless
    server: {quoted(host)}
    port: 443
    uuid: {quoted(sub['vless_uuid'])}
    network: ws
    tls: true
    udp: true
    servername: {quoted(host)}
    client-fingerprint: chrome
    packet-encoding: xudp
    ws-opts:
      path: /vless
      headers:
        Host: {quoted(host)}
  - name: {quoted(trojan_name)}
    type: trojan
    server: {quoted(host)}
    port: 443
    password: {quoted(sub['trojan_password'])}
    network: ws
    tls: true
    udp: true
    sni: {quoted(host)}
    skip-cert-verify: false
    client-fingerprint: chrome
    ws-opts:
      path: /trojan
      headers:
        Host: {quoted(host)}

proxy-groups:
  - name: PROXY
    type: fallback
    proxies:
      - {quoted(xhttp_h3_name)}
      - {quoted(xhttp_h2_name)}
      - {quoted(vless_name)}
      - {quoted(trojan_name)}
    url: https://www.gstatic.com/generate_204
    interval: 60
    lazy: true
    timeout: 10000
    max-failed-times: 2
    expected-status: 204

rules:
{routing_rules}
"""


def new_subscription_values():
    return secrets.token_urlsafe(24), str(uuid.uuid4()), secrets.token_urlsafe(24)

