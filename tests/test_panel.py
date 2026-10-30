import os
import secrets
import tempfile
from datetime import datetime, timedelta, timezone

os.environ["PANEL_DATA_DIR"] = tempfile.mkdtemp(prefix="proxy-panel-tests-")
os.environ["XRAY_CONFIG"] = os.path.join(os.environ["PANEL_DATA_DIR"], "xray.json")
os.environ["SESSION_SECRET"] = "test-session-secret"
os.environ["FERNET_KEY"] = "MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA="
os.environ["ADMIN_PASSWORD_HASH"] = "test-password-hash"
os.environ["NODE_DOMAIN"] = "node.example.com"
os.environ["SUB_BASE_URL"] = "https://sub.example.com"

import proxy_panel.app as panel_app
from proxy_panel.core import db, encrypt, init_db, now, xray_config
from proxy_panel.rate_limiter import account_info


def test_routes_exit_switch_and_parent_quota(monkeypatch):
    monkeypatch.setattr(panel_app, "rebuild_xray", lambda *args, **kwargs: False)
    monkeypatch.setattr(
        panel_app, "test_socks",
        lambda host, port, username="", password="", timeout=10: (True, "203.0.113.9", 50, None),
    )
    init_db()
    created = now()
    with db() as conn:
        sock_id = conn.execute(
            """INSERT INTO socks(name,host,port,username_enc,password_enc,status,created_at)
               VALUES(?,?,?,?,?,'active',?)""",
            ("Test", "127.0.0.2", 1080, encrypt("u"), encrypt("p"), created),
        ).lastrowid
        sub_id = conn.execute(
            """INSERT INTO subscriptions
               (name,token,vless_uuid,trojan_password,quota_period_start,created_at,updated_at)
               VALUES(?,?,?,?,?,?,?)""",
            ("Test", secrets.token_urlsafe(24), "11111111-1111-4111-8111-111111111111",
             secrets.token_urlsafe(24), created, created, created),
        ).lastrowid
        plan_id = conn.execute(
            """INSERT INTO secondary_plans
               (parent_subscription_id,name,created_at,updated_at)
               VALUES(?,?,?,?)""",
            (sub_id, "Plan", created, created),
        ).lastrowid
        child_id = conn.execute(
            """INSERT INTO activation_codes
               (plan_id,code,speed_mbps,quota_gb,valid_days,status,token,vless_uuid,
                trojan_password,activated_at,expires_at,created_at)
               VALUES(?,?,?,?,?,'active',?,?,?,?,?,?)""",
            (plan_id, "AAAA-BBBB-CCCC-DDDD", 30, 100, 30, secrets.token_urlsafe(24),
             "22222222-2222-4222-8222-222222222222", secrets.token_urlsafe(24), created,
             (datetime.now(timezone.utc) + timedelta(days=30)).isoformat(timespec="seconds"), created),
        ).lastrowid
        wifi_id = conn.execute(
            """INSERT INTO wifi_access
               (name,token,vless_uuid,trojan_password,created_at,updated_at)
               VALUES(?,?,?,?,?,?)""",
            ("WiFi only", "wifi-test-token", "33333333-3333-4333-8333-333333333333",
             secrets.token_urlsafe(24), created, created),
        ).lastrowid

    app = panel_app.create_app()
    app.config.update(TESTING=True)
    with app.test_client() as client:
        with client.session_transaction() as session:
            session["authenticated"] = True
            session["csrf"] = "test-csrf"
        for path in ("/", "/socks", "/subscriptions", "/secondary", "/activation-codes", "/secondary-accounts", "/settings", "/wifi-calling", "/wifi-access"):
            assert client.get(path).status_code == 200
        wifi_profile = client.get("/w/wifi-test-token?format=clash")
        assert wifi_profile.status_code == 200
        assert b"DST-PORT,500,PROXY" in wifi_profile.data
        assert b"DST-PORT,4500,PROXY" in wifi_profile.data
        assert b"MATCH,DIRECT" in wifi_profile.data
        shadowrocket_profile = client.get("/w/wifi-test-token?format=shadowrocket")
        assert shadowrocket_profile.status_code == 200
        assert b"DST-PORT,500,PROXY" in shadowrocket_profile.data
        assert b"DST-PORT,4500,PROXY" in shadowrocket_profile.data
        assert b"FINAL,DIRECT" in shadowrocket_profile.data
        assert client.post(
            f"/wifi-access/{wifi_id}/speed",
            data={"csrf": "test-csrf", "speed_mbps": "50"},
        ).status_code == 302
        assert client.post(
            f"/subscriptions/{sub_id}/exits",
            data={"csrf": "test-csrf", "socks_id": str(sock_id)},
        ).status_code == 302
        assert client.post(
            "/subscriptions/999999/exits",
            data={"csrf": "test-csrf", "socks_id": str(sock_id)},
        ).status_code == 302

    with db() as conn:
        conn.execute("UPDATE subscriptions SET quota_exceeded=1 WHERE id=?", (sub_id,))
    config = xray_config()
    users = config["inbounds"][0]["settings"]["users"]
    assert any(user["email"] == f"child-{child_id}@proxy.local" for user in users)
    assert (f"parent-{sub_id}", 10) in account_info(f"child-{child_id}")[1]
    assert any(
        rule.get("user") == [f"child-{child_id}@proxy.local"]
        and rule.get("network") == "udp" and rule.get("outboundTag") == "blocked"
        for rule in config["routing"]["rules"]
    )
    assert account_info(f"wifi-{wifi_id}")[1] == [(f"wifi-{wifi_id}", 50)]
    assert any(
        rule.get("user") == [f"wifi-{wifi_id}@proxy.local"]
        and rule.get("port") == "500,4500"
        and rule.get("outboundTag") == f"wifi-limit-{wifi_id}"
        for rule in config["routing"]["rules"]
    )
    assert any(
        rule.get("user") == [f"wifi-{wifi_id}@proxy.local"]
        and rule.get("outboundTag") == "blocked"
        for rule in config["routing"]["rules"]
    )
