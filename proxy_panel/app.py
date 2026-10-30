import base64
import os
import secrets
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from functools import wraps
from zoneinfo import ZoneInfo

from flask import Flask, Response, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .core import (
    GIB,
    TIB,
    add_event,
    clash_subscription_text,
    check_one,
    db,
    decrypt,
    encrypt,
    get_setting,
    init_db,
    new_subscription_values,
    rebuild_xray,
    subscription_text,
    set_setting,
    test_socks,
    now,
    quota_period_start,
    server_traffic_status,
)


def profile_title(value):
    """Encode subscription titles as an ASCII-safe HTTP header value."""
    encoded = base64.b64encode(str(value or "Subscription").encode("utf-8")).decode("ascii")
    return f"base64:{encoded}"


def allocation_summary(conn, parent_id, exclude_code_id=None):
    parent = conn.execute(
        "SELECT id,name,quota_gb FROM subscriptions WHERE id=?", (parent_id,)
    ).fetchone()
    if not parent:
        return None
    sql = """SELECT COALESCE(SUM(a.quota_gb),0) FROM activation_codes a
             JOIN secondary_plans p ON p.id=a.plan_id WHERE p.parent_subscription_id=?"""
    params = [parent_id]
    if exclude_code_id is not None:
        sql += " AND a.id<>?"
        params.append(exclude_code_id)
    allocated = float(conn.execute(sql, params).fetchone()[0] or 0)
    return {
        "quota_gb": float(parent["quota_gb"]),
        "allocated_gb": allocated,
        "remaining_gb": max(0, float(parent["quota_gb"]) - allocated),
        "name": parent["name"],
    }


def create_app():
    app = Flask(__name__)
    sub_base_url = os.environ.get("SUB_BASE_URL", "https://sub.example.com").rstrip("/")
    app.secret_key = os.environ["SESSION_SECRET"]
    app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")

    @app.template_filter("dual_time")
    def dual_time(value):
        if not value:
            return "—"
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        london = parsed.astimezone(ZoneInfo("Europe/London"))
        singapore = parsed.astimezone(ZoneInfo("Asia/Singapore"))
        return f"英国 {london:%Y-%m-%d %H:%M:%S %Z} · 新加坡 {singapore:%Y-%m-%d %H:%M:%S SGT}"

    @app.template_filter("traffic_gb")
    def traffic_gb(value):
        return f"{int(value or 0) / GIB:.2f}"

    @app.template_filter("traffic_tb")
    def traffic_tb(value):
        return f"{int(value or 0) / TIB:.3f}"

    init_db()
    login_attempts = {}
    attempts_lock = threading.Lock()
    rebuild_lock = threading.Lock()
    rebuild_state = {"generation": 0, "running": False}

    def schedule_rebuild():
        """Coalesce config changes and restart Xray after the HTTP response."""
        with rebuild_lock:
            rebuild_state["generation"] += 1
            if rebuild_state["running"]:
                return
            rebuild_state["running"] = True

        def worker():
            while True:
                with rebuild_lock:
                    generation = rebuild_state["generation"]
                # Give the redirect response time to reach an administrator who
                # may currently be connected through this same Xray instance.
                time.sleep(3)
                try:
                    rebuild_xray()
                except Exception as exc:
                    add_event("error", f"Xray 配置更新失败：{str(exc)[:300]}")
                with rebuild_lock:
                    if generation == rebuild_state["generation"]:
                        rebuild_state["running"] = False
                        return

        threading.Thread(target=worker, name="xray-rebuild", daemon=True).start()

    def wifi_call_data(history_limit=60):
        cutoff = int(time.time()) - 86400
        with db() as conn:
            latest_rows = conn.execute(
                """SELECT c.* FROM wifi_call_checks c
                   JOIN (SELECT carrier, MAX(id) AS id FROM wifi_call_checks GROUP BY carrier) x
                   ON c.id=x.id ORDER BY c.carrier"""
            ).fetchall()
            rate_rows = conn.execute(
                """SELECT carrier, COUNT(*) AS tests, SUM(ok) AS successes
                   FROM wifi_call_checks WHERE checked_at_epoch>=? GROUP BY carrier""",
                (cutoff,),
            ).fetchall()
            history = conn.execute(
                "SELECT * FROM wifi_call_checks ORDER BY id DESC LIMIT ?", (history_limit,)
            ).fetchall()
        rates = {
            row["carrier"]: round((row["successes"] or 0) * 100 / row["tests"], 1)
            for row in rate_rows
        }
        latest = [dict(row) | {"rate_24h": rates.get(row["carrier"], 0)} for row in latest_rows]
        return latest, history

    def logged_in():
        return bool(session.get("authenticated"))

    def login_required(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            if not logged_in():
                return redirect(url_for("login"))
            return fn(*args, **kwargs)
        return wrapped

    @app.context_processor
    def inject_csrf():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        return {"csrf_token": session["csrf"], "sub_base_url": sub_base_url, "GIB": GIB, "TIB": TIB}

    @app.before_request
    def csrf_check():
        if request.method == "POST":
            if not secrets.compare_digest(session.get("csrf", ""), request.form.get("csrf", "")):
                return "CSRF validation failed", 400

    @app.get("/login")
    def login():
        if logged_in():
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.post("/login")
    def login_post():
        client_ip = request.headers.get("CF-Connecting-IP", request.remote_addr or "unknown")
        current = time.time()
        with attempts_lock:
            recent = [stamp for stamp in login_attempts.get(client_ip, []) if current - stamp < 900]
            login_attempts[client_ip] = recent
            if len(recent) >= 5:
                return "登录失败次数过多，请 15 分钟后再试", 429
        if check_password_hash(get_setting("admin_password_hash"), request.form.get("password", "")):
            with attempts_lock:
                login_attempts.pop(client_ip, None)
            session.clear()
            session["authenticated"] = True
            session["csrf"] = secrets.token_urlsafe(24)
            return redirect(url_for("dashboard"))
        with attempts_lock:
            login_attempts.setdefault(client_ip, []).append(current)
        flash("密码不正确", "error")
        return redirect(url_for("login"))

    @app.post("/logout")
    @login_required
    def logout():
        session.clear()
        return redirect(url_for("login"))

    @app.post("/password")
    @login_required
    def change_password():
        current = request.form.get("current_password", "")
        new = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not check_password_hash(get_setting("admin_password_hash"), current):
            flash("当前密码不正确", "error")
        elif len(new) < 12:
            flash("新密码至少需要 12 个字符", "error")
        elif new != confirm:
            flash("两次输入的新密码不一致", "error")
        else:
            set_setting("admin_password_hash", generate_password_hash(new))
            add_event("warning", "管理员密码已修改")
            flash("管理员密码已修改", "success")
        return redirect(url_for("settings_page"))

    @app.post("/server-traffic")
    @login_required
    def server_traffic_update():
        current_limit = get_setting("server_traffic_limit_mbps") or "10"
        try:
            quota_tb = float(request.form.get("quota_tb", "2"))
            limit_mbps = int(request.form.get("limit_mbps") or current_limit)
        except ValueError:
            quota_tb, limit_mbps = 0, 0
        action = request.form.get("action", "limit")
        return_endpoint = "dashboard" if request.form.get("return_to") == "dashboard" else "settings_page"
        if not 0.01 <= quota_tb <= 10000 or not 1 <= limit_mbps <= 10000 or action not in {"limit", "disconnect"}:
            flash("服务器总流量设置不正确", "error")
            return redirect(url_for(return_endpoint))
        set_setting("server_traffic_quota_tb", f"{quota_tb:g}")
        set_setting("server_traffic_limit_mbps", str(limit_mbps))
        set_setting("server_traffic_action", action)
        schedule_rebuild()
        add_event("info", f"服务器总流量策略更新：{quota_tb:g} TB，达到后{'断开' if action == 'disconnect' else f'限速 {limit_mbps} Mbps'}")
        flash("服务器总流量策略已更新", "success")
        return redirect(url_for(return_endpoint))

    @app.post("/server-traffic/reset")
    @login_required
    def server_traffic_reset():
        set_setting("server_traffic_used_bytes", "0")
        set_setting("server_traffic_period_start", quota_period_start())
        schedule_rebuild()
        add_event("warning", "服务器本月总流量已手动清零")
        flash("服务器本月总流量已清零", "success")
        return redirect(url_for("settings_page"))

    @app.get("/")
    @login_required
    def dashboard():
        with db() as conn:
            socks = conn.execute("SELECT * FROM socks ORDER BY id DESC").fetchall()
            subs = conn.execute("SELECT * FROM subscriptions ORDER BY id DESC").fetchall()
            events = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 8").fetchall()
        wifi_latest, _ = wifi_call_data(0)
        return render_template(
            "overview.html", socks=socks, subs=subs, events=events,
            wifi_latest=wifi_latest, server_traffic=server_traffic_status(),
        )

    @app.get("/socks")
    @login_required
    def socks_page():
        with db() as conn:
            socks = conn.execute("SELECT * FROM socks ORDER BY id DESC").fetchall()
        return render_template("socks.html", socks=socks)

    @app.get("/subscriptions")
    @login_required
    def subscriptions_page():
        with db() as conn:
            socks = conn.execute("SELECT * FROM socks ORDER BY id DESC").fetchall()
            subs = conn.execute(
                """SELECT s.*,
                   (SELECT COALESCE(SUM(a.quota_gb),0) FROM activation_codes a
                    JOIN secondary_plans p ON p.id=a.plan_id WHERE p.parent_subscription_id=s.id) AS allocated_gb
                   FROM subscriptions s ORDER BY s.id DESC"""
            ).fetchall()
            links = conn.execute(
                """SELECT ss.subscription_id,ss.socks_id,ss.position,s.name,s.exit_ip,s.latency_ms,s.status
                   FROM subscription_socks ss JOIN socks s ON s.id=ss.socks_id
                   ORDER BY ss.subscription_id,ss.position"""
            ).fetchall()
        selected = {}
        selected_details = {}
        for link in links:
            selected.setdefault(link["subscription_id"], []).append(link["socks_id"])
            selected_details.setdefault(link["subscription_id"], []).append(dict(link))
        return render_template(
            "subscriptions.html",
            socks=socks,
            subs=subs,
            selected=selected,
            selected_details=selected_details,
            create_request_key=secrets.token_urlsafe(24),
        )

    @app.get("/settings")
    @login_required
    def settings_page():
        with db() as conn:
            events = conn.execute("SELECT * FROM events ORDER BY id DESC LIMIT 100").fetchall()
        return render_template("settings.html", events=events, server_traffic=server_traffic_status())

    @app.get("/wifi-calling")
    @login_required
    def wifi_calling_page():
        latest, history = wifi_call_data()
        return render_template("wifi_calling.html", latest=latest, history=history)

    @app.get("/secondary")
    @login_required
    def secondary_page():
        try:
            parent_filter = int(request.args.get("parent_id", "0"))
        except ValueError:
            parent_filter = 0
        with db() as conn:
            expired = conn.execute(
                "DELETE FROM activation_codes WHERE status='active' AND expires_at<=?", (now(),)
            ).rowcount
            plan_sql = (
                """SELECT p.*,s.name AS parent_name,
                   (SELECT COUNT(*) FROM activation_codes a WHERE a.plan_id=p.id) AS code_count,
                   (SELECT COUNT(*) FROM activation_codes a WHERE a.plan_id=p.id AND a.status='active') AS active_count,
                   s.quota_gb AS parent_quota_gb,
                   (SELECT COALESCE(SUM(a.quota_gb),0) FROM activation_codes a
                    JOIN secondary_plans px ON px.id=a.plan_id WHERE px.parent_subscription_id=s.id) AS parent_allocated_gb
                   FROM secondary_plans p JOIN subscriptions s ON s.id=p.parent_subscription_id
                   """
            )
            plan_params = []
            if parent_filter:
                plan_sql += " WHERE p.parent_subscription_id=?"
                plan_params.append(parent_filter)
            plan_sql += " ORDER BY p.id DESC"
            plans = conn.execute(plan_sql, plan_params).fetchall()
            subs = conn.execute("SELECT id,name,enabled FROM subscriptions ORDER BY id DESC").fetchall()
        if expired:
            schedule_rebuild()
        return render_template("secondary.html", plans=plans, subs=subs, parent_filter=parent_filter)

    @app.get("/activation-codes")
    @login_required
    def activation_codes_page():
        query = request.args.get("q", "").strip().upper()
        normalized = "".join(ch for ch in query if ch.isalnum())
        try:
            parent_filter = int(request.args.get("parent_id", "0"))
        except ValueError:
            parent_filter = 0
        with db() as conn:
            plans = conn.execute(
                """SELECT p.*,s.name AS parent_name,s.quota_gb AS parent_quota_gb,
                   (SELECT COALESCE(SUM(ax.quota_gb),0) FROM activation_codes ax
                    JOIN secondary_plans px ON px.id=ax.plan_id WHERE px.parent_subscription_id=s.id) AS parent_allocated_gb,
                   (SELECT COUNT(*) FROM activation_codes a WHERE a.plan_id=p.id AND a.status='unused') AS unused_count
                   FROM secondary_plans p JOIN subscriptions s ON s.id=p.parent_subscription_id
                   ORDER BY p.id DESC"""
            ).fetchall()
            code_sql = """SELECT a.*,p.name AS plan_name,s.name AS parent_name,s.id AS parent_id
                          FROM activation_codes a JOIN secondary_plans p ON p.id=a.plan_id
                          JOIN subscriptions s ON s.id=p.parent_subscription_id WHERE 1=1"""
            params = []
            if normalized:
                code_sql += " AND REPLACE(UPPER(a.code),'-','') LIKE ?"
                params.append(f"%{normalized}%")
            else:
                code_sql += " AND a.status='unused'"
            if parent_filter:
                code_sql += " AND s.id=?"
                params.append(parent_filter)
            code_sql += " ORDER BY a.id DESC LIMIT 500"
            codes = conn.execute(code_sql, params).fetchall()
            parents = conn.execute("SELECT id,name FROM subscriptions ORDER BY name").fetchall()
        return render_template(
            "activation_codes.html", plans=plans, codes=codes, query=query,
            parent_filter=parent_filter, parents=parents,
        )

    @app.get("/secondary-accounts")
    @login_required
    def secondary_accounts_page():
        query = request.args.get("q", "").strip().upper()
        normalized = "".join(ch for ch in query if ch.isalnum())
        try:
            parent_filter = int(request.args.get("parent_id", "0"))
        except ValueError:
            parent_filter = 0
        with db() as conn:
            expired = conn.execute(
                "DELETE FROM activation_codes WHERE status='active' AND expires_at<=?", (now(),)
            ).rowcount
            sql = """SELECT a.*,p.name AS plan_name,s.name AS parent_name,s.id AS parent_id FROM activation_codes a
                   JOIN secondary_plans p ON p.id=a.plan_id
                   JOIN subscriptions s ON s.id=p.parent_subscription_id
                   WHERE a.status='active'"""
            params = []
            if normalized:
                sql += " AND REPLACE(UPPER(a.code),'-','') LIKE ?"
                params.append(f"%{normalized}%")
            if parent_filter:
                sql += " AND s.id=?"
                params.append(parent_filter)
            sql += " ORDER BY a.id DESC LIMIT 500"
            accounts = conn.execute(sql, params).fetchall()
            parents = conn.execute("SELECT id,name FROM subscriptions ORDER BY name").fetchall()
        if expired:
            schedule_rebuild()
        return render_template(
            "secondary_accounts.html", accounts=accounts, query=query,
            parent_filter=parent_filter, parents=parents,
        )

    @app.post("/secondary")
    @login_required
    def secondary_add():
        name = request.form.get("name", "").strip()
        try:
            parent_id = int(request.form.get("parent_subscription_id", "0"))
            speed = int(request.form.get("speed_mbps", "10"))
            quota = float(request.form.get("quota_gb", "100"))
            days = int(request.form.get("valid_days", "30"))
        except ValueError:
            parent_id, speed, quota, days = 0, 0, 0, 0
        if not name or not 10 <= speed <= 100 or not 0 < quota <= 1_000_000 or not 1 <= days <= 3650:
            flash("名称、速度、流量或有效期不正确", "error")
            return redirect(url_for("secondary_page"))
        with db() as conn:
            if not conn.execute("SELECT 1 FROM subscriptions WHERE id=?", (parent_id,)).fetchone():
                flash("关联的主订阅不存在", "error")
                return redirect(url_for("secondary_page"))
            conn.execute(
                """INSERT INTO secondary_plans(parent_subscription_id,name,default_speed_mbps,
                   default_quota_gb,default_valid_days,created_at,updated_at) VALUES(?,?,?,?,?,?,?)""",
                (parent_id, name, speed, quota, days, now(), now()),
            )
        flash("二级订阅已创建", "success")
        return redirect(url_for("secondary_page"))

    @app.post("/secondary/<int:plan_id>/update")
    @login_required
    def secondary_update(plan_id):
        name = request.form.get("name", "").strip()
        try:
            parent_id = int(request.form.get("parent_subscription_id", "0"))
            speed = int(request.form.get("speed_mbps", "0"))
            quota = float(request.form.get("quota_gb", "0"))
            days = int(request.form.get("valid_days", "0"))
        except ValueError:
            parent_id, speed, quota, days = 0, 0, 0, 0
        if not name or not 10 <= speed <= 100 or quota <= 0 or not 1 <= days <= 3650:
            flash("修改值不正确", "error")
            return redirect(url_for("secondary_page"))
        with db() as conn:
            if not conn.execute("SELECT 1 FROM subscriptions WHERE id=?", (parent_id,)).fetchone():
                flash("关联的主订阅不存在", "error")
                return redirect(url_for("secondary_page"))
            conn.execute(
                """UPDATE secondary_plans SET parent_subscription_id=?,name=?,default_speed_mbps=?,
                   default_quota_gb=?,default_valid_days=?,updated_at=? WHERE id=?""",
                (parent_id, name, speed, quota, days, now(), plan_id),
            )
        schedule_rebuild()
        flash("二级订阅参数已更新", "success")
        return redirect(url_for("secondary_page"))

    @app.post("/secondary/<int:plan_id>/codes")
    @login_required
    def secondary_codes_add(plan_id):
        try:
            count = int(request.form.get("count", "1"))
            speed = int(request.form.get("speed_mbps", "0"))
            quota = float(request.form.get("quota_gb", "0"))
            days = int(request.form.get("valid_days", "0"))
        except ValueError:
            count, speed, quota, days = 0, 0, 0, 0
        if not 1 <= count <= 500 or not 10 <= speed <= 100 or quota <= 0 or not 1 <= days <= 3650:
            flash("激活码参数不正确；单次最多生成 500 个", "error")
            return redirect(url_for("activation_codes_page"))
        created = []
        with db() as conn:
            plan = conn.execute(
                "SELECT * FROM secondary_plans WHERE id=?", (plan_id,)
            ).fetchone()
            if not plan:
                flash("二级订阅不存在", "error")
                return redirect(url_for("activation_codes_page"))
            allocation = allocation_summary(conn, plan["parent_subscription_id"])
            required = count * quota
            if not allocation or required > allocation["remaining_gb"] + 1e-9:
                remaining = allocation["remaining_gb"] if allocation else 0
                flash(
                    f"主订阅只剩 {remaining:g} GB 流量可分配，本次生成需要 {required:g} GB；"
                    "由于流量不足，暂时无法生成，你可以去修改主订阅配额来恢复。",
                    "error",
                )
                return redirect(url_for("activation_codes_page"))
            for _ in range(count):
                while True:
                    raw = secrets.token_hex(8).upper()
                    code = "-".join(raw[i:i + 4] for i in range(0, 16, 4))
                    try:
                        conn.execute(
                            """INSERT INTO activation_codes(plan_id,code,speed_mbps,quota_gb,
                               valid_days,created_at) VALUES(?,?,?,?,?,?)""",
                            (plan_id, code, speed, quota, days, now()),
                        )
                        created.append(code)
                        break
                    except sqlite3.IntegrityError:
                        continue
        flash(f"已生成 {len(created)} 个激活码", "success")
        return redirect(url_for("activation_codes_page"))

    @app.post("/activation/<int:code_id>/update")
    @login_required
    def activation_update(code_id):
        try:
            speed = int(request.form.get("speed_mbps", "0"))
            quota = float(request.form.get("quota_gb", "0"))
            days = int(request.form.get("valid_days", "0"))
        except ValueError:
            speed, quota, days = 0, 0, 0
        if not 10 <= speed <= 100 or quota <= 0 or not 1 <= days <= 3650:
            flash("激活码参数不正确", "error")
            return redirect(url_for("secondary_accounts_page" if request.form.get("source") == "accounts" else "activation_codes_page"))
        with db() as conn:
            row = conn.execute("SELECT * FROM activation_codes WHERE id=?", (code_id,)).fetchone()
            if not row:
                flash("激活码不存在", "error")
                return redirect(url_for("secondary_accounts_page" if request.form.get("source") == "accounts" else "activation_codes_page"))
            plan = conn.execute("SELECT parent_subscription_id FROM secondary_plans WHERE id=?", (row["plan_id"],)).fetchone()
            allocation = allocation_summary(conn, plan["parent_subscription_id"], code_id) if plan else None
            if not allocation or quota > allocation["remaining_gb"] + 1e-9:
                remaining = allocation["remaining_gb"] if allocation else 0
                flash(
                    f"主订阅只剩 {remaining:g} GB 流量可分配，本次修改需要 {quota:g} GB；请先提高主订阅配额。",
                    "error",
                )
                return redirect(url_for("secondary_accounts_page" if request.form.get("source") == "accounts" else "activation_codes_page"))
            expires = row["expires_at"]
            if row["activated_at"]:
                activated = datetime.fromisoformat(row["activated_at"])
                expires = (activated + timedelta(days=days)).isoformat(timespec="seconds")
            exceeded = int(int(row["used_bytes"] or 0) >= quota * GIB)
            conn.execute(
                """UPDATE activation_codes SET speed_mbps=?,quota_gb=?,valid_days=?,
                   expires_at=?,quota_exceeded=? WHERE id=?""",
                (speed, quota, days, expires, exceeded, code_id),
            )
        schedule_rebuild()
        flash("激活码参数已更新", "success")
        return redirect(url_for("secondary_accounts_page" if request.form.get("source") == "accounts" else "activation_codes_page"))

    @app.post("/activation/<int:code_id>/delete")
    @login_required
    def activation_delete(code_id):
        with db() as conn:
            row = conn.execute("SELECT status FROM activation_codes WHERE id=?", (code_id,)).fetchone()
            conn.execute("DELETE FROM activation_codes WHERE id=?", (code_id,))
        if row and row["status"] == "active":
            schedule_rebuild()
        flash("激活码及其账号已删除", "success")
        return redirect(url_for("secondary_accounts_page" if row and row["status"] == "active" else "activation_codes_page"))

    @app.post("/activations/bulk-delete")
    @login_required
    def activation_bulk_delete():
        target = "secondary_accounts_page" if request.form.get("source") == "accounts" else "activation_codes_page"
        ids = []
        for value in request.form.getlist("code_id")[:500]:
            try:
                ids.append(int(value))
            except ValueError:
                continue
        if not ids:
            flash("请先选择要删除的激活码或三级账号", "error")
            return redirect(url_for(target))
        placeholders = ",".join("?" for _ in ids)
        with db() as conn:
            active = conn.execute(
                f"SELECT COUNT(*) FROM activation_codes WHERE status='active' AND id IN ({placeholders})", ids
            ).fetchone()[0]
            deleted = conn.execute(
                f"DELETE FROM activation_codes WHERE id IN ({placeholders})", ids
            ).rowcount
        if active:
            schedule_rebuild()
        flash(f"已删除 {deleted} 条激活码/三级账号", "success")
        return redirect(url_for(target))

    @app.post("/secondary/<int:plan_id>/delete")
    @login_required
    def secondary_delete(plan_id):
        with db() as conn:
            conn.execute("DELETE FROM secondary_plans WHERE id=?", (plan_id,))
        schedule_rebuild()
        flash("二级订阅、激活码及账号已全部删除", "success")
        return redirect(url_for("secondary_page"))

    @app.post("/socks")
    @login_required
    def socks_add():
        name = request.form.get("name", "").strip()
        host = request.form.get("host", "").strip()
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        try:
            port = int(request.form.get("port", "0"))
        except ValueError:
            port = 0
        if not name or not host or not 1 <= port <= 65535:
            flash("名称、地址或端口不正确", "error")
            return redirect(url_for("socks_page"))
        with db() as conn:
            if conn.execute("SELECT COUNT(*) FROM socks").fetchone()[0] >= 30:
                flash("SOCKS5 数量已达到 30 个上限", "error")
                return redirect(url_for("socks_page"))
        ok, exit_ip, latency, error = test_socks(host, port, username, password)
        if not ok:
            flash(f"代理检测失败，未添加：{error}", "error")
            return redirect(url_for("socks_page"))
        with db() as conn:
            conn.execute(
                "INSERT INTO socks(name,host,port,username_enc,password_enc,status,exit_ip,latency_ms,last_checked_at,created_at) VALUES(?,?,?,?,?,'active',?,?,?,?)",
                (name, host, port, encrypt(username), encrypt(password), exit_ip, latency, now(), now()),
            )
        schedule_rebuild()
        add_event("success", f"添加 SOCKS5 {name}，出口 {exit_ip}")
        flash(f"添加成功，出口 {exit_ip}，延迟 {latency} ms", "success")
        return redirect(url_for("socks_page"))

    @app.post("/socks/<int:socks_id>/test")
    @login_required
    def socks_test(socks_id):
        ok, message = check_one(socks_id)
        schedule_rebuild()
        flash(("检测成功：" if ok else "检测失败：") + str(message), "success" if ok else "error")
        return redirect(url_for("socks_page"))

    @app.post("/socks/<int:socks_id>/delete")
    @login_required
    def socks_delete(socks_id):
        with db() as conn:
            row = conn.execute("SELECT name FROM socks WHERE id=?", (socks_id,)).fetchone()
            conn.execute("DELETE FROM socks WHERE id=?", (socks_id,))
        schedule_rebuild()
        if row:
            add_event("warning", f"手动删除 SOCKS5 {row['name']}")
        flash("已删除", "success")
        return redirect(url_for("socks_page"))

    @app.post("/subscriptions")
    @login_required
    def subscription_add():
        name = request.form.get("name", "").strip()
        request_key = request.form.get("request_key", "").strip()
        sock_ids = list(dict.fromkeys(request.form.getlist("socks_id")))
        try:
            quota_gb = float(request.form.get("quota_gb", "1000"))
        except ValueError:
            quota_gb = 0
        if not name:
            flash("请输入订阅名称", "error")
            return redirect(url_for("subscriptions_page"))
        if len(sock_ids) > 3:
            flash("每个订阅最多选择 3 个出口", "error")
            return redirect(url_for("subscriptions_page"))
        if len(request_key) < 20:
            flash("创建请求已过期，请刷新页面后重试", "error")
            return redirect(url_for("subscriptions_page"))
        if not 0 < quota_gb <= 1_000_000:
            flash("流量额度必须在 0 到 1,000,000 GB 之间", "error")
            return redirect(url_for("subscriptions_page"))
        token, vless_uuid, trojan_password = new_subscription_values()
        try:
            with db() as conn:
                existing = conn.execute(
                    "SELECT id FROM subscriptions WHERE name=? COLLATE NOCASE OR request_key=?",
                    (name, request_key),
                ).fetchone()
                if existing:
                    flash("该订阅已经创建，请勿重复提交", "success")
                    return redirect(url_for("subscriptions_page"))
                valid = {str(r["id"]) for r in conn.execute("SELECT id FROM socks WHERE status='active'")}
                if any(sid not in valid for sid in sock_ids):
                    flash("只能选择检测正常的 SOCKS5", "error")
                    return redirect(url_for("subscriptions_page"))
                cur = conn.execute(
                    """INSERT INTO subscriptions
                       (name,token,vless_uuid,trojan_password,request_key,quota_gb,
                        quota_period_start,created_at,updated_at)
                       VALUES(?,?,?,?,?,?,?,?,?)""",
                    (
                        name, token, vless_uuid, trojan_password, request_key,
                        quota_gb, quota_period_start(), now(), now(),
                    ),
                )
                sub_id = cur.lastrowid
                for position, sid in enumerate(sock_ids):
                    conn.execute("INSERT INTO subscription_socks(subscription_id,socks_id,position) VALUES(?,?,?)", (sub_id, int(sid), position))
        except sqlite3.IntegrityError:
            flash("该订阅已经创建，请勿重复提交", "success")
            return redirect(url_for("subscriptions_page"))
        schedule_rebuild()
        add_event("success", f"创建订阅 {name}")
        flash("订阅已创建", "success")
        return redirect(url_for("subscriptions_page"))

    @app.post("/subscriptions/<int:sub_id>/exits")
    @login_required
    def subscription_exits(sub_id):
        sock_ids = list(dict.fromkeys(request.form.getlist("socks_id")))
        if len(sock_ids) > 3:
            flash("每个订阅最多选择 3 个出口", "error")
            return redirect(url_for("subscriptions_page"))
        try:
            numeric_sock_ids = [int(sid) for sid in sock_ids]
        except (TypeError, ValueError):
            flash("出口选择无效，请重新选择", "error")
            return redirect(url_for("subscriptions_page"))
        tested = []
        with db() as conn:
            if not conn.execute("SELECT 1 FROM subscriptions WHERE id=?", (sub_id,)).fetchone():
                flash("主订阅不存在或已被删除", "error")
                return redirect(url_for("subscriptions_page"))
            rows = conn.execute(
                f"SELECT * FROM socks WHERE status='active' AND id IN ({','.join('?' for _ in sock_ids)})" if sock_ids else "SELECT * FROM socks WHERE 0",
                numeric_sock_ids,
            ).fetchall()
        rows_by_id = {row["id"]: row for row in rows}
        if any(socks_id not in rows_by_id for socks_id in numeric_sock_ids):
            flash("出口选择无效、已停用或已经不存在", "error")
            return redirect(url_for("subscriptions_page"))

        def probe(row):
            result = test_socks(
                row["host"], row["port"], decrypt(row["username_enc"]),
                decrypt(row["password_enc"]), timeout=10,
            )
            return row, result

        probe_results = {}
        if rows:
            with ThreadPoolExecutor(max_workers=len(rows), thread_name_prefix="exit-probe") as executor:
                futures = [executor.submit(probe, row) for row in rows]
                for future in as_completed(futures):
                    row, (ok, exit_ip, latency, error) = future.result()
                    if not ok:
                        flash(f"出口 {row['name']} 实测失败，未保存：{error}", "error")
                        return redirect(url_for("subscriptions_page"))
                    probe_results[row["id"]] = (exit_ip, latency)
        tested = [(socks_id, *probe_results[socks_id]) for socks_id in numeric_sock_ids]
        with db() as conn:
            if not conn.execute("SELECT 1 FROM subscriptions WHERE id=?", (sub_id,)).fetchone():
                flash("主订阅在检测期间已被删除，未保存出口", "error")
                return redirect(url_for("subscriptions_page"))
            for socks_id, exit_ip, latency in tested:
                conn.execute(
                    "UPDATE socks SET status='active',exit_ip=?,latency_ms=?,fail_count=0,last_error=NULL,last_checked_at=? WHERE id=?",
                    (exit_ip, latency, now(), socks_id),
                )
            conn.execute("DELETE FROM subscription_socks WHERE subscription_id=?", (sub_id,))
            for position, sid in enumerate(sock_ids):
                conn.execute("INSERT INTO subscription_socks(subscription_id,socks_id,position) VALUES(?,?,?)", (sub_id, int(sid), position))
            conn.execute("UPDATE subscriptions SET updated_at=? WHERE id=?", (now(), sub_id))
        schedule_rebuild()
        summary = "伦敦服务器兜底" if not tested else "、".join(f"{ip} ({latency} ms)" for _, ip, latency in tested)
        add_event("info", f"订阅 #{sub_id} 出口切换为 {summary}")
        flash(f"出口已实测并更新：{summary}", "success")
        return redirect(url_for("subscriptions_page"))

    @app.post("/subscriptions/<int:sub_id>/reset")
    @login_required
    def subscription_reset(sub_id):
        token, vless_uuid, trojan_password = new_subscription_values()
        with db() as conn:
            updated = conn.execute(
                "UPDATE subscriptions SET token=?,vless_uuid=?,trojan_password=?,updated_at=? WHERE id=?",
                (token, vless_uuid, trojan_password, now(), sub_id),
            ).rowcount
        if not updated:
            flash("订阅不存在", "error")
            return redirect(url_for("subscriptions_page"))
        schedule_rebuild()
        add_event("warning", f"重置订阅 #{sub_id}，旧链接已失效")
        flash("订阅凭据已重置，旧链接立即失效", "success")
        return redirect(url_for("subscriptions_page"))

    @app.post("/subscriptions/<int:sub_id>/quota")
    @login_required
    def subscription_quota(sub_id):
        try:
            quota_gb = float(request.form.get("quota_gb", "0"))
        except ValueError:
            quota_gb = 0
        if not 0 < quota_gb <= 1_000_000:
            flash("流量额度必须在 0 到 1,000,000 GB 之间", "error")
            return redirect(url_for("subscriptions_page"))
        with db() as conn:
            row = conn.execute(
                "SELECT name,used_bytes,quota_exceeded FROM subscriptions WHERE id=?", (sub_id,)
            ).fetchone()
            if not row:
                flash("订阅不存在", "error")
                return redirect(url_for("subscriptions_page"))
            allocated = conn.execute(
                """SELECT COALESCE(SUM(a.quota_gb),0) FROM activation_codes a
                   JOIN secondary_plans p ON p.id=a.plan_id WHERE p.parent_subscription_id=?""",
                (sub_id,),
            ).fetchone()[0]
            if quota_gb + 1e-9 < float(allocated or 0):
                flash(f"当前已向激活码分配 {float(allocated):g} GB，主订阅额度不能低于该值", "error")
                return redirect(url_for("subscriptions_page"))
            exceeded = int(int(row["used_bytes"] or 0) >= quota_gb * GIB)
            changed = exceeded != int(row["quota_exceeded"])
            conn.execute(
                "UPDATE subscriptions SET quota_gb=?,quota_exceeded=?,updated_at=? WHERE id=?",
                (quota_gb, exceeded, now(), sub_id),
            )
        if changed:
            schedule_rebuild()
        add_event("info", f"订阅 {row['name']} 流量额度调整为 {quota_gb:g} GB")
        flash("流量额度已更新", "success")
        return redirect(url_for("subscriptions_page"))

    @app.post("/subscriptions/<int:sub_id>/quota-reset")
    @login_required
    def subscription_quota_reset(sub_id):
        with db() as conn:
            row = conn.execute("SELECT name FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
            if not row:
                flash("订阅不存在", "error")
                return redirect(url_for("subscriptions_page"))
            conn.execute(
                """UPDATE subscriptions SET used_bytes=0,direct_used_bytes=0,quota_exceeded=0,
                   quota_period_start=?,updated_at=? WHERE id=?""",
                (quota_period_start(), now(), sub_id),
            )
            conn.execute(
                """UPDATE activation_codes SET parent_period_bytes=0 WHERE plan_id IN
                   (SELECT id FROM secondary_plans WHERE parent_subscription_id=?)""",
                (sub_id,),
            )
        schedule_rebuild()
        add_event("info", f"订阅 {row['name']} 本月流量已手动清零")
        flash("本月流量已清零，订阅已恢复", "success")
        return redirect(url_for("subscriptions_page"))

    @app.post("/subscriptions/<int:sub_id>/toggle")
    @login_required
    def subscription_toggle(sub_id):
        with db() as conn:
            updated = conn.execute("UPDATE subscriptions SET enabled=1-enabled,updated_at=? WHERE id=?", (now(), sub_id)).rowcount
        if not updated:
            flash("订阅不存在", "error")
            return redirect(url_for("subscriptions_page"))
        schedule_rebuild()
        flash("订阅状态已更新", "success")
        return redirect(url_for("subscriptions_page"))

    @app.post("/subscriptions/<int:sub_id>/delete")
    @login_required
    def subscription_delete(sub_id):
        with db() as conn:
            row = conn.execute("SELECT name FROM subscriptions WHERE id=?", (sub_id,)).fetchone()
            conn.execute("DELETE FROM subscriptions WHERE id=?", (sub_id,))
        schedule_rebuild()
        if row:
            add_event("warning", f"删除订阅 {row['name']}")
        flash("订阅已删除", "success")
        return redirect(url_for("subscriptions_page"))

    @app.get("/s/<token>")
    def subscription(token):
        with db() as conn:
            sub = conn.execute("SELECT * FROM subscriptions WHERE token=? AND enabled=1", (token,)).fetchone()
        if not sub:
            return "subscription not found", 404
        requested_format = request.args.get("format", "").lower()
        user_agent = request.headers.get("User-Agent", "").lower()
        wants_clash = requested_format in {"clash", "mihomo", "yaml"} or (
            not requested_format
            and any(name in user_agent for name in ("clash", "mihomo", "verge", "stash"))
        )
        if wants_clash:
            body = clash_subscription_text(sub)
            content_type = "text/yaml; charset=utf-8"
            filename = "subscription.yaml"
        else:
            body = subscription_text(sub)
            content_type = "text/plain; charset=utf-8"
            filename = "subscription.txt"
        return Response(
            body,
            content_type=content_type,
            headers={
                "Profile-Title": profile_title(sub["name"]),
                "Profile-Update-Interval": "1",
                "Content-Disposition": f'inline; filename="{filename}"',
                "Cache-Control": "no-store",
            },
        )

    def activation_view(code):
        with db() as conn:
            row = conn.execute(
                """SELECT a.*,p.name AS plan_name,s.name AS parent_name
                   FROM activation_codes a JOIN secondary_plans p ON p.id=a.plan_id
                   JOIN subscriptions s ON s.id=p.parent_subscription_id WHERE a.code=?""",
                (code,),
            ).fetchone()
        return row

    @app.get("/redeem")
    def redeem_page():
        code = request.args.get("code", "").strip().upper()
        result = activation_view(code) if code else None
        return render_template("redeem.html", result=result, searched=bool(code), code=code)

    @app.post("/redeem")
    def redeem_post():
        code = request.form.get("code", "").strip().upper()
        with db() as conn:
            row = conn.execute("SELECT * FROM activation_codes WHERE code=?", (code,)).fetchone()
            if not row:
                return render_template("redeem.html", result=None, searched=True, code=code, error="激活码不存在或已到期删除"), 404
            if row["status"] == "unused":
                token, vless_uuid, trojan_password = new_subscription_values()
                activated = datetime.now(timezone.utc)
                expires = activated + timedelta(days=row["valid_days"])
                conn.execute(
                    """UPDATE activation_codes SET status='active',token=?,vless_uuid=?,trojan_password=?,
                       activated_at=?,expires_at=? WHERE id=? AND status='unused'""",
                    (token, vless_uuid, trojan_password, activated.isoformat(timespec="seconds"),
                     expires.isoformat(timespec="seconds"), row["id"]),
                )
        schedule_rebuild()
        result = activation_view(code)
        return render_template("redeem.html", result=result, searched=True, code=code, activated=True)

    @app.get("/c/<token>")
    def child_subscription(token):
        with db() as conn:
            row = conn.execute(
                """SELECT a.*,p.name AS plan_name,s.enabled AS parent_enabled
                   FROM activation_codes a JOIN secondary_plans p ON p.id=a.plan_id
                   JOIN subscriptions s ON s.id=p.parent_subscription_id WHERE a.token=?""",
                (token,),
            ).fetchone()
            if row and row["expires_at"] <= now():
                conn.execute("DELETE FROM activation_codes WHERE id=?", (row["id"],))
                row = None
                schedule_rebuild()
        if not row or row["status"] != "active" or row["quota_exceeded"] or not row["parent_enabled"]:
            return "subscription unavailable", 404
        child = dict(row)
        child["name"] = f"{row['plan_name']}-{row['code'][-4:]}"
        requested_format = request.args.get("format", "").lower()
        user_agent = request.headers.get("User-Agent", "").lower()
        wants_clash = requested_format in {"clash", "mihomo", "yaml"} or (
            not requested_format and any(name in user_agent for name in ("clash", "mihomo", "verge", "stash"))
        )
        if wants_clash:
            body, content_type, filename = clash_subscription_text(child), "text/yaml; charset=utf-8", "subscription.yaml"
        else:
            body, content_type, filename = subscription_text(child), "text/plain; charset=utf-8", "subscription.txt"
        expire_epoch = int(datetime.fromisoformat(row["expires_at"]).timestamp())
        return Response(
            body,
            content_type=content_type,
            headers={
                "Profile-Title": profile_title(child["name"]),
                "Profile-Update-Interval": "1",
                "Subscription-Userinfo": f"upload=0; download={row['used_bytes']}; total={int(row['quota_gb'] * GIB)}; expire={expire_epoch}",
                "Content-Disposition": f'inline; filename="{filename}"',
                "Cache-Control": "no-store",
            },
        )

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    return app


app = create_app()

