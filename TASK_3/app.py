import os
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, render_template
import pymysql
from pymysql.cursors import DictCursor

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "avnadmin")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "defaultdb")
DB_SSL = os.getenv("DB_SSL", "true").lower() == "true"
PASS_SECRET = os.getenv("PASS_SECRET", "bus-pass-secret-key").encode("utf-8")

TOKENS = {}

ROUTE_CATALOG = [
    {
        "route_name": "City Express (Zone 1)",
        "rate": 25,
        "zone": "Zone 1",
        "frequency": "Every 10 mins",
        "stops": "Central Hub -> Market -> Tech Park",
        "bus_no": "TN-01-AE-1042",
        "bus_status": "On Time",
    },
    {
        "route_name": "Metro Link (Zone 2)",
        "rate": 40,
        "zone": "Zone 2",
        "frequency": "Every 15 mins",
        "stops": "Station Rd -> University -> IT Corridor",
        "bus_no": "TN-01-AE-2088",
        "bus_status": "On Time",
    },
    {
        "route_name": "Intercity Rapid (All Zones)",
        "rate": 75,
        "zone": "All Zones",
        "frequency": "Every 25 mins",
        "stops": "City Terminus -> Highway Bypass -> Express Gate",
        "bus_no": "TN-01-AE-3091",
        "bus_status": "Delayed (12m)",
    },
]

ROUTE_RATES = {r["route_name"]: r["rate"] for r in ROUTE_CATALOG}
DAY_MULTIPLIERS = {1: 1, 7: 6, 30: 20}

_db_ready = False


def get_connection():
    args = {
        "host": DB_HOST,
        "port": DB_PORT,
        "user": DB_USER,
        "password": DB_PASSWORD,
        "database": DB_NAME,
        "cursorclass": DictCursor,
        "autocommit": True,
        "connect_timeout": 8,
    }
    if DB_SSL:
        args["ssl"] = {"ssl_disabled": False}
    return pymysql.connect(**args)


def init_db():
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    login_id VARCHAR(40) PRIMARY KEY,
                    full_name VARCHAR(120) NOT NULL,
                    email VARCHAR(120) NOT NULL UNIQUE,
                    password_hash VARCHAR(200) NOT NULL,
                    created_at VARCHAR(50) NOT NULL
                )
                """
            )
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS passes (
                    pass_id VARCHAR(32) PRIMARY KEY,
                    login_id VARCHAR(40) NOT NULL DEFAULT '',
                    signature VARCHAR(64) NOT NULL,
                    passenger_name VARCHAR(120) NOT NULL,
                    email VARCHAR(120) NOT NULL,
                    route VARCHAR(100) NOT NULL,
                    days INT NOT NULL,
                    fare INT NOT NULL,
                    status VARCHAR(20) NOT NULL,
                    valid_until VARCHAR(50) NOT NULL,
                    created_at VARCHAR(50) NOT NULL
                )
                """
            )
            cur.execute("SHOW COLUMNS FROM passes LIKE 'login_id'")
            if not cur.fetchone():
                cur.execute("ALTER TABLE passes ADD COLUMN login_id VARCHAR(40) NOT NULL DEFAULT ''")
    finally:
        conn.close()


def ensure_db():
    global _db_ready
    if _db_ready:
        return
    init_db()
    _db_ready = True


def hash_password(password: str, salt: str = None) -> str:
    salt = salt or secrets.token_hex(8)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        25_000,
    ).hex()
    return f"{salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, _ = stored.split("$", 1)
    except ValueError:
        return False
    return hmac.compare_digest(hash_password(password, salt), stored)


def calculate_fare(route: str, days: int):
    rate = ROUTE_RATES.get(route)
    mult = DAY_MULTIPLIERS.get(days)
    if rate is None or mult is None:
        return None
    return rate * mult


def make_signature(pass_id: str, email: str, route: str, fare: int, valid_until: str, status: str) -> str:
    msg = f"{pass_id}|{email}|{route}|{fare}|{valid_until}|{status}".encode("utf-8")
    return hmac.new(PASS_SECRET, msg, hashlib.sha256).hexdigest()[:16].upper()


def enrich_pass(row: dict) -> dict:
    expected_sig = make_signature(
        row["pass_id"],
        row["email"],
        row["route"],
        row["fare"],
        row["valid_until"],
        row["status"],
    )
    sig_ok = hmac.compare_digest(expected_sig, row["signature"])
    expired = datetime.now(timezone.utc).isoformat() > row["valid_until"]

    if not sig_ok:
        effective_status = "TAMPERED"
    elif row["status"] == "CANCELLED":
        effective_status = "CANCELLED"
    elif expired:
        effective_status = "EXPIRED"
    else:
        effective_status = "ACTIVE"

    out = dict(row)
    out["effective_status"] = effective_status
    out["sig_verified"] = sig_ok
    return out


def get_authed_user():
    auth_header = request.headers.get("Authorization", "")
    token = auth_header.replace("Bearer ", "").strip() if auth_header.startswith("Bearer ") else ""
    if not token:
        token = (request.get_json(silent=True) or {}).get("token", "") or request.args.get("token", "")
    login_id = TOKENS.get(token)
    if not login_id:
        return None
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT login_id, full_name, email, created_at FROM users WHERE login_id = %s", (login_id,))
            return cur.fetchone()
    finally:
        conn.close()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    try:
        ensure_db()
        return jsonify({"status": "ok", "database": "aiven-mysql"}), 200
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/api/auth/register", methods=["POST"])
def register():
    ensure_db()
    body = request.get_json(silent=True) or {}
    login_id = str(body.get("loginId", "")).strip().lower()
    full_name = str(body.get("fullName", "")).strip()
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))

    if not login_id or not full_name or not email or len(password) < 4:
        return jsonify({"error": "Login ID, full name, email, and password (min 4 chars) are required."}), 400

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT login_id FROM users WHERE login_id = %s", (login_id,))
            if cur.fetchone():
                return jsonify({"error": f"Login ID '{login_id}' is already taken."}), 409

            cur.execute("SELECT email FROM users WHERE email = %s", (email,))
            if cur.fetchone():
                return jsonify({"error": f"Email '{email}' is already registered. Same email cannot be used twice."}), 409

            now_iso = datetime.now(timezone.utc).isoformat()
            cur.execute(
                "INSERT INTO users (login_id, full_name, email, password_hash, created_at) VALUES (%s, %s, %s, %s, %s)",
                (login_id, full_name, email, hash_password(password), now_iso),
            )
    finally:
        conn.close()

    token = secrets.token_hex(24)
    TOKENS[token] = login_id
    return jsonify({
        "token": token,
        "user": {"login_id": login_id, "full_name": full_name, "email": email},
    }), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    ensure_db()
    body = request.get_json(silent=True) or {}
    login_id = str(body.get("loginId", "")).strip().lower()
    password = str(body.get("password", ""))

    if not login_id or not password:
        return jsonify({"error": "Login ID and password are required."}), 400

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE login_id = %s", (login_id,))
            user = cur.fetchone()
    finally:
        conn.close()

    if not user or not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Invalid Login ID or password."}), 401

    token = secrets.token_hex(24)
    TOKENS[token] = user["login_id"]
    return jsonify({
        "token": token,
        "user": {
            "login_id": user["login_id"],
            "full_name": user["full_name"],
            "email": user["email"],
        },
    }), 200


@app.route("/api/profile", methods=["PUT"])
def update_profile():
    ensure_db()
    user = get_authed_user()
    if not user:
        return jsonify({"error": "Please login first."}), 401

    body = request.get_json(silent=True) or {}
    new_name = str(body.get("fullName", "")).strip()
    new_email = str(body.get("email", "")).strip().lower()
    new_password = str(body.get("password", ""))

    if not new_name or not new_email:
        return jsonify({"error": "Full name and email are required."}), 400

    login_id = user["login_id"]
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT login_id FROM users WHERE email = %s AND login_id != %s", (new_email, login_id))
            if cur.fetchone():
                return jsonify({"error": f"Email '{new_email}' is already used by another account."}), 409

            if new_password:
                if len(new_password) < 4:
                    return jsonify({"error": "New password must be at least 4 characters."}), 400
                cur.execute(
                    "UPDATE users SET full_name = %s, email = %s, password_hash = %s WHERE login_id = %s",
                    (new_name, new_email, hash_password(new_password), login_id),
                )
            else:
                cur.execute(
                    "UPDATE users SET full_name = %s, email = %s WHERE login_id = %s",
                    (new_name, new_email, login_id),
                )

            cur.execute("SELECT * FROM passes WHERE login_id = %s", (login_id,))
            user_passes = cur.fetchall()
            for p in user_passes:
                sig = make_signature(p["pass_id"], new_email, p["route"], p["fare"], p["valid_until"], p["status"])
                cur.execute(
                    "UPDATE passes SET passenger_name = %s, email = %s, signature = %s WHERE pass_id = %s",
                    (new_name, new_email, sig, p["pass_id"]),
                )
    finally:
        conn.close()

    return jsonify({
        "message": "Profile updated & pass signatures refreshed.",
        "user": {"login_id": login_id, "full_name": new_name, "email": new_email},
    }), 200


@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    ensure_db()
    user = get_authed_user()
    if not user:
        return jsonify({"error": "Please login first."}), 401

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM passes WHERE login_id = %s ORDER BY created_at DESC", (user["login_id"],))
            rows = cur.fetchall()
    finally:
        conn.close()

    enriched = [enrich_pass(r) for r in rows]
    counts = {"ACTIVE": 0, "EXPIRED": 0, "CANCELLED": 0, "TAMPERED": 0}
    for p in enriched:
        st = p["effective_status"]
        counts[st] = counts.get(st, 0) + 1

    return jsonify({
        "user": user,
        "counts": counts,
        "total_passes": len(enriched),
        "passes": enriched,
    }), 200


@app.route("/api/routes", methods=["GET"])
def get_routes():
    return jsonify({"routes": ROUTE_CATALOG}), 200


@app.route("/api/passes", methods=["POST"])
def create_pass():
    ensure_db()
    user = get_authed_user()
    if not user:
        return jsonify({"error": "Please login first."}), 401

    body = request.get_json(silent=True) or {}
    route = str(body.get("route", "")).strip()
    try:
        days = int(body.get("days", 0))
    except (TypeError, ValueError):
        days = 0

    fare = calculate_fare(route, days)
    if fare is None:
        return jsonify({"error": "Invalid route or duration."}), 400

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    login_id = user["login_id"]
    email = user["email"]
    passenger_name = user["full_name"]

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM passes WHERE login_id = %s ORDER BY created_at DESC", (login_id,))
            for existing in cur.fetchall():
                if existing["status"] == "ACTIVE" and existing["valid_until"] > now_iso:
                    return jsonify({
                        "error": f"You already have an active pass ({existing['pass_id']}). Renew or cancel it first.",
                        "pass": enrich_pass(existing),
                    }), 409

            valid_until = (now + timedelta(days=days)).isoformat()
            pass_id = "BP-" + secrets.token_hex(4).upper()
            signature = make_signature(pass_id, email, route, fare, valid_until, "ACTIVE")

            cur.execute(
                """
                INSERT INTO passes (
                    pass_id, login_id, signature, passenger_name, email,
                    route, days, fare, status, valid_until, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (pass_id, login_id, signature, passenger_name, email, route, days, fare, "ACTIVE", valid_until, now_iso),
            )
    finally:
        conn.close()

    return jsonify({
        "pass": enrich_pass({
            "pass_id": pass_id,
            "login_id": login_id,
            "signature": signature,
            "passenger_name": passenger_name,
            "email": email,
            "route": route,
            "days": days,
            "fare": fare,
            "status": "ACTIVE",
            "valid_until": valid_until,
            "created_at": now_iso,
        })
    }), 201


@app.route("/api/passes/<pass_id>/renew", methods=["POST"])
def renew_pass(pass_id: str):
    ensure_db()
    user = get_authed_user()
    if not user:
        return jsonify({"error": "Please login first."}), 401

    clean_id = pass_id.strip().upper()
    body = request.get_json(silent=True) or {}
    try:
        extra_days = int(body.get("days", 7))
    except (TypeError, ValueError):
        extra_days = 0

    route_override = str(body.get("route", "")).strip()

    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM passes WHERE pass_id = %s AND login_id = %s", (clean_id, user["login_id"]))
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "Pass not found for your account."}), 404

            target_route = route_override if route_override else row["route"]
            renewal_fare = calculate_fare(target_route, extra_days)
            if renewal_fare is None:
                return jsonify({"error": "Invalid renewal plan."}), 400

            now = datetime.now(timezone.utc)
            current_exp = datetime.fromisoformat(row["valid_until"])
            if current_exp.tzinfo is None:
                current_exp = current_exp.replace(tzinfo=timezone.utc)

            base_time = current_exp if (current_exp > now and row["status"] != "CANCELLED") else now
            new_valid_until = (base_time + timedelta(days=extra_days)).isoformat()
            new_days = int(row["days"]) + extra_days
            new_fare = int(row["fare"]) + renewal_fare
            new_sig = make_signature(row["pass_id"], row["email"], target_route, new_fare, new_valid_until, "ACTIVE")

            cur.execute(
                """
                UPDATE passes
                SET route = %s, days = %s, fare = %s, status = 'ACTIVE', valid_until = %s, signature = %s
                WHERE pass_id = %s
                """,
                (target_route, new_days, new_fare, new_valid_until, new_sig, clean_id),
            )
            cur.execute("SELECT * FROM passes WHERE pass_id = %s", (clean_id,))
            updated = cur.fetchone()
    finally:
        conn.close()

    return jsonify({
        "message": f"Renewed +{extra_days} days (+₹{renewal_fare}).",
        "pass": enrich_pass(updated),
    }), 200


@app.route("/api/passes/<pass_id>/cancel", methods=["POST"])
def cancel_pass(pass_id: str):
    ensure_db()
    user = get_authed_user()
    if not user:
        return jsonify({"error": "Please login first."}), 401

    clean_id = pass_id.strip().upper()
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM passes WHERE pass_id = %s AND login_id = %s", (clean_id, user["login_id"]))
            row = cur.fetchone()
            if not row:
                return jsonify({"error": "Pass not found for your account."}), 404

            new_sig = make_signature(row["pass_id"], row["email"], row["route"], row["fare"], row["valid_until"], "CANCELLED")
            cur.execute(
                "UPDATE passes SET status = 'CANCELLED', signature = %s WHERE pass_id = %s",
                (new_sig, clean_id),
            )
            cur.execute("SELECT * FROM passes WHERE pass_id = %s", (clean_id,))
            updated = cur.fetchone()
    finally:
        conn.close()

    return jsonify({
        "message": f"Pass {clean_id} cancelled.",
        "pass": enrich_pass(updated),
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)