import os
import hmac
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from flask import Flask, request, jsonify, render_template
from dotenv import load_dotenv
import pymysql
from pymysql.cursors import DictCursor

load_dotenv()

app = Flask(__name__)

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "avnadmin")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "defaultdb")
DB_SSL = os.getenv("DB_SSL", "true").lower() == "true"
PASS_SECRET = os.getenv("PASS_SECRET", "bus-pass-secret-key").encode("utf-8")

# Server-side authoritative pricing (prevents tampering)
ROUTE_RATES = {
    "City Express (Zone 1)": 25,
    "Metro Link (Zone 2)": 40,
    "Intercity Rapid (All Zones)": 75,
}

DAY_MULTIPLIERS = {
    1: 1,
    7: 6,
    30: 20,
}


def get_connection():
    args = {
        "host": DB_HOST,
        "port": DB_PORT,
        "user": DB_USER,
        "password": DB_PASSWORD,
        "database": DB_NAME,
        "cursorclass": DictCursor,
        "autocommit": True,
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
                CREATE TABLE IF NOT EXISTS passes (
                    pass_id VARCHAR(32) PRIMARY KEY,
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
    finally:
        conn.close()


def calculate_fare(route: str, days: int):
    rate = ROUTE_RATES.get(route)
    mult = DAY_MULTIPLIERS.get(days)
    if rate is None or mult is None:
        return None
    return rate * mult


def make_signature(pass_id: str, email: str, route: str, fare: int, valid_until: str) -> str:
    msg = f"{pass_id}|{email}|{route}|{fare}|{valid_until}".encode("utf-8")
    return hmac.new(PASS_SECRET, msg, hashlib.sha256).hexdigest()[:16].upper()


def enrich_pass(row: dict) -> dict:
    expected_sig = make_signature(
        row["pass_id"],
        row["email"],
        row["route"],
        row["fare"],
        row["valid_until"],
    )
    sig_ok = hmac.compare_digest(expected_sig, row["signature"])
    expired = datetime.now(timezone.utc).isoformat() > row["valid_until"]
    effective_status = "TAMPERED" if not sig_ok else ("EXPIRED" if expired else row["status"])

    out = dict(row)
    out["effective_status"] = effective_status
    out["sig_verified"] = sig_ok
    return out


try:
    init_db()
except Exception as e:
    print("DB init warning:", e)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok", "database": "aiven-mysql"}), 200


@app.route("/api/passes", methods=["POST"])
def create_pass():
    body = request.get_json(silent=True) or {}
    passenger_name = str(body.get("passengerName", "")).strip()
    email = str(body.get("email", "")).strip().lower()
    route = str(body.get("route", "")).strip()

    try:
        days = int(body.get("days", 0))
    except (TypeError, ValueError):
        days = 0

    if not passenger_name or not email or not route or days <= 0:
        return jsonify({"error": "All fields are required."}), 400

    fare = calculate_fare(route, days)
    if fare is None:
        return jsonify({"error": "Invalid route or duration."}), 400

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    try:
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                # Prevent duplicate active/unexpired pass for the same email
                cur.execute(
                    "SELECT * FROM passes WHERE email = %s ORDER BY created_at DESC",
                    (email,),
                )
                existing_rows = cur.fetchall()
                for existing in existing_rows:
                    if existing["valid_until"] > now_iso and existing["status"] == "ACTIVE":
                        return jsonify({
                            "error": f"Duplicate blocked: {email} already has an active pass ({existing['pass_id']}). Use Renew Pass instead.",
                            "existing_pass": enrich_pass(existing),
                        }), 409

                valid_until = (now + timedelta(days=days)).isoformat()
                pass_id = "BP-" + secrets.token_hex(4).upper()
                signature = make_signature(pass_id, email, route, fare, valid_until)

                cur.execute(
                    """
                    INSERT INTO passes (
                        pass_id, signature, passenger_name, email, route,
                        days, fare, status, valid_until, created_at
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        pass_id,
                        signature,
                        passenger_name,
                        email,
                        route,
                        days,
                        fare,
                        "ACTIVE",
                        valid_until,
                        now_iso,
                    ),
                )
        finally:
            conn.close()
    except Exception as e:
        return jsonify({"error": f"MySQL error: {str(e)}"}), 500

    return jsonify({
        "pass": {
            "pass_id": pass_id,
            "signature": signature,
            "passenger_name": passenger_name,
            "email": email,
            "route": route,
            "days": days,
            "fare": fare,
            "status": "ACTIVE",
            "valid_until": valid_until,
            "created_at": now_iso,
            "effective_status": "ACTIVE",
            "sig_verified": True,
        }
    }), 201


@app.route("/api/passes/<pass_id>", methods=["GET"])
def verify_pass(pass_id: str):
    clean_id = pass_id.strip().upper()
    try:
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM passes WHERE pass_id = %s", (clean_id,))
                row = cur.fetchone()
        finally:
            conn.close()
    except Exception as e:
        return jsonify({"error": f"MySQL error: {str(e)}"}), 500

    if not row:
        return jsonify({"error": "Pass not found."}), 404

    return jsonify({"pass": enrich_pass(row)}), 200


@app.route("/api/passes/<pass_id>/renew", methods=["POST"])
def renew_pass(pass_id: str):
    clean_id = pass_id.strip().upper()
    body = request.get_json(silent=True) or {}

    try:
        extra_days = int(body.get("days", 7))
    except (TypeError, ValueError):
        extra_days = 0

    route_override = str(body.get("route", "")).strip()

    try:
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM passes WHERE pass_id = %s", (clean_id,))
                row = cur.fetchone()
                if not row:
                    return jsonify({"error": "Pass not found to renew."}), 404

                target_route = route_override if route_override else row["route"]
                renewal_fare = calculate_fare(target_route, extra_days)
                if renewal_fare is None:
                    return jsonify({"error": "Invalid renewal route or duration."}), 400

                now = datetime.now(timezone.utc)
                current_expiry = datetime.fromisoformat(row["valid_until"])
                if current_expiry.tzinfo is None:
                    current_expiry = current_expiry.replace(tzinfo=timezone.utc)

                base_time = current_expiry if current_expiry > now else now
                new_valid_until = (base_time + timedelta(days=extra_days)).isoformat()
                new_days = int(row["days"]) + extra_days
                new_fare = int(row["fare"]) + renewal_fare
                new_sig = make_signature(
                    row["pass_id"],
                    row["email"],
                    target_route,
                    new_fare,
                    new_valid_until,
                )

                cur.execute(
                    """
                    UPDATE passes
                    SET route = %s, days = %s, fare = %s, status = %s,
                        valid_until = %s, signature = %s
                    WHERE pass_id = %s
                    """,
                    (
                        target_route,
                        new_days,
                        new_fare,
                        "ACTIVE",
                        new_valid_until,
                        new_sig,
                        clean_id,
                    ),
                )

                cur.execute("SELECT * FROM passes WHERE pass_id = %s", (clean_id,))
                updated = cur.fetchone()
        finally:
            conn.close()
    except Exception as e:
        return jsonify({"error": f"MySQL error: {str(e)}"}), 500

    return jsonify({
        "message": f"Renewed +{extra_days} days (Renewal Charge: ₹{renewal_fare})",
        "pass": enrich_pass(updated),
    }), 200


@app.route("/api/passes/<pass_id>/profile", methods=["PUT"])
def edit_profile(pass_id: str):
    clean_id = pass_id.strip().upper()
    body = request.get_json(silent=True) or {}
    new_name = str(body.get("passengerName", "")).strip()
    new_email = str(body.get("email", "")).strip().lower()

    if not new_name or not new_email:
        return jsonify({"error": "Passenger name and email are required."}), 400

    try:
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT * FROM passes WHERE pass_id = %s", (clean_id,))
                row = cur.fetchone()
                if not row:
                    return jsonify({"error": "Pass not found."}), 404

                # Check if another pass already uses the new email
                cur.execute(
                    "SELECT pass_id FROM passes WHERE email = %s AND pass_id != %s",
                    (new_email, clean_id),
                )
                conflict = cur.fetchone()
                if conflict:
                    return jsonify({
                        "error": f"Email {new_email} is already linked to pass {conflict['pass_id']}."
                    }), 409

                new_sig = make_signature(
                    row["pass_id"],
                    new_email,
                    row["route"],
                    row["fare"],
                    row["valid_until"],
                )

                cur.execute(
                    """
                    UPDATE passes
                    SET passenger_name = %s, email = %s, signature = %s
                    WHERE pass_id = %s
                    """,
                    (new_name, new_email, new_sig, clean_id),
                )

                cur.execute("SELECT * FROM passes WHERE pass_id = %s", (clean_id,))
                updated = cur.fetchone()
        finally:
            conn.close()
    except Exception as e:
        return jsonify({"error": f"MySQL error: {str(e)}"}), 500

    return jsonify({
        "message": "Profile updated & pass signature refreshed.",
        "pass": enrich_pass(updated),
    }), 200


@app.route("/api/passes", methods=["GET"])
def recent_passes():
    try:
        conn = get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT pass_id, passenger_name, email, route, days, fare, status, valid_until FROM passes ORDER BY created_at DESC LIMIT 8"
                )
                rows = cur.fetchall()
        finally:
            conn.close()
        return jsonify({"passes": rows}), 200
    except Exception as e:
        return jsonify({"error": f"MySQL error: {str(e)}"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=True)