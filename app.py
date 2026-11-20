
import os
import time
import base64
import csv
import io
import sqlite3
from datetime import datetime, timedelta

from dotenv import load_dotenv
from flask import Flask, request, jsonify, session, render_template, make_response
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# ============================================================
# CONFIGURATION
# ============================================================

load_dotenv()

app = Flask(__name__)

SESSION_SECRET = os.environ.get("LEDGERGUARD_SESSION_SECRET")
ENCRYPTION_KEY = os.environ.get("LEDGERGUARD_ENCRYPTION_KEY")

if not SESSION_SECRET:
    raise RuntimeError("LedgerGuard session secret is missing!")

if not ENCRYPTION_KEY:
    raise RuntimeError("LedgerGuard encryption key is missing!")

app.secret_key = SESSION_SECRET

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=10)
)

try:
    decoded_key = base64.urlsafe_b64decode(ENCRYPTION_KEY)
    if len(decoded_key) != 32:
        raise ValueError
except Exception:
    raise RuntimeError("LedgerGuard encryption key must decode to 32 bytes!")

aes = AESGCM(decoded_key)

DB_NAME = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "ledgerguard.db"
)
MANAGER_USERNAME = "manager"
MANAGER_PASSWORD = "LG-MANAGER-2026"

MANAGER_SESSION_TIMEOUT = 600

FAILED_LOGIN_THRESHOLD = 10
FAILED_LOGIN_WINDOW_MINUTES = 5
IP_BLOCK_DURATION_MINUTES = 15

TRUSTED_IPS = ["127.0.0.1"]

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[],
    storage_uri="memory://"
)

# ============================================================
# DATABASE
# ============================================================

def get_db():
    conn = sqlite3.connect(DB_NAME, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def add_column_if_missing(conn, table, column, definition):
    columns = [
        row["name"]
        for row in conn.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()
    ]

    if column not in columns:
        conn.execute(
            f"ALTER TABLE {table} ADD COLUMN {column} {definition}"
        )


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vendor_name TEXT NOT NULL,
            bank_account TEXT NOT NULL,
            status TEXT DEFAULT 'PENDING',
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ip_blocks (
            ip_address TEXT PRIMARY KEY,
            blocked_until TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    add_column_if_missing(
        conn, "audit_logs", "ip_address", "TEXT"
    )

    conn.commit()
    conn.close()


init_db()

# ============================================================
# UTILITIES
# ============================================================

def current_time():
    return datetime.now()


def timestamp():
    return current_time().strftime("%Y-%m-%d %H:%M:%S")


def get_client_ip():
    return request.remote_addr or "UNKNOWN"


def encrypt_bank_account(account_number):
    nonce = os.urandom(12)

    encrypted_data = aes.encrypt(
        nonce,
        account_number.encode("utf-8"),
        None
    )

    combined = nonce + encrypted_data

    return base64.urlsafe_b64encode(combined).decode("utf-8")


def decrypt_bank_account(encrypted_account):
    combined = base64.urlsafe_b64decode(
        encrypted_account.encode("utf-8")
    )

    nonce = combined[:12]
    encrypted_data = combined[12:]

    decrypted = aes.decrypt(nonce, encrypted_data, None)

    return decrypted.decode("utf-8")


def log_event(event, details=""):
    conn = get_db()

    conn.execute("""
        INSERT INTO audit_logs (event, details, ip_address, created_at)
        VALUES (?, ?, ?, ?)
    """, (
        event,
        details,
        get_client_ip(),
        timestamp()
    ))

    conn.commit()
    conn.close()


def create_alert(severity, title, message):
    conn = get_db()

    conn.execute("""
        INSERT INTO alerts (severity, title, message, created_at)
        VALUES (?, ?, ?, ?)
    """, (
        severity,
        title,
        message,
        timestamp()
    ))

    conn.commit()
    conn.close()


def manager_required():
    return session.get("manager_logged_in") is True


def get_active_ip_block(ip_address):
    conn = get_db()

    row = conn.execute("""
        SELECT * FROM ip_blocks
        WHERE ip_address = ?
    """, (ip_address,)).fetchone()

    conn.close()

    if not row:
        return None

    blocked_until = datetime.strptime(
        row["blocked_until"],
        "%Y-%m-%d %H:%M:%S"
    )

    if current_time() >= blocked_until:
        conn = get_db()

        conn.execute("""
            DELETE FROM ip_blocks
            WHERE ip_address = ?
        """, (ip_address,))

        conn.commit()
        conn.close()

        log_event(
            "IP_BLOCK_EXPIRED",
            f"Block expired for {ip_address}"
        )

        return None

    return dict(row)


def block_ip(ip_address, reason):
    blocked_until = (
        current_time() + timedelta(minutes=IP_BLOCK_DURATION_MINUTES)
    ).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()

    conn.execute("""
        INSERT OR REPLACE INTO ip_blocks
        (ip_address, blocked_until, reason, created_at)
        VALUES (?, ?, ?, ?)
    """, (
        ip_address,
        blocked_until,
        reason,
        timestamp()
    ))

    conn.commit()
    conn.close()

    log_event(
        "IP_TEMPORARILY_BLOCKED",
        f"IP {ip_address} blocked until {blocked_until}. Reason: {reason}"
    )

    create_alert(
        "HIGH",
        "IP temporarily blocked",
        f"{ip_address} was blocked until {blocked_until}. Reason: {reason}"
    )


def failed_login_count(ip_address):
    cutoff = (
        current_time() - timedelta(minutes=FAILED_LOGIN_WINDOW_MINUTES)
    ).strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db()

    count = conn.execute("""
        SELECT COUNT(*) AS total
        FROM audit_logs
        WHERE event = 'MANAGER_LOGIN_FAILED'
        AND ip_address = ?
        AND created_at >= ?
    """, (ip_address, cutoff)).fetchone()["total"]

    conn.close()

    return count


def get_request_stats():
    conn = get_db()

    total = conn.execute(
        "SELECT COUNT(*) AS total FROM requests"
    ).fetchone()["total"]

    pending = conn.execute(
        "SELECT COUNT(*) AS total FROM requests WHERE status='PENDING'"
    ).fetchone()["total"]

    approved = conn.execute(
        "SELECT COUNT(*) AS total FROM requests WHERE status='APPROVED'"
    ).fetchone()["total"]

    rejected = conn.execute(
        "SELECT COUNT(*) AS total FROM requests WHERE status='REJECTED'"
    ).fetchone()["total"]

    conn.close()

    return {
        "total": total,
        "pending": pending,
        "approved": approved,
        "rejected": rejected
    }


def get_attack_count():
    conn = get_db()

    count = conn.execute("""
        SELECT COUNT(*) AS total
        FROM audit_logs
        WHERE event IN (
            'MANAGER_LOGIN_FAILED',
            'RATE_LIMIT_EXCEEDED',
            'IP_TEMPORARILY_BLOCKED',
            'UNAUTHORIZED_ACCESS',
            'DUPLICATE_PROCESSING_ATTEMPT'
        )
    """).fetchone()["total"]

    conn.close()

    return count


# ============================================================
# REQUEST / SESSION / SECURITY MIDDLEWARE
# ============================================================

@app.before_request
def check_temporary_ip_block():
    ip_address = get_client_ip()

    block = get_active_ip_block(ip_address)

    if block:
        return jsonify({
            "status": "BLOCKED",
            "error": "Your IP address is temporarily blocked.",
            "reason": block["reason"],
            "blocked_until": block["blocked_until"]
        }), 403


@app.before_request
def manager_session_timeout():
    if not session.get("manager_logged_in"):
        return

    now = time.time()
    last_activity = session.get("last_activity", now)

    if now - last_activity > MANAGER_SESSION_TIMEOUT:
        session.clear()

        log_event(
            "MANAGER_SESSION_EXPIRED",
            "Manager session expired"
        )

        return jsonify({
            "status": "SESSION_EXPIRED",
            "error": "Manager session expired. Please log in again."
        }), 401

    passive_endpoints = {
        "get_requests",
        "get_logs",
        "get_alerts",
        "security_stats",
        "attack_activity",
        "threat_ips",
        "security_health",
        "activity_timeline",
        "session_status"
    }

    if request.endpoint not in passive_endpoints:
        session["last_activity"] = now


# ============================================================
# RATE LIMIT HANDLER
# ============================================================

@app.errorhandler(429)
def rate_limit_exceeded(error):
    log_event(
        "RATE_LIMIT_EXCEEDED",
        f"Rate limit exceeded by IP: {get_client_ip()}"
    )

    create_alert(
        "HIGH",
        "Rate limit exceeded",
        f"Repeated requests from IP: {get_client_ip()}"
    )

    return jsonify({
        "status": "BLOCKED",
        "error": "Too many requests. Please wait before trying again.",
        "reason": "RATE_LIMIT_EXCEEDED"
    }), 429


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def index():
    return render_template("index.html")


# ============================================================
# SESSION STATUS
# ============================================================

@app.route("/api/session-status", methods=["GET"])
def session_status():
    return jsonify({
        "logged_in": manager_required()
    }), 200


# ============================================================
# VENDOR BANK CHANGE REQUEST
# ============================================================

@app.route("/api/request-change", methods=["POST"])
@limiter.limit("10 per minute")
def request_change():
    data = request.get_json(silent=True) or {}

    vendor_name = str(data.get("vendor_name", "")).strip()
    bank_account = str(data.get("bank_account", "")).strip()

    if not vendor_name or not bank_account:
        return jsonify({
            "status": "ERROR",
            "error": "Vendor name and bank account are required."
        }), 400

    if len(vendor_name) > 200 or len(bank_account) > 100:
        return jsonify({
            "status": "ERROR",
            "error": "Input length exceeds permitted limit."
        }), 400

    encrypted_account = encrypt_bank_account(bank_account)

    conn = get_db()

    cursor = conn.execute("""
        INSERT INTO requests
        (vendor_name, bank_account, status, created_at)
        VALUES (?, ?, 'PENDING', ?)
    """, (
        vendor_name,
        encrypted_account,
        timestamp()
    ))

    request_id = cursor.lastrowid

    conn.commit()
    conn.close()

    log_event(
        "BANK_CHANGE_REQUEST",
        f"Request ID {request_id} submitted for vendor {vendor_name}"
    )

    create_alert(
        "MEDIUM",
        "New bank change request",
        f"Vendor {vendor_name} submitted request #{request_id}"
    )

    return jsonify({
        "status": "PENDING",
        "request_id": request_id,
        "reason": "Security checks passed. Manager approval required."
    }), 201


# ============================================================
# MANAGER LOGIN
# ============================================================

@app.route("/api/manager-login", methods=["POST"])
@limiter.limit("15 per 5 minutes")
def manager_login():
    data = request.get_json(silent=True) or {}

    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    ip_address = get_client_ip()

    if username == MANAGER_USERNAME and password == MANAGER_PASSWORD:
        session.clear()

        session["manager_logged_in"] = True
        session["last_activity"] = time.time()
        session.permanent = True

        log_event(
            "MANAGER_LOGIN_SUCCESS",
            "Manager logged in"
        )

        return jsonify({
            "status": "SUCCESS",
            "message": "Manager login successful."
        })

    log_event(
        "MANAGER_LOGIN_FAILED",
        f"Failed login attempt from {ip_address}"
    )

    create_alert(
        "HIGH",
        "Failed manager login",
        f"Failed manager login attempt from {ip_address}"
    )

    count = failed_login_count(ip_address)

    if count >= FAILED_LOGIN_THRESHOLD:
        block_ip(
            ip_address,
            "Repeated failed manager login attempts"
        )

        return jsonify({
            "status": "BLOCKED",
            "error": "Too many failed login attempts.",
            "blocked_until": (
                current_time() +
                timedelta(minutes=IP_BLOCK_DURATION_MINUTES)
            ).strftime("%Y-%m-%d %H:%M:%S")
        }), 403

    return jsonify({
        "status": "ERROR",
        "error": "Invalid username or password"
    }), 401


# ============================================================
# MANAGER LOGOUT
# ============================================================

@app.route("/api/manager-logout", methods=["POST"])
def manager_logout():
    if session.get("manager_logged_in"):
        log_event(
            "MANAGER_LOGOUT",
            "Manager logged out"
        )

    session.clear()

    return jsonify({
        "status": "SUCCESS",
        "message": "Logged out successfully."
    })


# ============================================================
# APPROVE / REJECT REQUEST - ATOMIC PROCESSING
# ============================================================

@app.route("/api/approve/<int:request_id>", methods=["POST"])
@limiter.limit("20 per minute")
def approve_request(request_id):

    if not manager_required():
        log_event(
            "UNAUTHORIZED_ACCESS",
            "Unauthorized request approval attempt"
        )

        return jsonify({
            "status": "ERROR",
            "error": "Manager login required."
        }), 401

    data = request.get_json(silent=True) or {}

    action = str(data.get("action", "approve")).lower()

    if action not in ("approve", "reject"):
        return jsonify({
            "status": "ERROR",
            "error": "Invalid action."
        }), 400

    new_status = "APPROVED" if action == "approve" else "REJECTED"

    conn = get_db()

    try:
        conn.execute("BEGIN IMMEDIATE")

        row = conn.execute("""
            SELECT status FROM requests
            WHERE id = ?
        """, (request_id,)).fetchone()

        if not row:
            conn.rollback()
            conn.close()

            return jsonify({
                "status": "ERROR",
                "error": "Request not found."
            }), 404

        if row["status"] != "PENDING":
            conn.rollback()
            conn.close()

            log_event(
                "DUPLICATE_PROCESSING_ATTEMPT",
                f"Request {request_id} was already "
                f"{row['status']}. Attempted action: {action}"
            )

            create_alert(
                "HIGH",
                "Duplicate request processing attempt",
                f"Request {request_id} was already processed. "
                f"Repeated action: {action}"
            )

            return jsonify({
                "status": "ERROR",
                "error": "Request has already been processed."
            }), 409

        cursor = conn.execute("""
            UPDATE requests
            SET status = ?
            WHERE id = ?
            AND status = 'PENDING'
        """, (new_status, request_id))

        if cursor.rowcount != 1:
            conn.rollback()
            conn.close()

            log_event(
                "DUPLICATE_PROCESSING_ATTEMPT",
                f"Atomic processing failed for request {request_id}"
            )

            create_alert(
                "HIGH",
                "Duplicate request processing attempt",
                f"Request {request_id} could not be processed "
                f"because its status changed."
            )

            return jsonify({
                "status": "ERROR",
                "error": "Request has already been processed."
            }), 409

        conn.commit()

    except sqlite3.Error as error:
        conn.rollback()
        conn.close()

        log_event(
            "REQUEST_PROCESSING_ERROR",
            f"Database error processing request {request_id}: {error}"
        )

        return jsonify({
            "status": "ERROR",
            "error": "Database error while processing request."
        }), 500

    conn.close()

    log_event(
        f"BANK_CHANGE_{new_status}",
        f"Request {request_id} {new_status.lower()}"
    )

    create_alert(
        "LOW" if action == "approve" else "MEDIUM",
        f"Bank change {action}",
        f"Request {request_id} was {action}d"
    )

    return jsonify({
        "status": new_status,
        "request_id": request_id
    }), 200


# ============================================================
# REQUEST LIST
# ============================================================

@app.route("/api/requests")
def get_requests():
    if not manager_required():
        return jsonify({
            "error": "Manager login required."
        }), 401

    conn = get_db()

    rows = conn.execute("""
        SELECT * FROM requests ORDER BY id DESC
    """).fetchall()

    conn.close()

    results = []

    for row in rows:
        item = dict(row)

        try:
            item["bank_account"] = decrypt_bank_account(
                item["bank_account"]
            )
        except Exception:
            item["bank_account"] = "DECRYPTION ERROR"

        results.append(item)

    return jsonify(results)


# ============================================================
# AUDIT LOGS
# ============================================================

@app.route("/api/logs")
def get_logs():
    if not manager_required():
        return jsonify({
            "error": "Manager login required."
        }), 401

    conn = get_db()

    rows = conn.execute("""
        SELECT * FROM audit_logs
        ORDER BY id DESC
        LIMIT 500
    """).fetchall()

    conn.close()

    return jsonify([dict(row) for row in rows])


# ============================================================
# SECURITY ALERTS
# ============================================================

@app.route("/api/alerts")
def get_alerts():
    if not manager_required():
        return jsonify({
            "error": "Manager login required."
        }), 401

    conn = get_db()

    rows = conn.execute("""
        SELECT * FROM alerts
        ORDER BY id DESC
        LIMIT 500
    """).fetchall()

    conn.close()

    return jsonify([dict(row) for row in rows])


# ============================================================
# SECURITY STATISTICS
# ============================================================

@app.route("/api/security-stats")
def security_stats():
    if not manager_required():
        return jsonify({
            "error": "Manager login required."
        }), 401

    stats = get_request_stats()

    stats["attacks"] = get_attack_count()

    conn = get_db()

    stats["alerts"] = conn.execute(
        "SELECT COUNT(*) AS total FROM alerts"
    ).fetchone()["total"]

    stats["blocked_ips"] = conn.execute(
        "SELECT COUNT(*) AS total FROM ip_blocks"
    ).fetchone()["total"]

    conn.close()

    return jsonify(stats)


# ============================================================
# ATTACK ACTIVITY CHART
# ============================================================

@app.route("/api/attack-activity")
def attack_activity():
    if not manager_required():
        return jsonify({
            "error": "Manager login required."
        }), 401

    conn = get_db()

    rows = conn.execute("""
        SELECT
            substr(created_at, 1, 10) AS day,
            COUNT(*) AS attacks
        FROM audit_logs
        WHERE event IN (
            'MANAGER_LOGIN_FAILED',
            'RATE_LIMIT_EXCEEDED',
            'IP_TEMPORARILY_BLOCKED',
            'UNAUTHORIZED_ACCESS',
            'DUPLICATE_PROCESSING_ATTEMPT'
        )
        GROUP BY day
        ORDER BY day DESC
        LIMIT 7
    """).fetchall()

    conn.close()

    return jsonify([
        {
            "date": row["day"],
            "attacks": row["attacks"]
        }
        for row in reversed(rows)
    ])


# ============================================================
# THREAT IP LEADERBOARD
# ============================================================

@app.route("/api/threat-ips")
def threat_ips():
    if not manager_required():
        return jsonify({
            "error": "Manager login required."
        }), 401

    conn = get_db()

    rows = conn.execute("""
        SELECT
            ip_address,
            COUNT(*) AS attacks
        FROM audit_logs
        WHERE event IN (
            'MANAGER_LOGIN_FAILED',
            'RATE_LIMIT_EXCEEDED',
            'IP_TEMPORARILY_BLOCKED',
            'UNAUTHORIZED_ACCESS',
            'DUPLICATE_PROCESSING_ATTEMPT'
        )
        AND ip_address IS NOT NULL
        GROUP BY ip_address
        ORDER BY attacks DESC
        LIMIT 10
    """).fetchall()

    conn.close()

    return jsonify([
        {
            "ip": row["ip_address"],
            "attacks": row["attacks"]
        }
        for row in rows
    ])


# ============================================================
# ACTIVITY TIMELINE
# ============================================================

@app.route("/api/activity-timeline")
def activity_timeline():
    if not manager_required():
        return jsonify({
            "error": "Manager login required."
        }), 401

    conn = get_db()

    rows = conn.execute("""
        SELECT event, details, ip_address, created_at
        FROM audit_logs
        ORDER BY id DESC
        LIMIT 50
    """).fetchall()

    conn.close()

    return jsonify([dict(row) for row in rows])


# ============================================================
# SECURITY HEALTH SCORE
# ============================================================

@app.route("/api/security-health")
def security_health():
    if not manager_required():
        return jsonify({
            "error": "Manager login required."
        }), 401

    stats = get_request_stats()
    attack_count = get_attack_count()

    score = 100

    score -= min(attack_count * 2, 50)
    score -= min(stats["pending"] * 5, 25)

    score = max(0, min(100, score))

    if score >= 80:
        status = "HEALTHY"
    elif score >= 50:
        status = "MODERATE"
    else:
        status = "CRITICAL"

    return jsonify({
        "score": score,
        "status": status,
        "attacks": attack_count,
        "pending_requests": stats["pending"]
    })


# ============================================================
# CSV REPORT EXPORT
# ============================================================

@app.route("/api/export-report")
def export_report():
    if not manager_required():
        return jsonify({
            "error": "Manager login required."
        }), 401

    conn = get_db()

    requests_rows = conn.execute("""
        SELECT id, vendor_name, status, created_at
        FROM requests
        ORDER BY id DESC
    """).fetchall()

    logs_rows = conn.execute("""
        SELECT event, details, ip_address, created_at
        FROM audit_logs
        ORDER BY id DESC
    """).fetchall()

    alerts_rows = conn.execute("""
        SELECT severity, title, message, created_at
        FROM alerts
        ORDER BY id DESC
    """).fetchall()

    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["LEDGERGUARD SECURITY REPORT"])
    writer.writerow(["Generated", timestamp()])
    writer.writerow([])

    writer.writerow(["BANK CHANGE REQUESTS"])
    writer.writerow(["ID", "Vendor", "Status", "Created At"])

    for row in requests_rows:
        writer.writerow([
            row["id"],
            row["vendor_name"],
            row["status"],
            row["created_at"]
        ])

    writer.writerow([])
    writer.writerow(["AUDIT LOGS"])
    writer.writerow(["Event", "Details", "IP", "Created At"])

    for row in logs_rows:
        writer.writerow([
            row["event"],
            row["details"],
            row["ip_address"],
            row["created_at"]
        ])

    writer.writerow([])
    writer.writerow(["SECURITY ALERTS"])
    writer.writerow(["Severity", "Title", "Message", "Created At"])

    for row in alerts_rows:
        writer.writerow([
            row["severity"],
            row["title"],
            row["message"],
            row["created_at"]
        ])

    response = make_response(output.getvalue())

    response.headers["Content-Type"] = "text/csv"
    response.headers["Content-Disposition"] = (
        "attachment; filename=ledgerguard_report.csv"
    )

    log_event("REPORT_EXPORTED", "CSV report exported")

    return response


# ============================================================
# APPLICATION START
# ============================================================

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
