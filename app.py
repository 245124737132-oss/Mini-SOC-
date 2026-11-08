
from flask import Flask, request, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename
from collections import Counter
from datetime import datetime
import sqlite3
import re
import ipaddress
import os


# ---------------- APP CONFIGURATION ----------------

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "minisoc-development-key"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
DATABASE = os.path.join(BASE_DIR, "minisoc.db")

ALLOWED_EXTENSIONS = {"log", "txt"}
MAX_FILE_SIZE = 2 * 1024 * 1024

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ---------------- DATABASE ----------------

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip_address TEXT,
            severity TEXT,
            description TEXT
        )
    """)

    # Add status column if it does not already exist
    columns = [
        row["name"]
        for row in conn.execute("PRAGMA table_info(alerts)").fetchall()
    ]

    if "status" not in columns:
        conn.execute("""
            ALTER TABLE alerts
            ADD COLUMN status TEXT DEFAULT 'OPEN'
        """)

    conn.commit()
    conn.close()


# ---------------- SAVE ALERTS ----------------

def save_alerts(alerts):
    conn = get_db_connection()

    for alert in alerts:

        existing = conn.execute("""
            SELECT id
            FROM alerts
            WHERE ip_address = ?
            AND severity = ?
            AND status != 'RESOLVED'
        """, (
            alert["ip_address"],
            alert["severity"]
        )).fetchone()

        if existing:
            conn.execute("""
                UPDATE alerts
                SET timestamp = ?, description = ?
                WHERE id = ?
            """, (
                alert["timestamp"],
                alert["description"],
                existing["id"]
            ))

        else:
            conn.execute("""
                INSERT INTO alerts
                (timestamp, ip_address, severity, description, status)
                VALUES (?, ?, ?, ?, 'OPEN')
            """, (
                alert["timestamp"],
                alert["ip_address"],
                alert["severity"],
                alert["description"]
            ))

    conn.commit()
    conn.close()


# ---------------- ALERT HISTORY ----------------

def get_alert_history(search="", severity="", status=""):

    conn = get_db_connection()

    query = "SELECT * FROM alerts WHERE 1=1"
    params = []

    if search:
        query += " AND (ip_address LIKE ? OR description LIKE ?)"
        params.extend([f"%{search}%", f"%{search}%"])

    if severity:
        query += " AND severity = ?"
        params.append(severity)

    if status:
        query += " AND status = ?"
        params.append(status)

    query += " ORDER BY id DESC LIMIT 100"

    rows = conn.execute(query, params).fetchall()

    conn.close()

    return [dict(row) for row in rows]


# ---------------- DASHBOARD DATA ----------------

def get_dashboard_data():

    conn = get_db_connection()

    rows = conn.execute("""
        SELECT * FROM alerts
        ORDER BY id DESC
    """).fetchall()

    alerts = [dict(row) for row in rows]

    total_alerts = len(alerts)

    high_alerts = sum(
        1 for a in alerts if a["severity"] == "HIGH"
    )

    medium_alerts = sum(
        1 for a in alerts if a["severity"] == "MEDIUM"
    )

    open_alerts = sum(
        1 for a in alerts if a["status"] == "OPEN"
    )

    severity_counts = dict(
        Counter(a["severity"] for a in alerts)
    )

    status_counts = dict(
        Counter(a["status"] for a in alerts)
    )

    recent_alerts = alerts[:10]

    conn.close()

    return {
        "total_alerts": total_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "open_alerts": open_alerts,
        "severity_counts": severity_counts,
        "status_counts": status_counts,
        "recent_alerts": recent_alerts
    }


# ---------------- LOG ANALYSIS ----------------


def analyze_logs(file_path):

    alerts = []
    failed_logins = {}

    successful_logins = 0
    failed_events = 0
    total_events = 0

    sql_injection_count = 0
    directory_traversal_count = 0

    with open(file_path, "r", encoding="utf-8", errors="replace") as file:

        for line in file:

            line = line.strip()

            if not line:
                continue

            total_events += 1

            # Extract IP address
            ip_match = re.search(
                r"IP\s*=\s*([0-9a-fA-F:.]+)",
                line
            )

            if not ip_match:
                continue

            ip = ip_match.group(1)

            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue

            # BRUTE FORCE DETECTION
            if re.search(
                r"failed login|login failed|authentication failure",
                line,
                re.IGNORECASE
            ):
                failed_events += 1
                failed_logins[ip] = failed_logins.get(ip, 0) + 1

            # SUCCESSFUL LOGIN
            elif re.search(
                r"login successful|successful login",
                line,
                re.IGNORECASE
            ):
                successful_logins += 1

            # SQL INJECTION DETECTION
            if re.search(
                r"UNION\s+SELECT|OR\s+1\s*=\s*1|'\s*OR\s+|--",
                line,
                re.IGNORECASE
            ):
                sql_injection_count += 1

                alerts.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip_address": ip,
                    "severity": "HIGH",
                    "description": f"Possible SQL Injection detected from {ip}"
                })

            # DIRECTORY TRAVERSAL DETECTION
            if re.search(
                r"\.\./|\.\.\\|/etc/passwd|windows/system\.ini",
                line,
                re.IGNORECASE
            ):
                directory_traversal_count += 1

                alerts.append({
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip_address": ip,
                    "severity": "HIGH",
                    "description": f"Possible Directory Traversal detected from {ip}"
                })

    # Generate brute-force alerts
    for ip, count in failed_logins.items():

        if count >= 5:
            severity = "HIGH"
            description = f"Possible Brute Force Attack: {count} failed login attempts from {ip}"

        elif count >= 3:
            severity = "MEDIUM"
            description = f"Multiple failed login attempts: {count} attempts from {ip}"

        else:
            continue

        alerts.append({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ip_address": ip,
            "severity": severity,
            "description": description
        })

    # Statistics
    stats = {
        "total_events": total_events,
        "failed_events": failed_events,
        "successful_logins": successful_logins,
        "suspicious_ips": len([
            ip for ip, count in failed_logins.items() if count >= 3
        ]),
        "high_alerts": sum(
            1 for alert in alerts if alert["severity"] == "HIGH"
        ),
        "sql_injection_count": sql_injection_count,
        "directory_traversal_count": directory_traversal_count
    }

    chart_data = {
        "labels": [
            "Failed Logins",
            "Successful Logins",
            "SQL Injection",
            "Directory Traversal"
        ],
        "values": [
            failed_events,
            successful_logins,
            sql_injection_count,
            directory_traversal_count
        ]
    }

    return alerts, stats, chart_data


# ---------------- DASHBOARD ROUTE ----------------

@app.route("/")
def dashboard():

    data = get_dashboard_data()

    return render_template(
        "dashboard.html",
        **data
    )


# ---------------- ANALYSIS PAGE ----------------

@app.route("/analysis")
def analysis():

    return render_template("analysis.html")


# ---------------- FILE UPLOAD ----------------

@app.route("/upload", methods=["POST"])
def upload():

    if "file" not in request.files:
        flash("No file selected.", "error")
        return redirect(url_for("analysis"))

    file = request.files["file"]

    if file.filename == "":
        flash("Please select a log file.", "error")
        return redirect(url_for("analysis"))

    filename = secure_filename(file.filename)

    if "." not in filename:
        flash("Invalid file format.", "error")
        return redirect(url_for("analysis"))

    extension = filename.rsplit(".", 1)[1].lower()

    if extension not in ALLOWED_EXTENSIONS:
        flash("Only .log and .txt files are allowed.", "error")
        return redirect(url_for("analysis"))

    # Generate unique filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")

    saved_filename = f"{timestamp}_{filename}"

    file_path = os.path.join(
        app.config["UPLOAD_FOLDER"],
        saved_filename
    )

    try:

        file.save(file_path)

        # Analyze uploaded log file
        alerts, stats, chart_data = analyze_logs(file_path)

        # Save generated alerts
        save_alerts(alerts)

        flash(
            f"Analysis completed! "
            f"Total events: {stats['total_events']} | "
            f"Failed logins: {stats['failed_events']} | "
            f"Alerts detected: {len(alerts)}",
            "success"
        )

    except Exception as e:

        app.logger.exception("Log analysis failed")

        flash(
            f"Error analyzing log file: {str(e)}",
            "error"
        )

    finally:

        if os.path.exists(file_path):
            os.remove(file_path)

    return redirect(url_for("dashboard"))


# ---------------- UPDATE ALERT STATUS ----------------

@app.route("/update-status/<int:alert_id>", methods=["POST"])
def update_status(alert_id):

    new_status = request.form.get("status", "").upper()

    allowed_statuses = [
        "OPEN",
        "INVESTIGATING",
        "RESOLVED"
    ]

    if new_status not in allowed_statuses:
        flash("Invalid alert status.", "error")
        return redirect(url_for("dashboard"))

    conn = get_db_connection()

    conn.execute("""
        UPDATE alerts
        SET status = ?
        WHERE id = ?
    """, (
        new_status,
        alert_id
    ))

    conn.commit()
    conn.close()

    flash("Alert status updated successfully.", "success")

    return redirect(url_for("dashboard"))


# ---------------- FILE SIZE ERROR ----------------

@app.errorhandler(413)
def file_too_large(error):

    flash(
        "File is too large. Maximum allowed size is 2 MB.",
        "error"
    )

    return redirect(url_for("analysis"))


# ---------------- START APPLICATION ----------------

init_db()

if __name__ == "__main__":
    app.run(debug=True)
