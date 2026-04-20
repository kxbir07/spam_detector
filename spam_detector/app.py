"""
app.py — Flask Application Entry Point
"""

import os
import json
from datetime import datetime
from flask import (Flask, render_template, request, jsonify,
                   redirect, url_for, flash)

from database import init_db, get_connection
from trust_engine import (update_sender, get_all_senders, get_active_alerts,
                           dismiss_alert, manual_override, get_stats,
                           CATEGORY_COLORS, CATEGORY_ICONS)
from url_scanner import scan_urls, threat_summary
from train import load_model, predict

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "spamdetector-dev-secret-2024")

# ── Load model once at startup ─────────────────────────────────────────────
try:
    MODEL = load_model()
    MODEL_LOADED = True
    print("[App] ✅ Model loaded successfully.")
except FileNotFoundError as e:
    MODEL = None
    MODEL_LOADED = False
    print(f"[App] ⚠️  {e}")


# ── Helpers ────────────────────────────────────────────────────────────────

def log_email(sender, subject, prediction, confidence, urls_found, url_threats):
    conn = get_connection()
    conn.execute("""
        INSERT INTO email_history
        (sender, subject, prediction, confidence, urls_found, url_threats, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        sender, subject, prediction, confidence,
        json.dumps(urls_found), url_threats,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))
    conn.commit()
    conn.close()


# ── Routes ─────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    alerts = get_active_alerts()
    stats  = get_stats()
    model_ready = MODEL_LOADED

    # Recent emails
    conn = get_connection()
    recent = conn.execute(
        "SELECT * FROM email_history ORDER BY timestamp DESC LIMIT 8"
    ).fetchall()
    conn.close()
    recent = [dict(r) for r in recent]

    return render_template("index.html",
                           alerts=alerts,
                           stats=stats,
                           recent=recent,
                           model_ready=model_ready,
                           cat_colors=CATEGORY_COLORS,
                           cat_icons=CATEGORY_ICONS)


@app.route("/analyze", methods=["POST"])
def analyze():
    if not MODEL_LOADED:
        flash("⚠️ Model not loaded. Please run python train.py first.", "error")
        return redirect(url_for("index"))

    sender  = request.form.get("sender", "").strip().lower()
    subject = request.form.get("subject", "").strip()
    body    = request.form.get("body", "").strip()

    if not body:
        flash("Email body cannot be empty.", "error")
        return redirect(url_for("index"))

    # ── 1. Spam prediction ────────────────────────────────────────────────
    full_text  = f"{subject} {body}"
    prediction = predict(MODEL, full_text)

    # ── 2. URL scanning ───────────────────────────────────────────────────
    url_results  = scan_urls(body)
    url_summary  = threat_summary(url_results)

    # ── 3. Trust engine update ────────────────────────────────────────────
    trust_info = None
    alert      = None
    if sender:
        trust_data = update_sender(sender, prediction["label"])
        trust_info = trust_data
        alert      = trust_data.get("alert")

    # ── 4. Log to history ─────────────────────────────────────────────────
    log_email(
        sender    = sender or "unknown",
        subject   = subject,
        prediction= prediction["label"],
        confidence= prediction["confidence"],
        urls_found= [r["full_url"] for r in url_results],
        url_threats= url_summary["dangerous"] + url_summary["suspicious"],
    )

    return render_template("result.html",
                           sender=sender,
                           subject=subject,
                           body=body,
                           prediction=prediction,
                           url_results=url_results,
                           url_summary=url_summary,
                           trust_info=trust_info,
                           alert=alert,
                           cat_colors=CATEGORY_COLORS,
                           cat_icons=CATEGORY_ICONS)


@app.route("/dashboard")
def dashboard():
    senders = get_all_senders()
    alerts  = get_active_alerts()
    stats   = get_stats()

    # Annotate with color/icon
    for s in senders:
        s["color"] = CATEGORY_COLORS.get(s["category"], "#888")
        s["icon"]  = CATEGORY_ICONS.get(s["category"], "❓")

    # Email history
    conn = get_connection()
    history = conn.execute(
        "SELECT * FROM email_history ORDER BY timestamp DESC LIMIT 50"
    ).fetchall()
    conn.close()
    history = [dict(r) for r in history]

    return render_template("dashboard.html",
                           senders=senders,
                           alerts=alerts,
                           stats=stats,
                           history=history,
                           cat_colors=CATEGORY_COLORS,
                           cat_icons=CATEGORY_ICONS)


@app.route("/alert/dismiss/<int:alert_id>", methods=["POST"])
def dismiss(alert_id):
    dismiss_alert(alert_id)
    return jsonify({"status": "ok"})


@app.route("/sender/action", methods=["POST"])
def sender_action():
    email  = request.form.get("email", "").strip()
    action = request.form.get("action", "").strip()
    if email and action in ("block", "trust", "reset"):
        manual_override(email, action)
        flash(f"Sender {email} updated: {action.upper()}", "success")
    return redirect(url_for("dashboard"))


@app.route("/api/scan-url", methods=["POST"])
def api_scan_url():
    """Live URL scan endpoint called from the result page."""
    data = request.get_json()
    url  = data.get("url", "")
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    results = scan_urls(url)
    return jsonify(results)


@app.route("/api/stats")
def api_stats():
    stats = get_stats()
    conn  = get_connection()
    total_emails = conn.execute("SELECT COUNT(*) FROM email_history").fetchone()[0]
    total_spam   = conn.execute(
        "SELECT COUNT(*) FROM email_history WHERE prediction='spam'"
    ).fetchone()[0]
    conn.close()
    return jsonify({
        "sender_stats":  stats,
        "total_emails":  total_emails,
        "total_spam":    total_spam,
        "total_ham":     total_emails - total_spam,
    })


if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
