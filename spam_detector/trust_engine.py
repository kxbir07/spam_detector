"""
Trust Engine — Sender Reputation Scoring System
------------------------------------------------
Categories:
  VERIFIED     trust_score >= 80   (reliable ham sender)
  TRUSTED      trust_score 65–79
  NEUTRAL      trust_score 40–64   (default / unknown)
  SUSPICIOUS   trust_score 20–39
  SPAMMER      trust_score < 20    (confirmed bad actor)

Score mechanics:
  Ham prediction   → +8 points  (capped at 100)
  Spam prediction  → -12 points (floored at 0)
  Alert triggers at score < 20 after >= 3 emails seen
  Auto-verify triggers at score >= 80 after >= 5 ham emails
"""

from database import get_connection
from datetime import datetime


CATEGORIES = {
    "VERIFIED":   (80, 100),
    "TRUSTED":    (65, 79),
    "NEUTRAL":    (40, 64),
    "SUSPICIOUS": (20, 39),
    "SPAMMER":    (0,  19),
}

CATEGORY_COLORS = {
    "VERIFIED":   "#22c55e",
    "TRUSTED":    "#84cc16",
    "NEUTRAL":    "#f59e0b",
    "SUSPICIOUS": "#f97316",
    "SPAMMER":    "#ef4444",
}

CATEGORY_ICONS = {
    "VERIFIED":   "✅",
    "TRUSTED":    "👍",
    "NEUTRAL":    "❓",
    "SUSPICIOUS": "⚠️",
    "SPAMMER":    "🚫",
}

HAM_BOOST   =  8
SPAM_PENALTY = 12

ALERT_THRESHOLD_SPAMMER  = 20   # score drops below this → spammer alert
ALERT_THRESHOLD_VERIFIED = 80   # score rises above this → auto-verify
MIN_EMAILS_FOR_ALERT     = 3    # need at least this many emails before alerting


def _score_to_category(score: float) -> str:
    for cat, (low, high) in CATEGORIES.items():
        if low <= score <= high:
            return cat
    return "NEUTRAL"


def get_sender(email: str) -> dict | None:
    conn = get_connection()
    row = conn.execute(
        "SELECT * FROM sender_trust WHERE email = ?", (email,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_senders():
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM sender_trust ORDER BY trust_score ASC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def update_sender(email: str, prediction: str) -> dict:
    """
    Update sender trust after a new prediction.
    Returns a dict with updated sender info + any alert generated.
    """
    conn = get_connection()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    existing = conn.execute(
        "SELECT * FROM sender_trust WHERE email = ?", (email,)
    ).fetchone()

    alert = None

    if existing:
        spam_count = existing["spam_count"] + (1 if prediction == "spam" else 0)
        ham_count  = existing["ham_count"]  + (1 if prediction == "ham"  else 0)
        old_score  = existing["trust_score"]
        alerted    = existing["alerted"]

        if prediction == "ham":
            new_score = min(100.0, old_score + HAM_BOOST)
        else:
            new_score = max(0.0, old_score - SPAM_PENALTY)

        new_category = _score_to_category(new_score)
        total_emails  = spam_count + ham_count

        # Spammer alert — score fell below threshold
        if (new_score < ALERT_THRESHOLD_SPAMMER
                and total_emails >= MIN_EMAILS_FOR_ALERT
                and not alerted):
            alert = _create_alert(
                conn, email, "SPAMMER_DETECTED",
                f"⚠️ Possible spammer detected: {email} has a trust score of "
                f"{new_score:.0f}/100 after {total_emails} emails "
                f"({spam_count} spam, {ham_count} ham). Please review and take action.",
                now
            )
            alerted = 1

        # Auto-verified
        elif (new_score >= ALERT_THRESHOLD_VERIFIED
              and ham_count >= 5
              and old_score < ALERT_THRESHOLD_VERIFIED):
            alert = _create_alert(
                conn, email, "AUTO_VERIFIED",
                f"✅ Sender {email} has been auto-verified as trusted "
                f"(score: {new_score:.0f}/100, {ham_count} clean emails).",
                now
            )

        conn.execute("""
            UPDATE sender_trust
            SET spam_count=?, ham_count=?, trust_score=?, category=?,
                alerted=?, last_seen=?
            WHERE email=?
        """, (spam_count, ham_count, new_score, new_category, alerted, now, email))

    else:
        # First time seeing this sender
        if prediction == "ham":
            initial_score = 50.0 + HAM_BOOST
        else:
            initial_score = 50.0 - SPAM_PENALTY

        initial_score = max(0.0, min(100.0, initial_score))
        new_category  = _score_to_category(initial_score)
        spam_count    = 1 if prediction == "spam" else 0
        ham_count     = 1 if prediction == "ham"  else 0
        new_score     = initial_score

        conn.execute("""
            INSERT INTO sender_trust
            (email, spam_count, ham_count, trust_score, category, alerted, last_seen, first_seen)
            VALUES (?, ?, ?, ?, ?, 0, ?, ?)
        """, (email, spam_count, ham_count, new_score, new_category, now, now))

    conn.commit()
    conn.close()

    return {
        "email":       email,
        "trust_score": new_score,
        "category":    new_category,
        "color":       CATEGORY_COLORS.get(new_category, "#888"),
        "icon":        CATEGORY_ICONS.get(new_category, "❓"),
        "alert":       alert,
    }


def _create_alert(conn, sender, alert_type, message, timestamp):
    conn.execute("""
        INSERT INTO alerts (sender, alert_type, message, dismissed, timestamp)
        VALUES (?, ?, ?, 0, ?)
    """, (sender, alert_type, message, timestamp))
    return {
        "sender":     sender,
        "alert_type": alert_type,
        "message":    message,
        "timestamp":  timestamp,
    }


def get_active_alerts():
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM alerts WHERE dismissed=0 ORDER BY timestamp DESC"
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def dismiss_alert(alert_id: int):
    conn = get_connection()
    conn.execute("UPDATE alerts SET dismissed=1 WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()


def manual_override(email: str, action: str):
    """
    action: 'block' → force SPAMMER, score=0
            'trust' → force VERIFIED, score=95
            'reset' → back to NEUTRAL, score=50
    """
    conn = get_connection()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    mapping = {
        "block": (0.0,  "SPAMMER"),
        "trust": (95.0, "VERIFIED"),
        "reset": (50.0, "NEUTRAL"),
    }
    if action not in mapping:
        conn.close()
        return False

    score, category = mapping[action]
    existing = conn.execute(
        "SELECT * FROM sender_trust WHERE email=?", (email,)
    ).fetchone()

    if existing:
        conn.execute("""
            UPDATE sender_trust SET trust_score=?, category=?, alerted=0, last_seen=?
            WHERE email=?
        """, (score, category, now, email))
    else:
        conn.execute("""
            INSERT INTO sender_trust
            (email, spam_count, ham_count, trust_score, category, alerted, last_seen, first_seen)
            VALUES (?, 0, 0, ?, ?, 0, ?, ?)
        """, (email, score, category, now, now))

    conn.commit()
    conn.close()
    return True


def get_stats():
    conn = get_connection()
    rows = conn.execute("SELECT category, COUNT(*) as cnt FROM sender_trust GROUP BY category").fetchall()
    conn.close()
    stats = {cat: 0 for cat in CATEGORIES}
    for r in rows:
        stats[r["category"]] = r["cnt"]
    return stats
