import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "spam_detector.db")


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    # Sender trust table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sender_trust (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            spam_count INTEGER DEFAULT 0,
            ham_count INTEGER DEFAULT 0,
            trust_score REAL DEFAULT 50.0,
            category TEXT DEFAULT 'unknown',
            alerted INTEGER DEFAULT 0,
            last_seen TEXT,
            first_seen TEXT
        )
    """)

    # Email history table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS email_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            subject TEXT,
            prediction TEXT,
            confidence REAL,
            urls_found TEXT,
            url_threats INTEGER DEFAULT 0,
            timestamp TEXT
        )
    """)

    # Alerts table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            alert_type TEXT,
            message TEXT,
            dismissed INTEGER DEFAULT 0,
            timestamp TEXT
        )
    """)

    conn.commit()
    conn.close()
    print("[DB] Database initialized.")


if __name__ == "__main__":
    init_db()
