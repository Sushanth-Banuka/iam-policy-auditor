import sqlite3
import json
import os

class AuditDB:
    def __init__(self, db_path="iam_audit_history.db"):
        self.db_path = db_path
        # SQLite connection must use check_same_thread=False
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                summary TEXT,
                findings TEXT,
                principals TEXT
            )
        ''')
        self.conn.commit()

    def save_audit(self, results):
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO audits (timestamp, summary, findings, principals)
            VALUES (?, ?, ?, ?)
        ''', (
            results.get("scanned_at"),
            json.dumps(results.get("summary", {})),
            json.dumps(results.get("findings", [])),
            json.dumps(results.get("principals", []))
        ))
        self.conn.commit()

    def get_history(self):
        cursor = self.conn.cursor()
        # Return last 10 audits as list of dicts with timestamp, total_findings, critical, high
        cursor.execute('''
            SELECT timestamp, summary FROM audits ORDER BY id DESC LIMIT 10
        ''')
        rows = cursor.fetchall()
        history = []
        for row in rows:
            timestamp = row["timestamp"]
            try:
                summary = json.loads(row["summary"])
            except:
                summary = {}
            history.append({
                "timestamp": timestamp,
                "total_findings": summary.get("total", 0),
                "critical": summary.get("critical", 0),
                "high": summary.get("high", 0)
            })
        return history
