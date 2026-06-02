import sqlite3
import csv
import io
from datetime import datetime


class SQLiteLogger:
    """Handles all SQLite persistence for EzVeriPhish."""

    def __init__(self, db_path: str = 'ezveri.db'):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS analysis_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    content_preview TEXT,
                    label TEXT,
                    url_count INTEGER,
                    blacklisted_count INTEGER
                )
            ''')
            c.execute('''
                CREATE TABLE IF NOT EXISTS url_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    analysis_id INTEGER,
                    url TEXT,
                    is_blacklisted INTEGER,
                    phishtank_status TEXT,
                    FOREIGN KEY (analysis_id) REFERENCES analysis_log(id)
                )
            ''')
            try:
                c.execute("UPDATE analysis_log SET label = 'Low Risk' WHERE label = 'Safe'")
            except Exception:
                pass
            conn.commit()

    def log_result(self, result: dict) -> int:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with self._connect() as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO analysis_log (timestamp, content_preview, label, url_count, blacklisted_count)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                timestamp,
                result.get('email_preview', '')[:200],
                result.get('label', 'Unknown'),
                result.get('url_count', 0),
                result.get('blacklisted_count', 0)
            ))
            analysis_id = c.lastrowid
            for url_info in result.get('url_evidence', []):
                c.execute('''
                    INSERT INTO url_log (analysis_id, url, is_blacklisted, phishtank_status)
                    VALUES (?, ?, ?, ?)
                ''', (
                    analysis_id,
                    url_info.get('url', ''),
                    1 if url_info.get('blacklisted') else 0,
                    url_info.get('phishtank_status', 'NOT LISTED')
                ))
            conn.commit()
        return analysis_id

    def get_all_analyses(self) -> list:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT * FROM analysis_log ORDER BY id DESC')
            return [dict(row) for row in c.fetchall()]

    def get_analysis_by_id(self, analysis_id: int) -> dict:
        with self._connect() as conn:
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute('SELECT * FROM analysis_log WHERE id = ?', (analysis_id,))
            row = c.fetchone()
            if not row:
                return None
            result = dict(row)
            c.execute('SELECT * FROM url_log WHERE analysis_id = ?', (analysis_id,))
            result['url_evidence'] = []
            for r in c.fetchall():
                d = dict(r)
                d['blacklisted'] = bool(d['is_blacklisted'])
                d['display'] = d['url'][:55] + '...' if len(d['url']) > 55 else d['url']
                result['url_evidence'].append(d)
            return result

    def get_stats(self) -> dict:
        with self._connect() as conn:
            c = conn.cursor()
            c.execute('SELECT COUNT(*) FROM analysis_log')
            total = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM analysis_log WHERE label = 'Confirmed Phishing'")
            confirmed = c.fetchone()[0]
            c.execute("SELECT COUNT(*) FROM analysis_log WHERE label = 'Low Risk'")
            safe = c.fetchone()[0]
        return {'total': total, 'confirmed': confirmed, 'safe': safe}

    def export_csv_content(self) -> str:
        records = self.get_all_analyses()
        if not records:
            return ''
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)
        return output.getvalue()
