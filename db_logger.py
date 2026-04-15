import csv
import io
import os
import psycopg2
import psycopg2.extras
from datetime import datetime


class DbLogger:
    """Handles all PostgreSQL persistence for EzVeriPhish via Supabase."""

    def __init__(self):
        self.db_url = os.environ.get('DATABASE_URL')
        if not self.db_url:
            raise ValueError("DATABASE_URL environment variable is not set.")
        self._init_db()

    def _connect(self):
        return psycopg2.connect(self.db_url)

    def _init_db(self):
        """Ensure tables exist (safe to run on every startup)."""
        with self._connect() as conn:
            with conn.cursor() as c:
                c.execute('''
                    CREATE TABLE IF NOT EXISTS analysis_log (
                        id BIGSERIAL PRIMARY KEY,
                        timestamp TEXT NOT NULL,
                        content_preview TEXT,
                        label TEXT,
                        url_count INTEGER,
                        blacklisted_count INTEGER
                    )
                ''')
                c.execute('''
                    CREATE TABLE IF NOT EXISTS url_log (
                        id BIGSERIAL PRIMARY KEY,
                        analysis_id BIGINT REFERENCES analysis_log(id),
                        url TEXT,
                        is_blacklisted INTEGER,
                        phishtank_status TEXT
                    )
                ''')
            conn.commit()

    def log_result(self, result: dict) -> int:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with self._connect() as conn:
            with conn.cursor() as c:
                c.execute('''
                    INSERT INTO analysis_log
                        (timestamp, content_preview, label, url_count, blacklisted_count)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING id
                ''', (
                    timestamp,
                    result.get('email_preview', '')[:200],
                    result.get('label', 'Unknown'),
                    result.get('url_count', 0),
                    result.get('blacklisted_count', 0),
                ))
                analysis_id = c.fetchone()[0]
                for url_info in result.get('url_evidence', []):
                    c.execute('''
                        INSERT INTO url_log
                            (analysis_id, url, is_blacklisted, phishtank_status)
                        VALUES (%s, %s, %s, %s)
                    ''', (
                        analysis_id,
                        url_info.get('url', ''),
                        1 if url_info.get('blacklisted') else 0,
                        url_info.get('phishtank_status', 'NOT LISTED'),
                    ))
            conn.commit()
        return analysis_id

    def get_all_analyses(self) -> list:
        with self._connect() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c:
                c.execute('SELECT * FROM analysis_log ORDER BY id DESC')
                return [dict(row) for row in c.fetchall()]

    def get_analysis_by_id(self, analysis_id: int) -> dict:
        with self._connect() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as c:
                c.execute('SELECT * FROM analysis_log WHERE id = %s', (analysis_id,))
                row = c.fetchone()
                if not row:
                    return None
                result = dict(row)
                c.execute('SELECT * FROM url_log WHERE analysis_id = %s', (analysis_id,))
                result['url_evidence'] = []
                for r in c.fetchall():
                    d = dict(r)
                    d['blacklisted'] = bool(d['is_blacklisted'])
                    d['display'] = d['url'][:55] + '...' if len(d['url']) > 55 else d['url']
                    result['url_evidence'].append(d)
                return result

    def get_stats(self) -> dict:
        with self._connect() as conn:
            with conn.cursor() as c:
                c.execute('SELECT COUNT(*) FROM analysis_log')
                total = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM analysis_log WHERE label = 'Confirmed Phishing'")
                confirmed = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM analysis_log WHERE label = 'Safe'")
                safe = c.fetchone()[0]
        return {'total': total, 'confirmed': confirmed, 'safe': safe}

    def delete_analysis(self, analysis_id: int):
        with self._connect() as conn:
            with conn.cursor() as c:
                c.execute('DELETE FROM url_log WHERE analysis_id = %s', (analysis_id,))
                c.execute('DELETE FROM analysis_log WHERE id = %s', (analysis_id,))
            conn.commit()

    def export_csv_content(self) -> str:
        records = self.get_all_analyses()
        if not records:
            return ''
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=records[0].keys())
        writer.writeheader()
        writer.writerows(records)
        return output.getvalue()
