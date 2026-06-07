import csv
import io
import json
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
                        blacklisted_count INTEGER,
                        heuristic_label TEXT,
                        heuristic_score INTEGER,
                        triggered_features TEXT
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
                # Migration: add heuristic columns to existing deployments
                for col, coltype in [
                    ('heuristic_label', 'TEXT'),
                    ('heuristic_score', 'INTEGER'),
                    ('triggered_features', 'TEXT')
                ]:
                    try:
                        c.execute(f'ALTER TABLE analysis_log ADD COLUMN IF NOT EXISTS {col} {coltype}')
                    except Exception:
                        pass

                # Migration: update 'Safe' labels to 'Low Risk'
                try:
                    c.execute("UPDATE analysis_log SET label = 'Low Risk' WHERE label = 'Safe'")
                    c.execute("UPDATE analysis_log SET heuristic_label = 'Low Risk' WHERE heuristic_label = 'Safe'")
                except Exception:
                    pass
            conn.commit()

    def log_result(self, result: dict) -> int:
        from datetime import timezone, timedelta
        malaysia_tz = timezone(timedelta(hours=8))
        timestamp = datetime.now(malaysia_tz).strftime('%Y-%m-%d %H:%M:%S')
        with self._connect() as conn:
            with conn.cursor() as c:
                # Serialize triggered_features list to JSON string for storage
                features_json = json.dumps(result.get('triggered_features', []))
                c.execute('''
                    INSERT INTO analysis_log
                        (timestamp, content_preview, label, url_count, blacklisted_count,
                         heuristic_label, heuristic_score, triggered_features)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING id
                ''', (
                    timestamp,
                    result.get('email_preview', ''),
                    result.get('label', 'Unknown'),
                    result.get('url_count', 0),
                    result.get('blacklisted_count', 0),
                    result.get('heuristic_label'),
                    result.get('heuristic_score'),
                    features_json,
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
                # Deserialize triggered_features JSON string back to a list
                raw_features = result.get('triggered_features') or '[]'
                try:
                    features = json.loads(raw_features)
                    if isinstance(features, list):
                        severity_map = {'Big': 4, 'Medium': 2, 'Small': 1}
                        for feat in features:
                            if isinstance(feat, dict):
                                if 'priority_value' not in feat or feat['priority_value'] is None:
                                    feat['priority_value'] = severity_map.get(feat.get('severity'), 1)
                    else:
                        features = []
                    result['triggered_features'] = features
                except (json.JSONDecodeError, TypeError):
                    result['triggered_features'] = []
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
                c.execute("SELECT COUNT(*) FROM analysis_log WHERE label = 'Low Risk'")
                safe = c.fetchone()[0]
                c.execute("SELECT COUNT(*) FROM analysis_log WHERE label = 'Suspicious'")
                suspicious = c.fetchone()[0]
        return {'total': total, 'confirmed': confirmed, 'safe': safe, 'suspicious': suspicious}

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
