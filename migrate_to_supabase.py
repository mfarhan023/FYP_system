"""
migrate_to_supabase.py
----------------------
One-time migration script. Run this ONCE locally to:
  1. Create the required tables in Supabase (analysis_log, url_log, blacklist)
  2. Import existing records from ezveri.db into Supabase
  3. Import phishtank.csv + verified_online.csv into the blacklist table

Usage:
  1. Copy .env.example to .env and fill in your DATABASE_URL
  2. Run: py -3 migrate_to_supabase.py
"""

import os
import csv
import sqlite3
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv

load_dotenv()

SQLITE_PATH = 'ezveri.db'
DATABASE_URL = os.environ.get('DATABASE_URL')
BLACKLIST_CSVS = ['phishtank.csv', 'verified_online.csv']


def create_tables(pg_conn):
    print("Creating tables in Supabase...")
    with pg_conn.cursor() as c:
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
        c.execute('''
            CREATE TABLE IF NOT EXISTS blacklist (
                id BIGSERIAL PRIMARY KEY,
                url TEXT UNIQUE NOT NULL
            )
        ''')
        c.execute('CREATE INDEX IF NOT EXISTS idx_blacklist_url ON blacklist(url)')
    pg_conn.commit()
    print("  Tables ready.")


def migrate_sqlite(pg_conn):
    if not os.path.exists(SQLITE_PATH):
        print(f"  No {SQLITE_PATH} found — skipping SQLite migration.")
        return

    print(f"Migrating records from {SQLITE_PATH}...")
    sqlite_conn = sqlite3.connect(SQLITE_PATH)
    sqlite_conn.row_factory = sqlite3.Row

    analyses = sqlite_conn.execute('SELECT * FROM analysis_log').fetchall()
    urls = sqlite_conn.execute('SELECT * FROM url_log').fetchall()
    sqlite_conn.close()

    with pg_conn.cursor() as c:
        for row in analyses:
            c.execute('''
                INSERT INTO analysis_log
                    (id, timestamp, content_preview, label, url_count, blacklisted_count)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            ''', (row['id'], row['timestamp'], row['content_preview'],
                  row['label'], row['url_count'], row['blacklisted_count']))

        for row in urls:
            c.execute('''
                INSERT INTO url_log
                    (id, analysis_id, url, is_blacklisted, phishtank_status)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT (id) DO NOTHING
            ''', (row['id'], row['analysis_id'], row['url'],
                  row['is_blacklisted'], row['phishtank_status']))

    pg_conn.commit()
    print(f"  Migrated {len(analyses)} analyses and {len(urls)} URL records.")


def import_blacklist(pg_conn):
    for csv_path in BLACKLIST_CSVS:
        if not os.path.exists(csv_path):
            print(f"  {csv_path} not found — skipping.")
            continue

        print(f"Importing blacklist from {csv_path}...")
        batch = []
        total = 0

        with open(csv_path, newline='', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            with pg_conn.cursor() as c:
                for row in reader:
                    url = row.get('url', row.get('URL', '')).strip().lower().rstrip('/')
                    if url and len(url) <= 2000:
                        batch.append((url,))
                        if len(batch) >= 1000:
                            psycopg2.extras.execute_values(
                                c,
                                'INSERT INTO blacklist (url) VALUES %s ON CONFLICT (url) DO NOTHING',
                                batch
                            )
                            total += len(batch)
                            batch = []
                            print(f"  Inserted {total} rows...", end='\r')
                if batch:
                    psycopg2.extras.execute_values(
                        c,
                        'INSERT INTO blacklist (url) VALUES %s ON CONFLICT (url) DO NOTHING',
                        batch
                    )
                    total += len(batch)
            pg_conn.commit()
        print(f"  Done! {total} entries imported from {csv_path}.")


def main():
    if not DATABASE_URL:
        print("ERROR: DATABASE_URL not set. Copy .env.example to .env and fill it in.")
        return

    print(f"Connecting to Supabase...")
    pg_conn = psycopg2.connect(DATABASE_URL)
    print("  Connected!\n")

    try:
        create_tables(pg_conn)
        migrate_sqlite(pg_conn)
        import_blacklist(pg_conn)
    finally:
        pg_conn.close()

    print("\nMigration complete! Your Supabase database is ready.")


if __name__ == '__main__':
    main()
