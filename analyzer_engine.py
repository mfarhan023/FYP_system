import re
import os
import psycopg2
from urllib.parse import urlparse


class AnalyzerEngine:
    """
    Blacklist-only phishing detection engine.
    Extracts URLs from email text and checks them against the Supabase blacklist table.
    Result: 'Confirmed Phishing' if any URL is blacklisted, else 'Safe'.
    """

    def __init__(self):
        self.db_url = os.environ.get('DATABASE_URL')

    def extract_urls(self, text: str) -> list:
        """Extract all URLs from the email text."""
        url_pattern = re.compile(
            r'(?:https?://|ftp://|www\.)[^\s<>"\']+'
        )
        urls = url_pattern.findall(text)
        return [u.rstrip('.,;:!?)\'\"') for u in urls if u]

    def _check_url(self, url: str, cursor) -> bool:
        """
        Check a single URL against the Supabase blacklist.
        First tries exact match, then domain-level match.
        """
        normalized = url.strip().lower().rstrip('/')

        # 1. Exact URL match (fast — uses index)
        cursor.execute(
            'SELECT 1 FROM blacklist WHERE url = %s LIMIT 1',
            (normalized,)
        )
        if cursor.fetchone():
            return True

        # 2. Domain-level match
        try:
            domain = urlparse(normalized).netloc
            if domain:
                cursor.execute(
                    "SELECT 1 FROM blacklist WHERE url LIKE %s LIMIT 1",
                    (f'%{domain}%',)
                )
                if cursor.fetchone():
                    return True
        except Exception:
            pass

        return False

    def analyze(self, email_text: str) -> dict:
        """
        Analyze email text against the Supabase blacklist.
        Returns a result dict with label 'Confirmed Phishing' or 'Safe'.
        """
        urls = self.extract_urls(email_text)
        url_evidence = []
        any_blacklisted = False

        if urls and self.db_url:
            conn = psycopg2.connect(self.db_url)
            try:
                with conn.cursor() as cur:
                    for url in urls:
                        is_bl = self._check_url(url, cur)
                        if is_bl:
                            any_blacklisted = True
                        url_evidence.append({
                            'url': url,
                            'blacklisted': is_bl,
                            'display': url[:55] + '...' if len(url) > 55 else url,
                            'phishtank_status': 'MALICIOUS' if is_bl else 'NOT LISTED',
                        })
            finally:
                conn.close()
        else:
            # No DB connection available — classify all URLs as not listed
            for url in urls:
                url_evidence.append({
                    'url': url,
                    'blacklisted': False,
                    'display': url[:55] + '...' if len(url) > 55 else url,
                    'phishtank_status': 'NOT LISTED',
                })

        label = 'Confirmed Phishing' if any_blacklisted else 'Safe'

        return {
            'label': label,
            'urls_found': urls,
            'url_evidence': url_evidence,
            'url_count': len(urls),
            'blacklisted_count': sum(1 for u in url_evidence if u['blacklisted']),
            'email_preview': email_text[:200].strip(),
        }
