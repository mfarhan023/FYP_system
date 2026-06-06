import re
import os
import psycopg2
import urllib.request
import urllib.parse
import json
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
            domain = urlparse(normalized).netloc.lower()
            if domain:
                # Strip leading 'www.' if present
                base_domain = domain[4:] if domain.startswith('www.') else domain
                cursor.execute(
                    "SELECT url FROM blacklist WHERE url LIKE %s LIMIT 100",
                    (f'%{base_domain}%',)
                )
                rows = cursor.fetchall()
                for row in rows:
                    bl_url = row[0].strip().lower()
                    try:
                        parsed_bl = urlparse(bl_url)
                        bl_domain = parsed_bl.netloc.lower()
                        if bl_domain:
                            # Skip page-specific blocks (containing paths or queries) for domain-wide checks
                            # to prevent blocking shared platforms like bit.ly, drive.google.com, etc.
                            if parsed_bl.path.strip('/') or parsed_bl.query:
                                continue

                            bl_base = bl_domain[4:] if bl_domain.startswith('www.') else bl_domain
                            # Check for exact match or subdomain relationship
                            if bl_base == base_domain or bl_base.endswith('.' + base_domain) or base_domain.endswith('.' + bl_base):
                                return True
                    except Exception:
                        pass
        except Exception:
            pass

        return False

    def _check_url_via_api(self, url: str) -> bool:
        """
        Check a single URL against the PhishTank API in real-time.
        """
        api_url = "https://checkurl.phishtank.com/checkurl/"
        params = {
            'url': url,
            'format': 'json',
        }
        try:
            data = urllib.parse.urlencode(params).encode('utf-8')
            # User-Agent is required by PhishTank API to prevent blocking
            req = urllib.request.Request(
                api_url,
                data=data,
                headers={'User-Agent': 'phishtank/FYP_system'}
            )
            with urllib.request.urlopen(req, timeout=5) as response:
                if response.status == 200:
                    res_data = response.read().decode('utf-8')
                    result = json.loads(res_data)
                    results = result.get('results', {})
                    return results.get('in_database', False) and results.get('verified', False) and results.get('valid', False)
        except Exception as e:
            print(f"[PhishTank API Error] {e}")
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
                        # Fallback to PhishTank API check if not found in local DB
                        if not is_bl:
                            is_bl = self._check_url_via_api(url)
                        
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
            # No DB connection available — fallback to API checking directly
            for url in urls:
                is_bl = self._check_url_via_api(url)
                if is_bl:
                    any_blacklisted = True
                url_evidence.append({
                    'url': url,
                    'blacklisted': is_bl,
                    'display': url[:55] + '...' if len(url) > 55 else url,
                    'phishtank_status': 'MALICIOUS' if is_bl else 'NOT LISTED',
                })

        label = 'Confirmed Phishing' if any_blacklisted else 'Low Risk'

        return {
            'label': label,
            'urls_found': urls,
            'url_evidence': url_evidence,
            'url_count': len(urls),
            'blacklisted_count': sum(1 for u in url_evidence if u['blacklisted']),
            'email_preview': email_text.strip(),
        }

