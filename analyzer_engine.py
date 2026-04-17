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


# ---------------------------------------------------------------------------
# Weighted Heuristic Scoring Engine
# ---------------------------------------------------------------------------
# Triggered ONLY when no URL was found in the PhishTank blacklist.
# Analyses extracted URLs + raw email text using 11 rule-based checks,
# assigns weighted scores and returns a final risk classification.
#
# Maximum possible Total_Score : 17
# Classification threshold      : >= 9 → "Suspicious" | < 9 → "Safe"
# ---------------------------------------------------------------------------

def weighted_heuristic_score(url_list: list, email_text: str) -> dict:
    """
    Perform weighted heuristic analysis on a list of URLs and the raw email body.

    Parameters
    ----------
    url_list   : list[str]  – URLs extracted from the email (may be empty).
    email_text : str        – Full raw text of the email body.

    Returns
    -------
    dict with keys:
        final_label        – "Suspicious" or "Safe"
        total_score        – int  (0-17)
        triggered_features – list of dicts {feature_name, severity, points}
    """

    total_score      = 0
    triggered        = []   # collects every rule that fired

    # ── lowercase copy of email text for case-insensitive keyword matching ──
    email_lower = email_text.lower()

    # ===================================================================
    # SECTION 1 – URL-BASED HEURISTICS
    # Each rule is evaluated once per URL list; it only fires once even if
    # multiple URLs in the list trigger the same rule (avoids score inflation).
    # ===================================================================

    # ── Rule 1: IP address used as domain (Severity: Big, Weight: +3) ──────
    # Phishing URLs often hide behind raw IP addresses to avoid domain lookup.
    _ip_pattern = re.compile(
        r'https?://(\d{1,3}\.){3}\d{1,3}[/:]'   # IPv4 in URL authority
    )
    if any(_ip_pattern.search(url) for url in url_list):
        total_score += 3
        triggered.append({
            "feature_name": "IP in URL",
            "severity": "Big",
            "points": 3
        })

    # ── Rule 2: URL shortening service detected (Severity: Medium, Weight: +2) ─
    # Shorteners hide the true destination, a common phishing technique.
    _shortener_domains = re.compile(
        r'https?://(?:www\.)?(bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|t\.co|'
        r'buff\.ly|is\.gd|shorte\.st|tiny\.cc|rb\.gy|cutt\.ly|short\.io)'
        r'[/\s]',
        re.IGNORECASE
    )
    if any(_shortener_domains.search(url) for url in url_list):
        total_score += 2
        triggered.append({
            "feature_name": "Shortener",
            "severity": "Medium",
            "points": 2
        })

    # ── Rule 3: Excessive subdomains (Severity: Small, Weight: +1) ──────────
    # Legitimate sites rarely need more than 3 subdomain levels.
    # e.g. secure.login.bank.attacker.com → 4 labels before TLD
    def _count_subdomains(url: str) -> int:
        try:
            host = urlparse(url).netloc.split(':')[0]   # strip port if present
            return len(host.split('.')) - 2             # minus domain + TLD
        except Exception:
            return 0

    if any(_count_subdomains(url) > 3 for url in url_list):
        total_score += 1
        triggered.append({
            "feature_name": "Many subdomains",
            "severity": "Small",
            "points": 1
        })

    # ── Rule 4: Very long URL (Severity: Small, Weight: +1) ─────────────────
    # URLs longer than 75 chars are often crafted to confuse or hide destination.
    if any(len(url) > 75 for url in url_list):
        total_score += 1
        triggered.append({
            "feature_name": "Very long URL",
            "severity": "Small",
            "points": 1
        })

    # ── Rule 5: Obfuscation patterns (Severity: Small, Weight: +1) ──────────
    # Checks for three common obfuscation tricks in a single rule:
    #   • '@' symbol  – redirects browser to the part after '@'
    #   • '//'        – repeated slashes mid-URL confuse parsers
    #   • '%xx' hex   – percent-encoded characters hiding true characters
    _obfuscation = re.compile(
        r'@'                    # @ symbol in URL
        r'|(?<=[^:])//'         # double-slash NOT after the scheme colon
        r'|%[0-9a-fA-F]{2}',   # hex-encoded character sequence
    )
    if any(_obfuscation.search(url) for url in url_list):
        total_score += 1
        triggered.append({
            "feature_name": "Obfuscation patterns",
            "severity": "Small",
            "points": 1
        })

    # ── Rule 6: HTTP on login/signin path (Severity: Small, Weight: +1) ─────
    # A login page served over plain HTTP (not HTTPS) is a strong phishing signal.
    _login_http = re.compile(r'http://[^\s]*(?:login|signin)', re.IGNORECASE)
    if any(_login_http.search(url) for url in url_list):
        total_score += 1
        triggered.append({
            "feature_name": "HTTP on login path",
            "severity": "Small",
            "points": 1
        })

    # ===================================================================
    # SECTION 2 – TEXT-BASED HEURISTICS
    # Evaluated against the full email body (case-insensitive).
    # ===================================================================

    # ── Rule 7: Sensitive information request (Severity: Big, Weight: +3) ───
    # Legitimate organisations never ask for passwords/OTP/credentials via email.
    _sensitive_keywords = re.compile(
        r'\b(password|otp|one.time.pass(?:word|code)|banking.details?|'
        r'bank.details?|credentials?|credit.card|cvv|pin.number|'
        r'social.security|ssn)\b',
        re.IGNORECASE
    )
    if _sensitive_keywords.search(email_lower):
        total_score += 3
        triggered.append({
            "feature_name": "Sensitive request",
            "severity": "Big",
            "points": 3
        })

    # ── Rule 8: Threat or reward language (Severity: Medium, Weight: +2) ────
    # Fear/reward manipulation is a hallmark of phishing social engineering.
    _threat_reward = re.compile(
        r'\b(suspended?|suspension|prize|winner|won|reward|'
        r'restricted|blocked|disabled|compromised|unauthori[sz]ed)\b',
        re.IGNORECASE
    )
    if _threat_reward.search(email_lower):
        total_score += 2
        triggered.append({
            "feature_name": "Threat or reward",
            "severity": "Medium",
            "points": 2
        })

    # ── Rule 9: Urgency words (Severity: Small, Weight: +1) ─────────────────
    # Creating a false sense of urgency pressures victims into acting rashly.
    _urgency = re.compile(
        r'\b(verify|verification|update|immediate(?:ly)?|urgent(?:ly)?|'
        r'action.required|confirm.now|act.now)\b',
        re.IGNORECASE
    )
    if _urgency.search(email_lower):
        total_score += 1
        triggered.append({
            "feature_name": "Urgency words",
            "severity": "Small",
            "points": 1
        })

    # ── Rule 10: Time pressure phrases (Severity: Small, Weight: +1) ────────
    # Phrases that impose a tight deadline to prevent victims from thinking clearly.
    _time_pressure = re.compile(
        r'(within\s+24\s+hours?|within\s+\d+\s+hours?|'
        r'expires?\s+(?:soon|today|in\s+\d+)|'
        r'\bimmediately\b|'
        r'(?:by\s+)?end\s+of\s+(?:day|business))',
        re.IGNORECASE
    )
    if _time_pressure.search(email_lower):
        total_score += 1
        triggered.append({
            "feature_name": "Time pressure",
            "severity": "Small",
            "points": 1
        })

    # ── Rule 11: Generic click-through phrases (Severity: Small, Weight: +1) ─
    # Vague calls-to-action with no visible destination are classic phishing bait.
    _generic_click = re.compile(
        r'(click\s+here|click\s+the\s+link|click\s+below|'
        r'follow\s+this\s+link|tap\s+here)',
        re.IGNORECASE
    )
    if _generic_click.search(email_lower):
        total_score += 1
        triggered.append({
            "feature_name": "Generic click",
            "severity": "Small",
            "points": 1
        })

    # ===================================================================
    # SECTION 3 – CLASSIFICATION
    # Threshold: total_score >= 9 → "Suspicious", else → "Safe"
    # Maximum possible score: 3+2+1+1+1+1 (URL) + 3+2+1+1+1 (Text) = 17
    # ===================================================================
    final_label = "Suspicious" if total_score >= 9 else "Safe"

    return {
        "final_label":        final_label,
        "total_score":        total_score,
        "triggered_features": triggered,
    }
