import re
from urllib.parse import urlparse


class WeightedHeuristicScorer:
    """
    Priority-based heuristic scoring for phishing email detection.
    Evaluates 13 text-based and URL-based rules.
    Each rule triggers at most once.

    Severity to Priority Values:
    - Big = 4
    - Medium = 2
    - Small = 1

    Threshold:
    - score >= 4 -> Suspicious
    - score < 4 -> Low Risk

    NOTE: This scorer NEVER returns 'Confirmed Phishing'.
    'Confirmed Phishing' is reserved exclusively for PhishTank blacklist matches.
    """

    # --- Rule 1 to 6 Phrases ---
    SENSITIVE_PHRASES = [
        'password', 'credit card', 'bank account', 'otp', 'pin', 'cvv',
        'login credentials', 'identity verification', 'private information'
    ]

    REWARD_PHRASES = [
        'congratulations', 'lucky winner', 'prize', 'reward', 'lottery',
        'gift card', 'free offer', 'claim your'
    ]

    THREAT_PHRASES = [
        'account suspended', 'account blocked', 'legal action',
        'suspicious activity detected', 'account compromised', 'account closed'
    ]

    URGENCY_PHRASES = [
        'urgent', 'act now', 'action required', 'final notice',
        'last warning', 'limited time', 'do not delay'
    ]

    TIME_PRESSURE_PHRASES = [
        'within 24 hours', '48 hours', 'last chance', 'deadline',
        'ends today', 'only a few hours left'
    ]

    CLICK_PHRASES = [
        'click here', 'click the link', 'click below', 'tap here',
        'login here', 'sign in here'
    ]

    # --- URL Rules Config ---
    URL_SHORTENERS = [
        'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 't.co', 'rb.gy', 'cutt.ly', 'shorturl.at'
    ]

    SUSPICIOUS_TLDS = [
        '.xyz', '.tk', '.ru', '.cn', '.top', '.club', '.info', '.biz', '.click', '.download', '.zip', '.id'
    ]

    def score(self, email_text: str, urls: list) -> dict:
        text = email_text.lower()
        total = 0
        triggered = []

        # ── TEXT-BASED RULES ──────────────────────────────────────────────

        # Rule 1: Sensitive Information Request (Big = 4)
        if any(p in text for p in self.SENSITIVE_PHRASES):
            total += 4
            triggered.append({
                'feature_name': 'Sensitive Information Request',
                'severity': 'Big',
                'priority_value': 4
            })

        # Rule 2: Reward or Prize Language (Medium = 2)
        if any(p in text for p in self.REWARD_PHRASES):
            total += 2
            triggered.append({
                'feature_name': 'Reward or Prize Language',
                'severity': 'Medium',
                'priority_value': 2
            })

        # Rule 3: Threat Language (Medium = 2)
        if any(p in text for p in self.THREAT_PHRASES):
            total += 2
            triggered.append({
                'feature_name': 'Threat Language',
                'severity': 'Medium',
                'priority_value': 2
            })

        # Rule 4: Urgency Language (Medium = 2)
        if any(p in text for p in self.URGENCY_PHRASES):
            total += 2
            triggered.append({
                'feature_name': 'Urgency Language',
                'severity': 'Medium',
                'priority_value': 2
            })

        # Rule 5: Time Pressure Language (Small = 1)
        if any(p in text for p in self.TIME_PRESSURE_PHRASES):
            total += 1
            triggered.append({
                'feature_name': 'Time Pressure Language',
                'severity': 'Small',
                'priority_value': 1
            })

        # Rule 6: Generic Click Phrase (Small = 1)
        if any(p in text for p in self.CLICK_PHRASES):
            total += 1
            triggered.append({
                'feature_name': 'Generic Click Phrase',
                'severity': 'Small',
                'priority_value': 1
            })

        # ── URL-BASED RULES ───────────────────────────────────────────────

        # Pre-process domains and URL traits
        has_ip_rule = False
        has_shortener_rule = False
        has_suspicious_tld_rule = False
        has_many_hyphens_rule = False
        has_excessive_hyphens_rule = False
        has_long_url_rule = False
        has_insecure_http_rule = False

        for url in urls:
            url_lower = url.lower()
            try:
                parsed = urlparse(url_lower)
                domain = parsed.netloc or ''
            except Exception:
                domain = ''

            # Rule 7: IP Address in URL (Big = 4)
            if not has_ip_rule and re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
                has_ip_rule = True

            # Rule 8: URL Shortener (Medium = 2)
            if not has_shortener_rule and any(shortener in url_lower for shortener in self.URL_SHORTENERS):
                has_shortener_rule = True

            # Rule 9: Suspicious TLD (Medium = 2)
            if not has_suspicious_tld_rule and any(domain.endswith(tld) or (tld + '/') in url_lower for tld in self.SUSPICIOUS_TLDS):
                has_suspicious_tld_rule = True

            # Rule 10 & 11: Hyphen rules
            hyphen_count = domain.split('/')[0].count('-')
            if hyphen_count == 2:
                has_many_hyphens_rule = True
            elif hyphen_count >= 3:
                has_excessive_hyphens_rule = True

            # Rule 12: Suspiciously Long URL (Small = 1)
            if not has_long_url_rule and len(url) > 75:
                has_long_url_rule = True

            # Rule 13: Insecure HTTP URL (Small = 1)
            if not has_insecure_http_rule and url_lower.startswith('http://'):
                has_insecure_http_rule = True

        # Append triggered URL features and add to total score
        if has_ip_rule:
            total += 4
            triggered.append({
                'feature_name': 'IP Address in URL',
                'severity': 'Big',
                'priority_value': 4
            })

        if has_shortener_rule:
            total += 2
            triggered.append({
                'feature_name': 'URL Shortener',
                'severity': 'Medium',
                'priority_value': 2
            })

        if has_suspicious_tld_rule:
            total += 2
            triggered.append({
                'feature_name': 'Suspicious TLD',
                'severity': 'Medium',
                'priority_value': 2
            })

        if has_many_hyphens_rule:
            total += 1
            triggered.append({
                'feature_name': 'Domain with Many Hyphens',
                'severity': 'Small',
                'priority_value': 1
            })

        if has_excessive_hyphens_rule:
            total += 2
            triggered.append({
                'feature_name': 'Domain with Excessive Hyphens',
                'severity': 'Medium',
                'priority_value': 2
            })

        if has_long_url_rule:
            total += 1
            triggered.append({
                'feature_name': 'Suspiciously Long URL',
                'severity': 'Small',
                'priority_value': 1
            })

        if has_insecure_http_rule:
            total += 1
            triggered.append({
                'feature_name': 'Insecure HTTP URL',
                'severity': 'Small',
                'priority_value': 1
            })

        # ── FINAL SCORING ─────────────────────────────────────────────────

        total = max(0, total)

        if total >= 4:
            label = 'Suspicious'
        else:
            label = 'Low Risk'

        return {
            'score': total,
            'label': label,
            'triggered_features': triggered,
        }
