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

    def _find_trigger_evidence(self, email_text: str, phrases: list) -> list:
        """Find sentences in email_text containing any of the matched phrases."""
        lines = email_text.split('\n')
        sentences = []
        for line in lines:
            # Split sentences by punctuation followed by space or end of string
            parts = re.split(r'(?<=[.!?])\s+', line)
            for part in parts:
                p_strip = part.strip()
                if p_strip:
                    sentences.append(p_strip)

        evidences = []
        for phrase in phrases:
            phrase_lower = phrase.lower()
            for sentence in sentences:
                if phrase_lower in sentence.lower():
                    if sentence not in evidences:
                        evidences.append(sentence)
        return evidences

    def score(self, email_text: str, urls: list) -> dict:
        text = email_text.lower()
        total = 0
        triggered = []

        # ── TEXT-BASED RULES ──────────────────────────────────────────────

        # Rule 1: Sensitive Information Request (Big = 4)
        matched_sensitive = [p for p in self.SENSITIVE_PHRASES if p in text]
        if matched_sensitive:
            total += 4
            triggered.append({
                'feature_name': 'Sensitive Information Request',
                'severity': 'Big',
                'priority_value': 4,
                'evidence': self._find_trigger_evidence(email_text, matched_sensitive)
            })

        # Rule 2: Reward or Prize Language (Medium = 2)
        matched_reward = [p for p in self.REWARD_PHRASES if p in text]
        if matched_reward:
            total += 2
            triggered.append({
                'feature_name': 'Reward or Prize Language',
                'severity': 'Medium',
                'priority_value': 2,
                'evidence': self._find_trigger_evidence(email_text, matched_reward)
            })

        # Rule 3: Threat Language (Medium = 2)
        matched_threat = [p for p in self.THREAT_PHRASES if p in text]
        if matched_threat:
            total += 2
            triggered.append({
                'feature_name': 'Threat Language',
                'severity': 'Medium',
                'priority_value': 2,
                'evidence': self._find_trigger_evidence(email_text, matched_threat)
            })

        # Rule 4: Urgency Language (Medium = 2)
        matched_urgency = [p for p in self.URGENCY_PHRASES if p in text]
        if matched_urgency:
            total += 2
            triggered.append({
                'feature_name': 'Urgency Language',
                'severity': 'Medium',
                'priority_value': 2,
                'evidence': self._find_trigger_evidence(email_text, matched_urgency)
            })

        # Rule 5: Time Pressure Language (Small = 1)
        matched_time = [p for p in self.TIME_PRESSURE_PHRASES if p in text]
        if matched_time:
            total += 1
            triggered.append({
                'feature_name': 'Time Pressure Language',
                'severity': 'Small',
                'priority_value': 1,
                'evidence': self._find_trigger_evidence(email_text, matched_time)
            })

        # Rule 6: Generic Click Phrase (Small = 1)
        matched_click = [p for p in self.CLICK_PHRASES if p in text]
        if matched_click:
            total += 1
            triggered.append({
                'feature_name': 'Generic Click Phrase',
                'severity': 'Small',
                'priority_value': 1,
                'evidence': self._find_trigger_evidence(email_text, matched_click)
            })

        # ── URL-BASED RULES ───────────────────────────────────────────────

        # Pre-process domains and URL traits
        triggered_ips = []
        triggered_shorteners = []
        triggered_suspicious_tlds = []
        triggered_many_hyphens = []
        triggered_excessive_hyphens = []
        triggered_long_urls = []
        triggered_insecure_http = []

        for url in urls:
            url_lower = url.lower()
            try:
                parsed = urlparse(url_lower)
                domain = parsed.netloc or ''
            except Exception:
                domain = ''

            # Rule 7: IP Address in URL (Big = 4)
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
                triggered_ips.append(url)

            # Rule 8: URL Shortener (Medium = 2)
            if any(shortener in url_lower for shortener in self.URL_SHORTENERS):
                triggered_shorteners.append(url)

            # Rule 9: Suspicious TLD (Medium = 2)
            if any(domain.endswith(tld) or (tld + '/') in url_lower for tld in self.SUSPICIOUS_TLDS):
                triggered_suspicious_tlds.append(url)

            # Rule 10 & 11: Hyphen rules
            hyphen_count = domain.split('/')[0].count('-')
            if hyphen_count == 2:
                triggered_many_hyphens.append(url)
            elif hyphen_count >= 3:
                triggered_excessive_hyphens.append(url)

            # Rule 12: Suspiciously Long URL (Small = 1)
            if len(url) > 75:
                triggered_long_urls.append(url)

            # Rule 13: Insecure HTTP URL (Small = 1)
            if url_lower.startswith('http://'):
                triggered_insecure_http.append(url)

        # Append triggered URL features and add to total score
        if triggered_ips:
            total += 4
            triggered.append({
                'feature_name': 'IP Address in URL',
                'severity': 'Big',
                'priority_value': 4,
                'evidence': triggered_ips
            })

        if triggered_shorteners:
            total += 2
            triggered.append({
                'feature_name': 'URL Shortener',
                'severity': 'Medium',
                'priority_value': 2,
                'evidence': triggered_shorteners
            })

        if triggered_suspicious_tlds:
            total += 2
            triggered.append({
                'feature_name': 'Suspicious TLD',
                'severity': 'Medium',
                'priority_value': 2,
                'evidence': triggered_suspicious_tlds
            })

        if triggered_many_hyphens:
            total += 1
            triggered.append({
                'feature_name': 'Domain with Many Hyphens',
                'severity': 'Small',
                'priority_value': 1,
                'evidence': triggered_many_hyphens
            })

        if triggered_excessive_hyphens:
            total += 2
            triggered.append({
                'feature_name': 'Domain with Excessive Hyphens',
                'severity': 'Medium',
                'priority_value': 2,
                'evidence': triggered_excessive_hyphens
            })

        if triggered_long_urls:
            total += 1
            triggered.append({
                'feature_name': 'Suspiciously Long URL',
                'severity': 'Small',
                'priority_value': 1,
                'evidence': triggered_long_urls
            })

        if triggered_insecure_http:
            total += 1
            triggered.append({
                'feature_name': 'Insecure HTTP URL',
                'severity': 'Small',
                'priority_value': 1,
                'evidence': triggered_insecure_http
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
