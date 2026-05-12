import re


class WeightedHeuristicScorer:
    """
    Weighted heuristic scoring for phishing email detection.
    Thresholds: score >= 10 → Confirmed Phishing, >= 5 → Suspicious, else → Safe
    """

    REWARD_PHRASES = [
        'congratulations', 'lucky winner', 'you have won', "you've won",
        'prize', 'reward', 'lottery', 'selected winner', 'unclaimed funds',
        'million dollar', 'inheritance',
    ]

    THREAT_PHRASES = [
        'account will be', 'account suspended', 'account blocked',
        'account deleted', 'account terminated', 'legal action',
        'unauthorized access', 'suspicious activity detected',
    ]

    URGENCY_PHRASES = [
        'immediately', 'urgent', 'act now', 'action required',
        'expires', 'expiring', 'respond now', 'respond immediately',
        'final notice', 'last warning', 'limited time', 'do not delay',
    ]

    TIME_PRESSURE_PATTERNS = [
        r'within \d+ hours?', r'within \d+ days?', r'in \d+ hours?',
        r'24 hours?', r'48 hours?', r'before .{0,30} expires?',
        r'ends? today', r'last chance', r'deadline',
    ]

    SENSITIVE_PHRASES = [
        'password', 'credit card', 'bank account', 'otp',
        'one-time password', 'pin number', 'cvv', 'ssn',
        'social security', 'banking details', 'login credentials',
    ]

    CLICK_PHRASES = [
        'click here', 'click the link', 'click below',
        'follow this link', 'tap here', 'open the link', 'visit this link',
    ]

    URL_SHORTENERS = [
        'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 't.co',
        'buff.ly', 'is.gd', 'rb.gy', 'cutt.ly', 'tiny.cc',
    ]

    def score(self, email_text: str, urls: list) -> dict:
        text = email_text.lower()
        total = 0
        triggered = []

        # Rule 1: Sensitive info request — Big (+5)
        for phrase in self.SENSITIVE_PHRASES:
            if phrase in text:
                total += 5
                triggered.append({
                    'feature_name': f'Sensitive Info Request: "{phrase}"',
                    'severity': 'Big',
                    'points': 5,
                })
                break

        # Rule 2: Reward / prize language — Big (+4)
        for phrase in self.REWARD_PHRASES:
            if phrase in text:
                total += 4
                triggered.append({
                    'feature_name': 'Reward or Prize Language',
                    'severity': 'Big',
                    'points': 4,
                })
                break

        # Rule 3: Threat language — Medium (+3)
        for phrase in self.THREAT_PHRASES:
            if phrase in text:
                total += 3
                triggered.append({
                    'feature_name': 'Threat Language Detected',
                    'severity': 'Medium',
                    'points': 3,
                })
                break

        # Rule 4: Urgency words — Medium (+2)
        for phrase in self.URGENCY_PHRASES:
            if phrase in text:
                total += 2
                triggered.append({
                    'feature_name': f'Urgency Language: "{phrase}"',
                    'severity': 'Medium',
                    'points': 2,
                })
                break

        # Rule 5: Time pressure — Small (+1)
        for pattern in self.TIME_PRESSURE_PATTERNS:
            if re.search(pattern, text):
                total += 1
                triggered.append({
                    'feature_name': 'Time Pressure Language',
                    'severity': 'Small',
                    'points': 1,
                })
                break

        # Rule 6: Generic click phrases — Small (+1)
        for phrase in self.CLICK_PHRASES:
            if phrase in text:
                total += 1
                triggered.append({
                    'feature_name': f'Generic Click Phrase: "{phrase}"',
                    'severity': 'Small',
                    'points': 1,
                })
                break

        # URL-based rules
        for url in urls:
            url_lower = url.lower()

            # Rule 7: IP address in URL — Big (+3)
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
                total += 3
                triggered.append({
                    'feature_name': 'IP Address in URL',
                    'severity': 'Big',
                    'points': 3,
                })

            # Rule 8: URL shortener — Medium (+2)
            for shortener in self.URL_SHORTENERS:
                if shortener in url_lower:
                    total += 2
                    triggered.append({
                        'feature_name': f'URL Shortener ({shortener})',
                        'severity': 'Medium',
                        'points': 2,
                    })
                    break

            # Rule 9: Very long URL — Small (+1)
            if len(url) > 75:
                total += 1
                triggered.append({
                    'feature_name': 'Suspiciously Long URL (>75 chars)',
                    'severity': 'Small',
                    'points': 1,
                })

        # Cap at 15
        total = min(total, 15)

        if total >= 10:
            label = 'Confirmed Phishing'
        elif total >= 5:
            label = 'Suspicious'
        else:
            label = 'Safe'

        return {
            'score': total,
            'max_score': 15,
            'label': label,
            'triggered_features': triggered,
        }
