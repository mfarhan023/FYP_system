import re


class WeightedHeuristicScorer:
    """
    Applies weighted heuristic rules to determine if email content is phishing.
    Thresholds: score >= 12 → Confirmed Phishing, score >= 6 → Suspicious, else → Safe
    """

    URGENCY_WORDS = [
        'urgent', 'immediately', 'expire', 'expires', 'expiring', 'act now',
        'action required', 'verify', 'verify now', 'confirm', 'suspended',
        'deactivated', 'blocked', 'limited', 'restricted', 'update your',
        'update now', 'respond immediately', 'failure to', 'final notice',
        'last warning', 'warning', 'alert', 'attention', 'important notice'
    ]

    TIME_PRESSURE = [
        r'within \d+ hour', r'within \d+ day', r'in \d+ hour', r'in \d+ day',
        r'\d+ hours?', r'24 hours?', r'48 hours?', r'72 hours?', r'before .{0,20} expires?',
        r'deadline', r'by \w+ \d+', r'ends? today', r'last chance'
    ]

    SENSITIVE_WORDS = [
        'password', 'passwd', 'login credential', 'otp', 'one-time password',
        'pin', 'social security', 'ssn', 'bank account', 'credit card',
        'debit card', 'card number', 'cvv', 'banking credential', 'banking detail',
        'banking information', 'username and password', 'mother\'s maiden', 'secret question'
    ]

    THREAT_REWARD_WORDS = [
        'your account will be', 'account will be closed', 'account will be deleted',
        'account will be terminated', 'account will be suspended', 'will be deleted',
        'will be terminated', 'legal action', 'law enforcement', 'prosecuted',
        'congratulations', 'you have won', 'you\'ve won', 'prize', 'reward', 'lottery',
        'million dollar', 'inheritance', 'unclaimed', 'lucky winner', 'selected'
    ]

    GENERIC_CLICK = [
        'click here', 'click below', 'click the link', 'click this link',
        'tap here', 'follow this link', 'use this link', 'access the link',
        'open the link', 'visit the link'
    ]

    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 't.co', 'is.gd',
        'buff.ly', 'adf.ly', 'shorte.st', 'mcaf.ee', 'rb.gy', 'cutt.ly',
        'shorturl.at', 'tiny.cc', 'clck.ru', 'bit.do', 'su.pr'
    ]

    LEGITIMATE_DOMAINS = [
        'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
        'twitter.com', 'linkedin.com', 'github.com', 'youtube.com', 'instagram.com',
        'maybank.com', 'cimb.com', 'publicbank.com', 'rhbbank.com', 'hongleongbank.com',
        'bankislam.com', 'ambank.com', 'affinbank.com', 'bankrakyat.com',
        'paypal.com', 'dropbox.com', 'adobe.com', 'salesforce.com', 'zoom.us',
        'netflix.com', 'spotify.com', 'slack.com', 'notion.so', 'atlassian.com'
    ]

    def __init__(self):
        self.max_score = 15

    def score(self, email_text: str, urls: list) -> dict:
        """
        Score the email content and return result dict.
        """
        text_lower = email_text.lower()
        triggered = []
        total_score = 0
        has_legitimate_domain = False

        # --- URL-based rules ---
        for url in urls:
            url_lower = url.lower()

            # Check if URL uses a legitimate domain (reduces suspicion)
            for legit in self.LEGITIMATE_DOMAINS:
                if legit in url_lower:
                    has_legitimate_domain = True

            # Rule 1: IP address in URL (Big: +3)
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
                total_score += 3
                triggered.append({
                    'feature': 'IP Address in URL',
                    'severity': 'BIG',
                    'weight': 3
                })

            # Rule 2: URL shortener (Big: +3)
            for shortener in self.URL_SHORTENERS:
                if shortener in url_lower:
                    total_score += 3
                    triggered.append({
                        'feature': f'URL Shortener Detected ({shortener})',
                        'severity': 'BIG',
                        'weight': 3
                    })
                    break

            # Rule 3: Many subdomains (Medium: +2)
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url_lower)
                host = parsed.netloc
                parts = host.split('.')
                if len(parts) > 3:
                    total_score += 2
                    triggered.append({
                        'feature': 'Excessive Subdomains in URL',
                        'severity': 'MEDIUM',
                        'weight': 2
                    })
            except Exception:
                pass

            # Rule 4: Very long URL (Small: +1)
            if len(url) > 75:
                total_score += 1
                triggered.append({
                    'feature': 'Suspiciously Long URL (>75 chars)',
                    'severity': 'SMALL',
                    'weight': 1
                })

            # Rule 5: Obfuscation (@, //, %xx) (Small: +1)
            if '@' in url or '//' in url[7:] or re.search(r'%[0-9a-fA-F]{2}', url):
                total_score += 1
                triggered.append({
                    'feature': 'URL Obfuscation (@, double-slash, %xx)',
                    'severity': 'SMALL',
                    'weight': 1
                })

            # Rule 6: HTTP on login/banking path (Small: +1)
            if url_lower.startswith('http://') and re.search(
                r'(login|signin|banking|account|secure|verify|update|confirm)', url_lower
            ):
                total_score += 1
                triggered.append({
                    'feature': 'HTTP (Insecure) on Sensitive Path',
                    'severity': 'SMALL',
                    'weight': 1
                })

            # Rule 7: Suspicious URL structure - combosquatting (Medium: +2)
            if re.search(
                r'(paypal|amazon|google|microsoft|apple|ebay|netflix|bank|secure)'
                r'[-.]?(account|login|secure|update|verify|confirm)',
                url_lower
            ):
                if not has_legitimate_domain:
                    total_score += 2
                    triggered.append({
                        'feature': 'Suspicious URL Structure (Combosquatting)',
                        'severity': 'MEDIUM',
                        'weight': 2
                    })

        # --- Text-based rules ---

        # Rule 8: Sensitive credential request (Big: +3)
        for word in self.SENSITIVE_WORDS:
            if word in text_lower:
                total_score += 3
                triggered.append({
                    'feature': f'Direct Request for Sensitive Credentials ({word.title()})',
                    'severity': 'BIG',
                    'weight': 3
                })
                break  # only score once

        # Rule 9: Threat or reward language (Medium: +2)
        for phrase in self.THREAT_REWARD_WORDS:
            if phrase in text_lower:
                total_score += 2
                triggered.append({
                    'feature': 'Threat or Reward Language Detected',
                    'severity': 'MEDIUM',
                    'weight': 2
                })
                break

        # Rule 10: Urgency words (Small: +1)
        for word in self.URGENCY_WORDS:
            if word in text_lower:
                total_score += 1
                triggered.append({
                    'feature': f'Urgency Language ("{word}")',
                    'severity': 'SMALL',
                    'weight': 1
                })
                break

        # Rule 11: Time pressure (Small: +1)
        for pattern in self.TIME_PRESSURE:
            if re.search(pattern, text_lower):
                total_score += 1
                triggered.append({
                    'feature': 'Time Pressure Language',
                    'severity': 'SMALL',
                    'weight': 1
                })
                break

        # Rule 12: Generic click phrases (Small: +1)
        for phrase in self.GENERIC_CLICK:
            if phrase in text_lower:
                total_score += 1
                triggered.append({
                    'feature': f'Generic Click Phrase ("{phrase.title()}")',
                    'severity': 'SMALL',
                    'weight': 1
                })
                break

        # Rule 13: Generic greeting (Small: +1)
        if re.search(r'\b(dear (customer|user|account holder|member|sir|madam|valued))\b', text_lower):
            total_score += 1
            triggered.append({
                'feature': 'Generic Greeting (Dear Customer/User)',
                'severity': 'SMALL',
                'weight': 1
            })

        # Legitimate domain reduces impact slightly
        if has_legitimate_domain and total_score > 0:
            triggered.insert(0, {
                'feature': 'Legitimate Domain Detected',
                'severity': 'BIG',
                'weight': 0
            })

        # Cap score
        total_score = min(total_score, self.max_score)

        # Determine label
        if total_score >= 12:
            label = 'Confirmed Phishing'
        elif total_score >= 6:
            label = 'Suspicious'
        else:
            label = 'Safe'

        return {
            'score': total_score,
            'max_score': self.max_score,
            'label': label,
            'triggered_features': triggered
        }
