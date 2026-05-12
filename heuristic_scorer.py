import re
from urllib.parse import urlparse


class WeightedHeuristicScorer:
    """
    Weighted heuristic scoring for phishing email detection.
    Thresholds: score >= 4 → Suspicious, else → Safe

    NOTE: This scorer NEVER returns 'Confirmed Phishing'.
    'Confirmed Phishing' is reserved exclusively for PhishTank blacklist matches.

    Improvements:
    - All phrase matches are counted (not just first match), capped per category
    - Legitimate email indicators reduce the score (negative weights)
    - Additional URL-based rules (TLD, hyphen count, http, subdomain abuse)
    - Adjusted thresholds for better precision & recall
    """

    REWARD_PHRASES = [
        'congratulations', 'lucky winner', 'you have won', "you've won",
        'prize', 'reward', 'lottery', 'selected winner', 'unclaimed funds',
        'million dollar', 'inheritance', 'cash prize', 'gift card',
        'free offer', 'exclusive offer', 'claim your',
    ]

    THREAT_PHRASES = [
        'account will be', 'account suspended', 'account blocked',
        'account deleted', 'account terminated', 'legal action',
        'unauthorized access', 'suspicious activity detected',
        'account has been compromised', 'your account will be closed',
        'failure to comply', 'law enforcement', 'arrested',
    ]

    URGENCY_PHRASES = [
        'immediately', 'urgent', 'act now', 'action required',
        'expires', 'expiring', 'respond now', 'respond immediately',
        'final notice', 'last warning', 'limited time', 'do not delay',
        'asap', 'right away', 'without delay', 'time-sensitive',
    ]

    TIME_PRESSURE_PATTERNS = [
        r'within \d+ hours?', r'within \d+ days?', r'in \d+ hours?',
        r'24 hours?', r'48 hours?', r'before .{0,30} expires?',
        r'ends? today', r'last chance', r'deadline',
        r'expires? in \d+', r'only \d+ (hours?|minutes?) left',
    ]

    SENSITIVE_PHRASES = [
        'password', 'credit card', 'bank account', 'otp',
        'one-time password', 'pin number', 'cvv', 'ssn',
        'social security', 'banking details', 'login credentials',
        'mother\'s maiden name', 'date of birth', 'security question',
        'verify your identity', 'confirm your details',
    ]

    CLICK_PHRASES = [
        'click here', 'click the link', 'click below',
        'follow this link', 'tap here', 'open the link', 'visit this link',
        'access your account here', 'login here', 'sign in here',
    ]

    URL_SHORTENERS = [
        'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 't.co',
        'buff.ly', 'is.gd', 'rb.gy', 'cutt.ly', 'tiny.cc',
        'shorturl.at', 'clck.ru', 'su.pr', 'adf.ly',
    ]

    SUSPICIOUS_TLDS = [
        '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq',
        '.ru', '.cn', '.pw', '.top', '.club', '.info',
        '.biz', '.link', '.click', '.download', '.zip',
    ]

    # [B] Legitimate indicators — reduce score (negative weights)
    LEGITIMATE_INDICATORS = [
        ('unsubscribe', -2),
        ('privacy policy', -2),
        ('terms and conditions', -2),
        ('terms of service', -2),
        ('do not reply', -1),
        ('this is an automated', -1),
        ('sent from our office', -2),
        ('©', -1),
        ('all rights reserved', -1),
        ('contact us at', -1),
        ('if you did not request', -2),
        ('you are receiving this', -1),
    ]

    def score(self, email_text: str, urls: list) -> dict:
        text = email_text.lower()
        total = 0
        triggered = []

        # ── POSITIVE RULES ────────────────────────────────────────────────

        # Rule 1: Sensitive info request — count all matches, cap at 3, Big (+5 each)
        sensitive_matches = [p for p in self.SENSITIVE_PHRASES if p in text]
        if sensitive_matches:
            count = min(len(sensitive_matches), 3)
            pts = count * 5
            total += pts
            triggered.append({
                'feature_name': f'Sensitive Info Request ({count} match{"es" if count > 1 else ""}): '
                                + ', '.join(f'"{m}"' for m in sensitive_matches[:3]),
                'severity': 'Big',
                'points': pts,
            })

        # Rule 2: Reward / prize language — count all matches, cap at 2, Big (+4 each)
        reward_matches = [p for p in self.REWARD_PHRASES if p in text]
        if reward_matches:
            count = min(len(reward_matches), 2)
            pts = count * 4
            total += pts
            triggered.append({
                'feature_name': f'Reward or Prize Language ({count} match{"es" if count > 1 else ""}): '
                                + ', '.join(f'"{m}"' for m in reward_matches[:2]),
                'severity': 'Big',
                'points': pts,
            })

        # Rule 3: Threat language — count all matches, cap at 3, Medium (+3 each)
        threat_matches = [p for p in self.THREAT_PHRASES if p in text]
        if threat_matches:
            count = min(len(threat_matches), 3)
            pts = count * 3
            total += pts
            triggered.append({
                'feature_name': f'Threat Language ({count} match{"es" if count > 1 else ""}): '
                                + ', '.join(f'"{m}"' for m in threat_matches[:3]),
                'severity': 'Medium',
                'points': pts,
            })

        # Rule 4: Urgency words — count all matches, cap at 3, Medium (+2 each)
        urgency_matches = [p for p in self.URGENCY_PHRASES if p in text]
        if urgency_matches:
            count = min(len(urgency_matches), 3)
            pts = count * 2
            total += pts
            triggered.append({
                'feature_name': f'Urgency Language ({count} match{"es" if count > 1 else ""}): '
                                + ', '.join(f'"{m}"' for m in urgency_matches[:3]),
                'severity': 'Medium',
                'points': pts,
            })

        # Rule 5: Time pressure — count all patterns, cap at 2, Small (+1 each)
        time_matches = [p for p in self.TIME_PRESSURE_PATTERNS if re.search(p, text)]
        if time_matches:
            count = min(len(time_matches), 2)
            pts = count * 1
            total += pts
            triggered.append({
                'feature_name': f'Time Pressure Language ({count} pattern{"s" if count > 1 else ""})',
                'severity': 'Small',
                'points': pts,
            })

        # Rule 6: Generic click phrases — count all matches, cap at 2, Small (+1 each)
        click_matches = [p for p in self.CLICK_PHRASES if p in text]
        if click_matches:
            count = min(len(click_matches), 2)
            pts = count * 1
            total += pts
            triggered.append({
                'feature_name': f'Generic Click Phrase ({count} match{"es" if count > 1 else ""}): '
                                + ', '.join(f'"{m}"' for m in click_matches[:2]),
                'severity': 'Small',
                'points': pts,
            })

        # ── URL-BASED RULES ───────────────────────────────────────────────

        for url in urls:
            url_lower = url.lower()
            try:
                parsed = urlparse(url_lower)
                domain = parsed.netloc or ''
            except Exception:
                domain = ''

            # Rule 7: IP address in URL — Big (+4)
            if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url_lower):
                total += 4
                triggered.append({
                    'feature_name': 'IP Address in URL',
                    'severity': 'Big',
                    'points': 4,
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

            # [C] Rule 10: Insecure HTTP (not HTTPS) — Small (+1)
            if url_lower.startswith('http://'):
                total += 1
                triggered.append({
                    'feature_name': 'Insecure HTTP URL (not HTTPS)',
                    'severity': 'Small',
                    'points': 1,
                })

            # [C] Rule 11: Suspicious TLD — Medium (+2)
            for tld in self.SUSPICIOUS_TLDS:
                if domain.endswith(tld) or (tld + '/') in url_lower:
                    total += 2
                    triggered.append({
                        'feature_name': f'Suspicious TLD ({tld})',
                        'severity': 'Medium',
                        'points': 2,
                    })
                    break

            # [C] Rule 12: Too many hyphens in domain (e.g. secure-login-paypal-verify.com) — Medium (+2)
            hyphen_count = domain.split('/')[0].count('-')
            if hyphen_count >= 3:
                total += 2
                triggered.append({
                    'feature_name': f'Suspicious Domain with {hyphen_count} Hyphens',
                    'severity': 'Medium',
                    'points': 2,
                })
            elif hyphen_count == 2:
                total += 1
                triggered.append({
                    'feature_name': f'Domain with {hyphen_count} Hyphens',
                    'severity': 'Small',
                    'points': 1,
                })

            # [C] Rule 13: Brand name in subdomain abuse (e.g. paypal.evil.com) — Big (+3)
            BRAND_NAMES = ['paypal', 'amazon', 'google', 'microsoft', 'apple',
                           'facebook', 'netflix', 'ebay', 'instagram', 'whatsapp',
                           'maybank', 'cimb', 'rhb', 'bankrakyat', 'bnm']
            parts = domain.split('.')
            # If brand name appears in subdomain part (not the actual domain)
            if len(parts) > 2:
                subdomain_part = '.'.join(parts[:-2])
                for brand in BRAND_NAMES:
                    if brand in subdomain_part:
                        total += 3
                        triggered.append({
                            'feature_name': f'Brand Name "{brand}" Spoofed in Subdomain',
                            'severity': 'Big',
                            'points': 3,
                        })
                        break

        # ── NEGATIVE RULES (Legitimate Indicators) ───────────────────────

        # [B] Subtract points for signs of legitimate email
        for phrase, penalty in self.LEGITIMATE_INDICATORS:
            if phrase in text:
                total += penalty  # penalty is already negative
                triggered.append({
                    'feature_name': f'Legitimate Indicator: "{phrase}"',
                    'severity': 'Negative',
                    'points': penalty,
                })

        # ── FINAL SCORING ─────────────────────────────────────────────────

        # Ensure score doesn't go below 0 or above 15
        total = max(0, min(total, 15))

        # This scorer only returns 'Suspicious' or 'Safe'.
        # 'Confirmed Phishing' is exclusively assigned when PhishTank blacklist matches.
        if total >= 4:
            label = 'Suspicious'
        else:
            label = 'Safe'

        return {
            'score': total,
            'max_score': 15,
            'label': label,
            'triggered_features': triggered,
        }
