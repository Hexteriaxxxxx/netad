def detect_threats(username, ip, data, result, votes, user_agent='', csrf_failed=False):
    import datetime
    threats = []
    ua      = (user_agent or '').lower()
    granted = result == 'GRANTED'

    # Skip most threat checks on successful logins from known users — reduces noise
    # Still check SQL injection and attack tools even on success (paranoia is good)

    for field, val in [('username', data.get('_raw_username', username)), ('password', data.get('_raw_password', ''))]:
        v = val.lower()
        for p in _SQL_PATTERNS:
            if p in v:
                threats.append({'type': 'SQL_INJECTION', 'description': f'SQL injection in {field}: "{p}"', 'severity': 'CRITICAL', 'score': -0.9})
                break

    for agent in _ATTACK_AGENTS:
        if agent in ua:
            threats.append({'type': 'ATTACK_TOOL', 'description': f'Attack tool UA: {user_agent[:80]}', 'severity': 'HIGH', 'score': -0.8})
            break

    # === DENIED-only checks below ===
    if not granted:

        if username and username not in _get_valid_users():
            threats.append({'type': 'UNKNOWN_USERNAME', 'description': f'Unknown username: "{username}"', 'severity': 'MEDIUM', 'score': -0.5})

        if votes and votes[0] == 'FAIL':
            try:
                count = get_all_failed_count(ip)
                if count >= 5:
                    threats.append({'type': 'BRUTE_FORCE', 'description': f'Rate limit hit — {count} failed attempts from {mask_ip(ip)}', 'severity': 'HIGH', 'score': -0.85})
            except Exception: pass

        if csrf_failed:
            threats.append({'type': 'CSRF_BYPASS_ATTEMPT', 'description': f'Invalid/missing CSRF token from {mask_ip(ip)}', 'severity': 'HIGH', 'score': -0.75})

        if len(votes) >= 6 and votes[5] == 'FAIL':
            threats.append({'type': 'REPLAY_ATTACK', 'description': f'Token already consumed — replay attack from {mask_ip(ip)}', 'severity': 'HIGH', 'score': -0.8})

        # OFF_HOURS — log only, MEDIUM severity, never blocks on its own
        # Isolation Forest needs 50+ real logins before its estimates are reliable
        ph_hour = (datetime.datetime.utcnow().hour + 8) % 24
        if ph_hour >= 22 or ph_hour < 5:
            threats.append({'type': 'OFF_HOURS', 'description': f'Failed login at {ph_hour:02d}:00 PH — outside normal hours (5AM-10PM)', 'severity': 'MEDIUM', 'score': -0.3})

    # CREDENTIAL_LEAK — fires even on denied, because password being correct is the signal
    # But only when it's a known valid user (otherwise it's just a wrong-user attempt)
    if len(votes) >= 2 and votes[1] == 'PASS' and not granted:
        if username in _get_valid_users():
            threats.append({'type': 'CREDENTIAL_LEAK', 'description': f'Correct password but denied — password may be compromised for "{username}"', 'severity': 'CRITICAL', 'score': -0.95})

    return threats
