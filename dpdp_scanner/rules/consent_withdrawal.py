"""
Rule: CONSENT_WITHDRAWAL_MISSING / CONSENT_WITHDRAWAL_PRESENT
DPDP Section 6(6) — Every consent given shall be as easy to withdraw as it was to give.

Logic:
  Only fires when positive consent signals exist in the repo.
  If consent is collected but no withdrawal mechanism exists → HIGH violation.
  If no consent signals at all → skip (consent rule handles that separately).

Withdrawal signals: endpoint or function that deletes/revokes/updates a consent record.
"""

import re


# ── Withdrawal endpoint patterns ───────────────────────────────────────────
# Routes and functions that revoke or withdraw consent
WITHDRAWAL_ROUTE_PATTERNS = [
    # REST route patterns
    r'/consent\b.*(?:delete|revoke|withdraw|remove)',
    r'/privacy\b.*(?:delete|revoke|withdraw|remove)',
    r'/gdpr\b.*(?:delete|revoke|withdraw)',
    r'/dpdp\b.*(?:delete|revoke|withdraw)',
    r'/unsubscribe\b',
    r'/opt[-_]out\b',
    r'/withdraw[-_]consent\b',
    r'/revoke[-_]consent\b',
    r'/delete[-_]consent\b',
    r'/privacy[-_]settings\b',
    r'/data[-_]preferences\b',

    # HTTP method + consent path combinations
    r'(?:DELETE|PATCH|PUT)\s+[\'"/].*consent',
    r'(?:delete|patch|put)\s*\(\s*[\'"].*consent',

    # Function/method names
    r'def\s+withdraw_consent\b',
    r'def\s+revoke_consent\b',
    r'def\s+delete_consent\b',
    r'def\s+update_consent\b',
    r'def\s+opt_out\b',
    r'def\s+unsubscribe\b',
    r'withdrawConsent\s*[(\{]',
    r'revokeConsent\s*[(\{]',
    r'deleteConsent\s*[(\{]',
    r'updateConsent\s*[(\{]',
    r'optOut\s*[(\{]',

    # DB operations on consent records
    r'(?:DELETE|UPDATE)\s+.*consent',
    r'consent.*(?:\.delete|\.destroy|\.remove|\.update)\s*\(',
    r'consent_given\s*=\s*(?:False|false|0|null|None)',
    r'is_agreed\s*=\s*(?:False|false|0|null|None)',
    r'opted_in\s*=\s*(?:False|false|0|null|None)',
    r'terms_accepted\s*=\s*(?:False|false|0|null|None)',

    # Framework-specific
    # Django
    r'ConsentRecord\.objects\.(?:delete|update|filter.*delete)',
    # Rails
    r'consent\.destroy\b',
    r'before_action.*:revoke',
    # Express
    r'router\.delete\s*\(\s*[\'"].*consent',
    r'app\.delete\s*\(\s*[\'"].*consent',
    # Spring
    r'@DeleteMapping.*consent',
    r'@PatchMapping.*consent',
    # Laravel
    r'Route::delete.*consent',
    r'Route::patch.*consent',
]

# Exclude file/resource deletion and storage APIs mistaken for consent withdrawal
WITHDRAWAL_FALSE_POSITIVE_PATTERNS = [
    r"/delete[_\-]?file",
    r"/delete[_\-]?post",
    r"/delete[_\-]?message",
    r"/delete[_\-]?comment",
    r"/delete[_\-]?item",
    r"/delete[_\-]?record",
    r"/remove[_\-]?file",
    r"delete.*file.*storage",
    r"storage.*delete",
    r"bucket.*delete",
    r"\.delete\s*\(.*path",
    r"\.remove\s*\(.*file",
    r"unlink\s*\(",
    r"os\.remove\s*\(",
    r"fs\.unlink\s*\(",
    # Bare resource/file delete — not consent withdrawal
    r"(?:@app\.|@bp\.|app\.)(?:route|get)\s*\(\s*['\"]/delete\b",
    r"\.get\s*\(\s*['\"]/delete\b",
    r"['\"]/delete\b['\"]\s*,\s*methods\s*=\s*\[\s*['\"]GET['\"]",
]

WITHDRAWAL_ROUTE_PATTERNS += [
    r"CookieConsent\b",
    r"ConsentManager\b",
    r"useConsent\b",
    r"ConsentContext\b",
    r"ConsentProvider\b",
    r"gdpr\b",
    r"cookieconsent\b",
    r"react-cookie-consent\b",
    r"@consent-manager",
    r"dpdp.*withdraw",
    r"withdraw.*dpdp",
    r"data.*principal.*withdraw",
    r"revoke.*data.*consent",
    r"delete.*account",
    r"account.*delete",
    r"deactivate.*account",
    r"account.*deactivat",
    r"close.*account",
    r"unsubscribe\b",
    r"opt[_\-]out\b",
    r"manage[_\-]preferences",
    r"communication[_\-]preferences",
    r"notification[_\-]preferences",
    r"email[_\-]preferences",
    r"withdraw[_\-]consent.*button",
    r"revoke[_\-]consent.*click",
    r"<WithdrawConsent",
    r"<ConsentToggle",
    r"<ManageConsent",
    r"DELETE.*\/consents?\b",
    r"DELETE.*\/subscriptions?\b",
    r"PATCH.*consent.*false",
    r"PUT.*consent.*revoked",
    r"revoke_consent.*task\b",
    r"consent_withdrawal.*job\b",
    r"process.*withdrawal\b",
]

PRIVACY_SETTINGS_PATTERNS = [
    r"/privacy[_\-]?settings\b",
    r"/cookie[_\-]?settings\b",
    r"/data[_\-]?preferences\b",
    r"/account[_\-]?settings\b",
    r"/notification[_\-]?settings\b",
    r"PrivacySettings\b",
    r"CookieSettings\b",
    r"DataPreferences\b",
]


# ── Consent collection patterns ────────────────────────────────────────────
# Reuse a tighter version to confirm consent IS being collected
# (so we only flag withdrawal absence when consent collection exists)
CONSENT_COLLECTION_PATTERNS = [
    r'consent_given\s*[=:]',
    r'consent_timestamp\s*[=:]',
    r'is_agreed\s*[=:]',
    r'opted_in\s*=\s*(?:True|true|1)',
    r'terms_accepted\s*[=:]',
    r'record_consent\s*\(',
    r'save_consent\s*\(',
    r'grant_consent\s*\(',
    r'ConsentService\.',
    r'INSERT.*consent',
    r'consentGiven\s*[=:]',
    r'ConsentMiddleware',
    r'@consent_required',
    r'\[RequireConsent\]',
    r"supabase\.auth\.sign_up",
    r"supabase\.auth\.signUp",
    r"auth\.create_user",
    r"createUserWithEmail",
    r"register\s*\(",
    r"signup\s*\(",
    r"/signup",
    r"/register",
]


def _search_files(file_contents: dict, patterns: list) -> list:
    """
    Search all files for any matching pattern.
    Returns list of {file, line_number, matched_text} dicts.
    """
    results = []
    for path, content in file_contents.items():
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(('#', '//', '*', '<!--')):
                continue
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    results.append({
                        'file':       path,
                        'line_number': i,
                        'matched_text': stripped[:120],
                        'pattern':    pattern,
                    })
                    break  # one match per line
    return results


def run(extracted: dict) -> list:
    findings = []
    file_contents = extracted.get('_file_contents', {})

    # Consent withdrawal applies to deployed products, not framework/library source trees.
    if extracted.get("is_framework_library"):
        return findings

    # ── Prerequisite: consent must actually be collected ───────────
    # If there are no consent collection signals, this rule is out of scope.
    # The consent.py rule already handles the "no consent at all" case.
    consent_collection = _search_files(file_contents, CONSENT_COLLECTION_PATTERNS)
    if not consent_collection:
        return findings  # nothing to check — consent rule covers this

    # ── Check for withdrawal mechanism ─────────────────────────────
    withdrawal_signals = _search_files(file_contents, WITHDRAWAL_ROUTE_PATTERNS)
    withdrawal_signals = [
        s
        for s in withdrawal_signals
        if not any(
            re.search(
                p,
                (s.get("matched_text") or "") + " " + (s.get("file") or ""),
                re.IGNORECASE,
            )
            for p in WITHDRAWAL_FALSE_POSITIVE_PATTERNS
        )
    ]
    privacy_settings = _search_files(file_contents, PRIVACY_SETTINGS_PATTERNS)

    if not withdrawal_signals:
        if privacy_settings:
            findings.append({
                'rule':        'CONSENT_WITHDRAWAL_PARTIAL',
                'dpdp_section': 'Section 6(6) — Consent Withdrawal',
                'severity':    'MEDIUM',
                'confidence':  0.65,
                'file':        privacy_settings[0]['file'],
                'display_path': privacy_settings[0]['file'],
                'line_number': privacy_settings[0]['line_number'],
                'description': (
                    'Consent is collected and privacy/notification settings page detected, '
                    'but no explicit consent withdrawal mechanism found. '
                    'DPDP Section 6(6) requires withdrawal to be as easy as giving consent. '
                    "A settings page is insufficient — implement explicit 'Withdraw Consent' "
                    'functionality with immediate effect.'
                ),
                'evidence': {
                    'privacy_settings_found': [
                        {'file': s['file'], 'line': s['line_number'], 'text': s['matched_text']}
                        for s in privacy_settings[:3]
                    ],
                },
                'fix': None,
                'requires_human_validation': True,
            })
            return findings

        # Consent collected but no withdrawal mechanism found — DPDP 6(6) violation
        collection_sample = consent_collection[:3]
        findings.append({
            'rule':        'CONSENT_WITHDRAWAL_MISSING',
            'dpdp_section': 'Section 6(6) — Consent Withdrawal',
            'severity':    'HIGH',
            'confidence':  0.75,
            'file':        'N/A',
            'display_path': 'N/A',
            'line_number': None,
            'description': (
                'Consent is collected but no withdrawal mechanism detected. '
                'DPDP Section 6(6) requires consent withdrawal to be as easy '
                'as giving consent. Users must be able to revoke consent at any time.'
            ),
            'evidence': {
                'consent_collection_found_in': [
                    {'file': s['file'], 'line': s['line_number'],
                     'text': s['matched_text']}
                    for s in collection_sample
                ],
                'withdrawal_patterns_checked': len(WITHDRAWAL_ROUTE_PATTERNS),
            },
            'fix': None,
            'requires_human_validation': False,
        })

    else:
        # Withdrawal mechanism found — PASS
        findings.append({
            'rule':        'CONSENT_WITHDRAWAL_PRESENT',
            'dpdp_section': 'Section 6(6) — Consent Withdrawal',
            'severity':    'PASS',
            'confidence':  0.80,
            'file':        withdrawal_signals[0]['file'],
            'display_path': withdrawal_signals[0]['file'],
            'line_number': withdrawal_signals[0]['line_number'],
            'description': (
                'Consent withdrawal mechanism detected. '
                f"Found in: {withdrawal_signals[0]['file']} "
                f"(line {withdrawal_signals[0]['line_number']})"
            ),
            'evidence': {
                'withdrawal_signals': [
                    {'file': s['file'], 'line': s['line_number'],
                     'text': s['matched_text']}
                    for s in withdrawal_signals[:3]
                ],
            },
            'fix': None,
        })

    return findings
