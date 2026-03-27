#!/usr/bin/env python3
"""
Test suite for SpamDetector.gs.

Validates the spam detection engine against real-world .eml samples and ensures
the deployed Google Apps Script only calls methods that actually exist on the
Gmail Advanced Service API.

Four test phases run in order:
    1. Gmail API method validation — static analysis of SpamDetector.gs
    2. Spam detection — every .eml in spam_examples/ must be flagged
    3. Scam detection — every .eml in scam_examples/ must be flagged
    4. Ham verification — every .eml in ham_examples/ must NOT be flagged

Exit codes:
    0 — all tests passed
    1 — one or more tests failed (CI will block deploy)
"""

import re
import sys
import email
from email import policy
from email.header import decode_header
from pathlib import Path


# =============================================================================
# SpamDetector.gs Pattern Loader
#
# Option B: single source of truth. All detection constants (regex patterns,
# domain lists, numeric limits) are extracted directly from SpamDetector.gs at
# import time. The test never re-defines a pattern — if a pattern changes in
# the source, the test automatically picks it up on the next run.
#
# JS → Python conversion notes:
#   - /pattern/i  → re.compile(r'pattern', re.IGNORECASE)
#   - /pattern/   → re.compile(r'pattern')
#   - \uD835      → [\U0001D400-\U0001D7FF]  (see _js_pattern_to_python)
#   - All other JS regex syntax is directly compatible with Python's re module.
# =============================================================================

def _parse_js_regex_literal(line):
    """
    Parse a single JS regex literal /pattern/flags from a source line.

    Returns (pattern_str, flags_str) or None if the line has no regex
    (e.g. comment lines, blank lines, closing brackets).
    """
    line = line.strip()
    if not line or line.startswith('//'):
        return None
    # Match /pattern/flags — handles escaped slashes inside the pattern (\/)
    m = re.match(r'^/((?:[^/\\]|\\.)*)/([gimsuy]*)', line)
    return (m.group(1), m.group(2)) if m else None


def _js_flags_to_python(js_flags):
    """Convert a JS regex flag string ('i', 'im', etc.) to Python re flags."""
    flags = 0
    if 'i' in js_flags:
        flags |= re.IGNORECASE
    if 'm' in js_flags:
        flags |= re.MULTILINE
    if 's' in js_flags:
        flags |= re.DOTALL
    return flags


def _js_pattern_to_python(js_pattern):
    """
    Convert a JS regex pattern string to a Python-compatible one.

    The only conversion needed: \\uD835 is the UTF-16 high surrogate for the
    mathematical alphanumeric Unicode block (U+1D400–U+1DFFF, e.g. "𝗔𝗺𝗮𝘇𝗼𝗻").
    JS strings are UTF-16 so matching the surrogate catches all of them. Python
    strings are UCS-4 (full codepoints), so we match the actual range instead.
    All other JS regex syntax is directly compatible with Python's re module.
    """
    return js_pattern.replace(r'\uD835', r'[\U0001D400-\U0001D7FF]')


def _extract_bracket_content(source, marker, terminator='\n]);'):
    """
    Find `marker` in source, then return the content between the opening [
    and the given `terminator` string.

    Depth-counting would miscount `[` inside regex character classes like
    /[a-z]/, so we rely on structural terminators instead:
    - Top-level Object.freeze([...]) arrays end with bare `]);`  (default)
    - Nested sub-arrays (e.g. inside DEFAULT_DOMAINS) end with `]),` or `])`
      and need '\n  ])' passed as the terminator.
    """
    start = source.find(marker)
    if start == -1:
        raise ValueError(f'Marker not found in SpamDetector.gs: {marker!r}')
    bracket_start = source.index('[', start)
    end = source.find(terminator, bracket_start)
    if end == -1:
        raise ValueError(f'No closing {terminator!r} found after marker: {marker!r}')
    return source[bracket_start + 1:end]


def _extract_brace_content(source, marker):
    """Like _extract_bracket_content but for { }."""
    start = source.find(marker)
    if start == -1:
        raise ValueError(f'Marker not found in SpamDetector.gs: {marker!r}')
    brace_start = source.index('{', start)
    depth = 0
    for i in range(brace_start, len(source)):
        if source[i] == '{':
            depth += 1
        elif source[i] == '}':
            depth -= 1
            if depth == 0:
                return source[brace_start + 1:i]
    raise ValueError(f'Unmatched {{ after marker: {marker!r}')


def _load_regex_array(source, const_name):
    """Extract a JS Object.freeze([...]) regex array and compile to Python."""
    content = _extract_bracket_content(source, f'const {const_name} = Object.freeze([')
    patterns = []
    for line in content.splitlines():
        parsed = _parse_js_regex_literal(line)
        if parsed:
            js_pat, js_flags = parsed
            patterns.append(
                re.compile(_js_pattern_to_python(js_pat), _js_flags_to_python(js_flags))
            )
    return patterns


def _load_string_array(source, const_name):
    """Extract a JS Object.freeze([...]) string array as a Python list."""
    content = _extract_bracket_content(source, f'const {const_name} = Object.freeze([')
    return re.findall(r"""['"]([^'"]+)['"]""", content)


def _load_single_regex(source, const_name):
    """Extract a standalone JS const NAME = /pattern/flags; and compile."""
    marker = f'const {const_name} = '
    start = source.find(marker)
    if start == -1:
        raise ValueError(f'{const_name} not found in SpamDetector.gs')
    line_end = source.index('\n', start)
    line = source[start + len(marker):line_end].strip()
    parsed = _parse_js_regex_literal(line)
    if not parsed:
        raise ValueError(f'Could not parse regex for {const_name}')
    js_pat, js_flags = parsed
    return re.compile(_js_pattern_to_python(js_pat), _js_flags_to_python(js_flags))


def _load_gs_constants(gs_path):
    """
    Parse SpamDetector.gs and extract all detection constants used by the test.

    Called once at module load time. Returns a dict with:
        CLICKBAIT_PATTERNS, BODY_CRYPTO_PATTERNS, FEAR_PATTERNS,
        MARKETING_PATTERNS     — lists of compiled re.Pattern objects
        BULK_EMAIL_FINGERPRINTS — list of strings
        RFC2822_QUOTED_NAME    — single compiled re.Pattern
        LIMITS                 — dict of int values (maxDisplayNameLength, etc.)
        DEFAULT_DOMAINS        — dict with 'legitimate' and 'suspicious' lists
    """
    source = gs_path.read_text(encoding='utf-8')

    # LIMITS: extract key: integer_value pairs from the Object.freeze({}) block
    limits_content = _extract_brace_content(source, 'const LIMITS = Object.freeze({')
    limits = {
        m.group(1): int(m.group(2))
        for m in re.finditer(r'(\w+)\s*:\s*(\d+)', limits_content)
    }

    # DEFAULT_DOMAINS: two named inner arrays inside the outer object.
    # These end with ]), (comma) or ]) not ]); so pass the nested terminator.
    legit_content      = _extract_bracket_content(source, 'legitimate: Object.freeze([',  '\n  ])')
    suspicious_content = _extract_bracket_content(source, 'suspicious: Object.freeze([', '\n  ])')

    return {
        'CLICKBAIT_PATTERNS':      _load_regex_array(source, 'CLICKBAIT_PATTERNS'),
        'BODY_CRYPTO_PATTERNS':    _load_regex_array(source, 'BODY_CRYPTO_PATTERNS'),
        'FEAR_PATTERNS':           _load_regex_array(source, 'FEAR_PATTERNS'),
        'MARKETING_PATTERNS':      _load_regex_array(source, 'MARKETING_PATTERNS'),
        'BULK_EMAIL_FINGERPRINTS': _load_string_array(source, 'BULK_EMAIL_FINGERPRINTS'),
        'RFC2822_QUOTED_NAME':     _load_single_regex(source, 'RFC2822_QUOTED_NAME'),
        'LIMITS':                  limits,
        'DEFAULT_DOMAINS': {
            'legitimate': re.findall(r"""['"]([^'"]+)['"]""", legit_content),
            'suspicious':  re.findall(r"""['"]([^'"]+)['"]""", suspicious_content),
        },
    }


# =============================================================================
# Loaded Constants (single source of truth — all from SpamDetector.gs)
# =============================================================================

_GS_PATH = Path(__file__).parent.parent / 'SpamDetector.gs'
_gs = _load_gs_constants(_GS_PATH)

CLICKBAIT_PATTERNS      = _gs['CLICKBAIT_PATTERNS']
BODY_CRYPTO_PATTERNS    = _gs['BODY_CRYPTO_PATTERNS']
FEAR_PATTERNS           = _gs['FEAR_PATTERNS']
MARKETING_PATTERNS      = _gs['MARKETING_PATTERNS']
BULK_EMAIL_FINGERPRINTS = _gs['BULK_EMAIL_FINGERPRINTS']
RFC2822_QUOTED_NAME     = _gs['RFC2822_QUOTED_NAME']
WHITELISTED_DOMAINS     = _gs['DEFAULT_DOMAINS']['legitimate']
BLACKLISTED_DOMAINS     = _gs['DEFAULT_DOMAINS']['suspicious']
MAX_DISPLAY_NAME_LENGTH = _gs['LIMITS']['maxDisplayNameLength']
MAX_INPUT_CHARS         = _gs['LIMITS']['maxInputChars']
MAX_LOG_CHARS           = _gs['LIMITS']['maxLogChars']


# =============================================================================
# Gmail API Method Whitelist
#
# The Advanced Gmail Service in Apps Script does NOT expose every REST API
# method. Notably, single-message delete() does not exist — only batchDelete().
# This whitelist is used by validate_api_methods() to catch bad method calls
# before they reach production (where they'd silently fail or throw).
#
# Source: https://developers.google.com/apps-script/advanced/gmail
# =============================================================================

GMAIL_API_METHODS = {
    'Gmail.Users.Messages': {
        'batchDelete', 'batchModify', 'get', 'insert', 'list',
        'modify', 'send', 'trash', 'untrash',
    },
    'Gmail.Users.Threads': {
        'get', 'list', 'modify', 'trash', 'untrash',
    },
    'Gmail.Users.Labels': {
        'create', 'get', 'list', 'patch', 'update',
    },
}


# =============================================================================
# Helper Functions
# =============================================================================

def decode_email_header(header_value):
    """
    Decode an email header value per RFC 2047.

    Handles encoded-word syntax (e.g., =?utf-8?B?...?=) that mail clients use
    for non-ASCII characters in subject lines and sender names.

    Args:
        header_value: Raw header string, possibly with RFC 2047 encoded words.

    Returns:
        Decoded Unicode string. Returns empty string if header_value is falsy.
    """
    if not header_value:
        return ''

    # Split into (bytes_or_str, charset) tuples per RFC 2047
    decoded_parts = decode_header(header_value)

    # Reassemble: decode bytes with their declared charset, pass strings through
    result = ''
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            result += part.decode(encoding or 'utf-8', errors='replace')
        else:
            result += part
    return result


def parse_eml(filepath):
    """
    Parse an .eml file and extract the fields needed for spam analysis.

    Reads the file twice: once as a structured email (for decoded headers) and
    once as raw text (to check for bulk email service signatures in headers
    that the email library doesn't expose).

    Args:
        filepath: Path to the .eml file.

    Returns:
        Tuple of (subject, from_field, has_bulk_service, body, has_attachment) where:
            - subject: Decoded subject line
            - from_field: Decoded From header (display name + address)
            - has_bulk_service: True if Amazon SES or SendGrid signatures found
            - body: Plain-text body for body-only pattern checks
            - has_attachment: True if the message has one or more attachments
    """
    # Parse structured email for decoded headers (Subject, From, etc.)
    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    # Re-read as raw text — bulk service indicators live in Received/Return-Path
    # headers that the email library doesn't expose as structured fields
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Case-insensitive check using BULK_EMAIL_FINGERPRINTS loaded from SpamDetector.gs
    content_lower = content.lower()
    has_amazon_ses = any(fp in content_lower for fp in BULK_EMAIL_FINGERPRINTS)

    # Decode headers (handles RFC 2047 encoded-words like =?utf-8?B?...?=)
    subject = decode_email_header(msg.get('subject', ''))
    from_raw = decode_email_header(msg.get('from', ''))
    # Strip outer RFC 2822 quotes from display names using the RFC2822_QUOTED_NAME
    # pattern loaded from SpamDetector.gs — same normalization as getFrom() in GAS
    from_field = RFC2822_QUOTED_NAME.sub(r'\1\2', from_raw)

    # Extract plain-text body for body-only pattern checks (e.g. crypto airdrop)
    body = ''
    has_attachment = False
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            disp = part.get_content_disposition() or ''
            if ct == 'text/plain' and not body:
                body = part.get_content()
            elif disp == 'attachment' or (ct not in ('text/plain', 'text/html', 'multipart/mixed',
                                                      'multipart/alternative', 'multipart/related')):
                if part.get_filename():
                    has_attachment = True
    elif msg.get_content_type() == 'text/plain':
        body = msg.get_content()

    return subject, from_field, has_amazon_ses, body, has_attachment


def analyze_email(subject, from_field, has_amazon_ses, body='', has_attachment=False):
    """
    Run the detection logic against a single email's fields.

    Mirrors the analyzeMessage() function in SpamDetector.gs. Collects signals
    from multiple pattern categories, then applies the 5-rule decision logic.

    All patterns and constants used here are loaded from SpamDetector.gs at
    import time — any change to the source is automatically reflected.

    The detection pipeline:
        1. Check sender against blacklisted domains
        2. Inspect From display name for suspicious formatting
        3. Count clickbait pattern matches in subject + from
        4. Check body for high-confidence crypto scam terms (airdrop, wallet drainer)
        5. Check for fear-mongering language
        6. Check for marketing sender format
        7. Check for empty subject + attachment (payload delivery scam)
        8. Apply 5-rule decision logic (rules evaluated in priority order)

    Args:
        subject:        Decoded email subject line.
        from_field:     Decoded From header (display name + email address).
        has_amazon_ses: Whether bulk email service signatures were found.
        body:           Plain-text body for body-only pattern checks.
        has_attachment: Whether the message has one or more attachments.

    Returns:
        Tuple of (signals, is_spam, rule) where:
            - signals: Dict of all detected signal values and matched patterns
            - is_spam: Boolean verdict
            - rule: String describing which rule triggered (empty if not spam)
    """
    # Whitelist check — known legitimate senders bypass all detection
    for domain in WHITELISTED_DOMAINS:
        if domain in from_field.lower():
            return {'bulk_email': has_amazon_ses, 'blacklisted_sender': False,
                    'clickbait_count': 0, 'fear_mongering': False,
                    'marketing_format': False, 'suspicious_from_name': False,
                    'empty_subject_with_attachment': False,
                    'matched_patterns': ['whitelisted']}, False, ''

    # Initialize signal accumulators — each detection phase populates one signal
    signals = {
        'bulk_email': has_amazon_ses,
        'blacklisted_sender': False,
        'clickbait_count': 0,
        'fear_mongering': False,
        'marketing_format': False,
        'suspicious_from_name': False,
        'empty_subject_with_attachment': False,
        'matched_patterns': []          # Audit trail of which patterns fired
    }

    # Concatenate subject + from for pattern matching (same as SpamDetector.gs)
    text_to_check = subject + ' ' + from_field
    from_lower = from_field.lower()

    # ── Signal: Blacklisted sender domain ──────────────────────────────────
    # Substring match against known spam mill domains (one match is enough)
    for domain in BLACKLISTED_DOMAINS:
        if domain in from_lower:
            signals['blacklisted_sender'] = True
            signals['matched_patterns'].append(f'blacklist:{domain}')
            break

    # ── Signal: Suspicious From display name ───────────────────────────────
    # Strip the <email@address> portion, then check the remaining display name
    # for bullet separators (spammer tactic) or excessive length (keyword stuffing)
    display_name = re.sub(r'<[^>]*>$', '', from_field).strip()
    if '•' in display_name or len(display_name) > MAX_DISPLAY_NAME_LENGTH:
        signals['suspicious_from_name'] = True
        signals['matched_patterns'].append('suspicious_from')

    # ── Signal: Clickbait pattern count ────────────────────────────────────
    # Each matching pattern increments the counter independently — this allows
    # Rule 2 (bulk + 2 clickbait) and Rule 4 (3+ clickbait alone) to trigger
    for i, pattern in enumerate(CLICKBAIT_PATTERNS):
        if pattern.search(text_to_check):
            signals['clickbait_count'] += 1
            signals['matched_patterns'].append(f'clickbait[{i}]')

    # ── Signal: Body crypto scam patterns ──────────────────────────────────
    # High-confidence terms checked against body only. Each match increments
    # clickbait_count (same pool) — supports Rule 4 on non-bulk senders.
    for i, pattern in enumerate(BODY_CRYPTO_PATTERNS):
        if pattern.search(body):
            signals['clickbait_count'] += 1
            signals['matched_patterns'].append(f'body_crypto[{i}]')

    # ── Signal: Fear-mongering (boolean, first match wins) ─────────────────
    # Only need to know if fear is present, not how many patterns match
    for i, pattern in enumerate(FEAR_PATTERNS):
        if pattern.search(text_to_check):
            signals['fear_mongering'] = True
            signals['matched_patterns'].append(f'fear[{i}]')
            break

    # ── Signal: Marketing sender format ────────────────────────────────────
    # Checked against From only (not subject) — detects spammy name formatting
    for pattern in MARKETING_PATTERNS:
        if pattern.search(from_field):
            signals['marketing_format'] = True
            signals['matched_patterns'].append('marketing')
            break

    # ── Signal: Empty subject + attachment ─────────────────────────────────
    # Payload delivery scams hide scam content inside attached files (Excel,
    # PDF) and leave the subject and body empty to evade text-pattern rules.
    if subject.strip() == '' and has_attachment:
        signals['empty_subject_with_attachment'] = True
        signals['matched_patterns'].append('empty_subject_attachment')

    # ── Decision Logic (5 rules, evaluated in priority order) ──────────────
    #
    # The rules cascade from most-specific (Rule 1) to broadest (Rule 5).
    # Only one rule can fire per email. This matches SpamDetector.gs exactly.
    is_spam = False
    rule = ''

    # Rule 1: Bulk email + blacklisted sender = definitive spam
    #   Rationale: Known spam domain + bulk infrastructure = no false positives
    if signals['bulk_email'] and signals['blacklisted_sender']:
        is_spam = True
        rule = 'RULE 1: Bulk + blacklisted sender'

    # Rule 2: Bulk email + 2+ clickbait patterns = spam
    #   Rationale: Legitimate bulk senders rarely use multiple clickbait tactics
    elif signals['bulk_email'] and signals['clickbait_count'] >= 2:
        is_spam = True
        rule = 'RULE 2: Bulk + 2+ clickbait'

    else:
        # Rule 3: Bulk email + 2+ distinct spam behaviors = spam
        #   Rationale: Two independent spam signals from a bulk sender is strong
        #   evidence — very unlikely to both fire on a legitimate email
        behavior_count = 0
        if signals['clickbait_count'] >= 1:
            behavior_count += 1
        if signals['fear_mongering']:
            behavior_count += 1
        if signals['marketing_format']:
            behavior_count += 1
        if signals['suspicious_from_name']:
            behavior_count += 1

        if signals['bulk_email'] and behavior_count >= 2:
            is_spam = True
            rule = 'RULE 3: Bulk + 2+ behaviors'

        # Rule 4: Extreme clickbait alone (no bulk email required)
        #   Rationale: 3+ clickbait hits is so anomalous that even non-bulk
        #   senders are almost certainly spam (catches direct-send spam)
        elif signals['clickbait_count'] >= 3:
            is_spam = True
            rule = 'RULE 4: Extreme clickbait'

        # Rule 5: Empty subject + attachment = payload delivery scam
        #   Rationale: Legitimate email virtually never has an empty subject
        #   and an attachment together — this is the fingerprint of file-based
        #   scams that bypass text-pattern detection entirely.
        elif signals['empty_subject_with_attachment']:
            is_spam = True
            rule = 'RULE 5: Empty subject with attachment'

    return signals, is_spam, rule


# =============================================================================
# Test: Gmail API Method Validation
# =============================================================================

def validate_api_methods():
    """
    Static-analyze SpamDetector.gs to verify all Gmail API calls use real methods.

    Reads the source file and regex-matches every Gmail.Users.Messages.xxx(),
    Gmail.Users.Threads.xxx(), etc. call. Each method name is checked against
    GMAIL_API_METHODS. This catches nonexistent methods (e.g., remove(),
    delete_(), delete()) that would compile fine in Apps Script but throw
    TypeError at runtime.

    Checks both dot notation (Gmail.Users.Messages.get()) and bracket notation
    (Gmail.Users.Messages['batchDelete']()) since the codebase uses both.

    Returns:
        List of error strings. Empty list means all methods are valid.
        Returns False if SpamDetector.gs is not found at expected path.
    """
    if not _GS_PATH.exists():
        print(f"ERROR: SpamDetector.gs not found at {_GS_PATH}")
        return False

    source = _GS_PATH.read_text()

    errors = []
    for api_object, valid_methods in GMAIL_API_METHODS.items():
        # Build regex for dot notation: Gmail.Users.Messages.methodName(
        dot_pattern = re.compile(re.escape(api_object) + r'\.(\w+)\s*\(')
        # Build regex for bracket notation: Gmail.Users.Messages['methodName'](
        bracket_pattern = re.compile(re.escape(api_object) + r"\['(\w+)'\]\s*\(")

        # Scan source for both notation styles
        for pattern in [dot_pattern, bracket_pattern]:
            for match in pattern.finditer(source):
                method = match.group(1)
                if method not in valid_methods:
                    # Report line number for easy debugging
                    line_num = source[:match.start()].count('\n') + 1
                    errors.append(f"  Line {line_num}: {api_object}.{method}() is NOT a valid method")
                    errors.append(f"    Valid methods: {', '.join(sorted(valid_methods))}")

    return errors


# =============================================================================
# Test: Spam Detection
# =============================================================================

def run_spam_tests(spam_dir, label='Spam'):
    """
    Test that every .eml in spam_dir is correctly detected as spam.

    Iterates over all .eml files alphabetically, runs analyze_email() on each,
    and expects a spam verdict. Prints per-file results with the triggering
    rule and signal summary for visibility in CI logs.

    A failure here means the detection engine missed a real spam email — the
    patterns or rules need tightening.

    Args:
        spam_dir: Path to directory containing spam .eml files.
        label:    Display label for the test phase header (e.g. 'Spam', 'Scam').

    Returns:
        Tuple of (passed, failed, failures) where:
            - passed:   Count of correctly detected spam emails
            - failed:   Count of missed spam emails (false negatives)
            - failures: List of dicts with details for each missed email
    """
    # Collect and sort .eml files for deterministic ordering across platforms
    files = sorted([f for f in spam_dir.iterdir() if f.suffix == '.eml'])

    print('=' * 80)
    print(f'{label} Detection Test Results')
    print('=' * 80)
    print(f'Testing {len(files)} {label.lower()} examples...\n')

    passed = 0
    failed = 0
    failures = []

    for filepath in files:
        # Parse email and run detection pipeline
        subject, from_field, has_amazon_ses, body, has_attachment = parse_eml(filepath)
        signals, is_spam, rule = analyze_email(subject, from_field, has_amazon_ses, body, has_attachment)

        if is_spam:
            # Expected: spam correctly detected
            passed += 1
            print(f'✅ PASS: {filepath.name[:60]}')
            print(f'   Subject: {subject[:60]}')
            print(f'   Rule: {rule}')
            print(f'   Signals: bulk={signals["bulk_email"]}, clickbait={signals["clickbait_count"]}, '
                  f'fear={signals["fear_mongering"]}, marketing={signals["marketing_format"]}')
            print()
        else:
            # Unexpected: spam was NOT detected — this is a test failure
            failed += 1
            failures.append({
                'file': filepath.name,
                'subject': subject,
                'from': from_field,
                'signals': signals
            })
            print(f'❌ FAIL: {filepath.name}')
            print(f'   Subject: {subject}')
            print(f'   From: {from_field}')
            print(f'   Signals: bulk={signals["bulk_email"]}, clickbait={signals["clickbait_count"]}, '
                  f'fear={signals["fear_mongering"]}, marketing={signals["marketing_format"]}')
            print(f'   Matched: {", ".join(signals["matched_patterns"]) or "NONE"}')
            print()

    # Print spam summary
    print('=' * 80)
    print('SPAM DETECTION SUMMARY')
    print('=' * 80)
    print(f'Total: {len(files)}')
    print(f'Detected: {passed} ({passed/len(files)*100:.1f}%)')
    print(f'Missed: {failed} ({failed/len(files)*100:.1f}%)')

    return passed, failed, failures


# =============================================================================
# Test: Ham (Legitimate Email) Verification
# =============================================================================

def run_ham_tests(ham_dir):
    """
    Test that every .eml in ham_dir is correctly allowed through (not flagged).

    These are synthetic emails covering edge cases like bank alerts, Amazon SES
    senders (GitHub, Stripe), security warnings, and articles with words that
    partially match spam patterns. A failure here means a false positive — the
    detection engine is too aggressive and would delete legitimate mail.

    Args:
        ham_dir: Path to directory containing legitimate .eml files.

    Returns:
        Tuple of (ham_passed, ham_total, false_positives) where:
            - ham_passed:       Count of correctly allowed legitimate emails
            - ham_total:        Total number of ham emails tested
            - false_positives:  List of dicts with details for each wrongly flagged email
    """
    # Collect and sort .eml files for deterministic ordering
    ham_files = sorted([f for f in ham_dir.iterdir() if f.suffix == '.eml'])
    ham_total = len(ham_files)
    ham_passed = 0
    false_positives = []

    # Guard: skip if no ham examples exist (avoids division by zero later)
    if not ham_files:
        return 0, 0, []

    print('\n' + '=' * 80)
    print('HAM (Legitimate Email) Testing')
    print('=' * 80)
    print(f'Testing {len(ham_files)} ham examples...\n')

    for filepath in ham_files:
        # Parse email and run detection pipeline
        subject, from_field, has_amazon_ses, body, has_attachment = parse_eml(filepath)
        signals, is_spam, rule = analyze_email(subject, from_field, has_amazon_ses, body, has_attachment)

        if not is_spam:
            # Expected: legitimate email correctly allowed through
            ham_passed += 1
            print(f'✅ PASS (not spam): {filepath.name[:60]}')
            print(f'   Subject: {subject[:60]}')
            print(f'   From: {from_field[:60]}')
            print()
        else:
            # Unexpected: legitimate email was wrongly flagged — false positive
            false_positives.append({
                'file': filepath.name,
                'subject': subject,
                'from': from_field,
                'rule': rule,
                'signals': signals
            })
            print(f'❌ FALSE POSITIVE: {filepath.name}')
            print(f'   Subject: {subject}')
            print(f'   From: {from_field}')
            print(f'   Wrongly triggered: {rule}')
            print(f'   Signals: bulk={signals["bulk_email"]}, clickbait={signals["clickbait_count"]}, '
                  f'fear={signals["fear_mongering"]}, marketing={signals["marketing_format"]}')
            print()

    # Print ham summary
    print('=' * 80)
    print('HAM TESTING SUMMARY')
    print('=' * 80)
    print(f'Total: {ham_total}')
    print(f'Correctly allowed: {ham_passed} ({ham_passed/ham_total*100:.1f}%)')
    print(f'False positives: {len(false_positives)} ({len(false_positives)/ham_total*100:.1f}%)')

    return ham_passed, ham_total, false_positives


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """
    Run all test phases and exit with appropriate code for CI.

    Executes four phases in order, failing fast on critical errors:
        Phase 1: Gmail API method validation — fails fast because there's no
                 point testing detection if the deployed code will crash on
                 bad API calls.
        Phase 2: Spam detection against spam_examples/.
        Phase 3: Scam detection against scam_examples/.
        Phase 4: Ham verification against ham_examples/.

    Exits 0 if all phases pass, 1 if any phase fails.
    """
    # ── Phase 1: Gmail API Method Validation ───────────────────────────────
    # Fail fast: if the source code calls nonexistent Gmail methods, stop here.
    # No point running detection tests if the deployment would crash anyway.
    print('=' * 80)
    print('Gmail API Method Validation')
    print('=' * 80)
    api_errors = validate_api_methods()
    if api_errors:
        print('❌ INVALID API METHODS FOUND IN SpamDetector.gs:')
        for err in api_errors:
            print(err)
        print()
        print('Fix these before deploying — these methods will fail at runtime.')
        print('=' * 80)
        sys.exit(1)
    else:
        print('✅ All Gmail API method calls are valid')
    print()

    # ── Phase 2: Spam Detection ────────────────────────────────────────────
    # Every .eml in spam_examples/ must be correctly flagged as spam.
    spam_dir = Path(__file__).parent / 'spam_examples'

    if not spam_dir.exists():
        print(f"ERROR: spam_examples directory not found at {spam_dir}")
        sys.exit(1)

    passed, failed, spam_failures = run_spam_tests(spam_dir)

    # ── Phase 3: Scam Detection ────────────────────────────────────────────
    # Every .eml in scam_examples/ must be correctly flagged as spam.
    # Scam examples cover attack vectors that evade text-pattern rules (e.g.
    # empty subject + attachment payload delivery).
    scam_dir = Path(__file__).parent / 'scam_examples'
    scam_passed = 0
    scam_failed = 0
    scam_failures = []

    if scam_dir.exists():
        scam_passed, scam_failed, scam_failures = run_spam_tests(scam_dir, label='Scam')

    # ── Phase 4: Ham Verification ──────────────────────────────────────────
    # Every .eml in ham_examples/ must NOT be flagged (no false positives).
    ham_dir = Path(__file__).parent / 'ham_examples'
    ham_passed = 0
    ham_total = 0
    ham_false_positives = []

    if ham_dir.exists():
        ham_passed, ham_total, ham_false_positives = run_ham_tests(ham_dir)

    # ── Final Summary ──────────────────────────────────────────────────────
    # Aggregate results from all phases and determine exit code for CI
    print('\n' + '=' * 80)
    print('FINAL RESULTS')
    print('=' * 80)

    all_good = True

    # Report any missed spam (false negatives)
    if spam_failures:
        print(f'❌ SPAM MISSED: {len(spam_failures)}')
        for f in spam_failures:
            print(f'   - {f["file"]}: {f["subject"][:50]}')
        all_good = False
    else:
        print(f'✅ SPAM: {passed}/{passed + failed} detected (100%)')

    # Report any missed scams (false negatives)
    if scam_failures:
        print(f'❌ SCAMS MISSED: {len(scam_failures)}')
        for f in scam_failures:
            print(f'   - {f["file"]}: {f["subject"][:50]}')
        all_good = False
    elif scam_dir.exists():
        print(f'✅ SCAM: {scam_passed}/{scam_passed + scam_failed} detected (100%)')

    # Report any wrongly flagged ham (false positives)
    if ham_false_positives:
        print(f'❌ FALSE POSITIVES: {len(ham_false_positives)}')
        for f in ham_false_positives:
            print(f'   - {f["file"]}: {f["subject"][:50]}')
        all_good = False
    elif ham_total > 0:
        print(f'✅ HAM: {ham_passed}/{ham_total} correctly allowed (0% false positives)')

    # Exit 0 for CI success, 1 for failure
    if all_good:
        print('\n🎉 ALL TESTS PASSED!')
        sys.exit(0)
    else:
        print('\n💥 TESTS FAILED!')
        sys.exit(1)


if __name__ == '__main__':
    main()
