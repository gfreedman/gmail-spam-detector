#!/usr/bin/env python3
"""
Test suite for SpamDetector.gs.

Validates the spam detection engine against real-world .eml samples and ensures
the deployed Google Apps Script only calls methods that actually exist on the
Gmail Advanced Service API.

Seven test phases run in order:
    0. Parser self-tests — unit-test the JS→Python regex extractor
    1. Gmail API method validation — static analysis of SpamDetector.gs
    2. Spam detection — every .eml in spam_examples/ must be flagged
    3. Scam detection — every .eml in scam_examples/ must be flagged
    4. Ham verification — every .eml in ham_examples/ must NOT be flagged
    5. Edge cases — robustness against malformed/boundary/pathological inputs
    6. Performance — informational P50/P95/P99 timing (not pass/fail)

Exit codes:
    0 — all tests passed
    1 — one or more tests failed (CI will block deploy)
"""

import re
import sys
import time
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
#   - \\uD835      → [\U0001D400-\U0001D7FF]  (see _js_pattern_to_python)
#   - All other JS regex syntax used in this codebase is directly compatible
#     with Python's re module.
#
# FORMATTING CONTRACT (enforced at import time):
#   - Every constant must be declared as:  const NAME = Object.freeze([
#   - Each regex must be on its own line:  /pattern/flags,
#   - Violation causes an import-time ValueError with a diagnostic message.
#   - _extract_bracket_content uses a state machine (not string search) so
#     regex character classes like /[a-z]/ and comments are handled correctly.
# =============================================================================

def _parse_js_regex_literal(line):
    """
    Parse a single JS regex literal /pattern/flags from a source line.

    The tricky part: a regex like /foo\\/bar/i has an escaped slash inside the
    pattern. Naively splitting on '/' breaks here — we'd get ['', 'foo\\', 'bar', 'i'].
    The regex below handles backslash escapes so it correctly finds the CLOSING /.

    Args:
        line: One line of JavaScript source code.

    Returns:
        (pattern_str, flags_str) if line contains a regex literal, or None if not
        (e.g. comment lines '// ...', blank lines, or closing brackets ']);').
    """
    line = line.strip()
    if not line or line.startswith('//'):
        return None
    # Match /pattern/flags — handles escaped slashes inside the pattern (\/)
    m = re.match(r'^/((?:[^/\\]|\\.)*)/([gimsuy]*)', line)
    return (m.group(1), m.group(2)) if m else None


def _js_flags_to_python(js_flags):
    """
    Convert a JS regex flag string ('i', 'im', etc.) to a Python re flags int.

    Supported flags (directly translatable):
        i → re.IGNORECASE
        m → re.MULTILINE
        s → re.DOTALL

    Raises ValueError on JS-only flags (g, u, y) — they either have no Python
    equivalent or change semantics in ways the test doesn't account for.
    Raises ValueError on unrecognized flags (typos, future JS additions).
    """
    _SUPPORTED = {'i': re.IGNORECASE, 'm': re.MULTILINE, 's': re.DOTALL}
    _JS_ONLY   = set('guy')   # global, Unicode mode, sticky — no Python equivalent

    unknown = set(js_flags) - set(_SUPPORTED) - _JS_ONLY
    if unknown:
        raise ValueError(f'Unrecognized JS regex flags: {unknown!r}')
    unsupported = set(js_flags) & _JS_ONLY
    if unsupported:
        raise ValueError(
            f'JS-only regex flag(s) {unsupported!r} cannot be mapped to Python re. '
            f'Add explicit handling in _js_pattern_to_python() for this case.'
        )

    flags = 0
    for flag, py_flag in _SUPPORTED.items():
        if flag in js_flags:
            flags |= py_flag
    return flags


def _js_pattern_to_python(js_pattern):
    """
    Convert a JS regex pattern string to a Python-compatible one.

    Almost all JS regex syntax works unchanged in Python. ONE exception: fancy
    Unicode characters like "𝗔𝗺𝗮𝘇𝗼𝗻" (bold math font used in spam subjects).

    Background: JavaScript stores strings as UTF-16 (16-bit code units). Characters
    above U+FFFF — like the bold math block U+1D400–U+1DFFF — need TWO 16-bit
    "surrogate" units to encode. \\uD835 is the HIGH surrogate shared by the entire
    bold math block, so the JS pattern /\\uD835/ matches any bold math character.

    Python 3 uses full Unicode codepoints natively, so we convert \\uD835 to the
    actual character range [\\U0001D400-\\U0001D7FF] instead.

    All other JS regex features used in this codebase (\\b, \\d, \\s, |, {n,m},
    character classes, flags i/m/s) work identically in Python's re module.
    """
    return js_pattern.replace(r'\uD835', r'[\U0001D400-\U0001D7FF]')


def _extract_bracket_content(source, marker):
    """
    Find `marker` in source and return the content between the outer [ and its
    matching ].

    Why a state machine instead of simple bracket-counting?
    A naive counter (depth++ on '[', depth-- on ']') breaks on patterns like:
        /[a-z]+/,   ← the '[' here is inside a regex, NOT opening a nested array
    The naive counter increments depth, then can't find the matching ']', and
    either returns truncated content or raises an error.

    Solution: track context. A '[' only counts toward depth when we're NOT inside
    a regex literal, string literal, or comment. The state machine skips over:
        - Line comments   //...
        - Block comments  /* ... */
        - String literals '...' and "..."
        - Regex literals  /pattern/flags  (including character classes /[a-z]/)
    """
    start = source.find(marker)
    if start == -1:
        raise ValueError(
            f'Marker not found in SpamDetector.gs: {marker!r}\n'
            f'Expected:  const NAME = Object.freeze([\n'
            f'Check the constant name is spelled correctly.'
        )
    bracket_start = source.index('[', start)
    i = bracket_start
    depth = 0

    while i < len(source):
        c = source[i]

        # ── Skip line comment (//) ──────────────────────────────────────────
        if c == '/' and i + 1 < len(source) and source[i + 1] == '/':
            newline = source.find('\n', i)
            i = newline + 1 if newline != -1 else len(source)
            continue

        # ── Skip block comment (/* ... */) ─────────────────────────────────
        if c == '/' and i + 1 < len(source) and source[i + 1] == '*':
            end = source.find('*/', i + 2)
            i = end + 2 if end != -1 else len(source)
            continue

        # ── Skip string literal ('...' or "...") ───────────────────────────
        if c in ('"', "'"):
            quote = c
            i += 1
            while i < len(source):
                if source[i] == '\\':
                    i += 2          # Skip escaped character (e.g. \', \")
                    continue
                if source[i] == quote:
                    break
                i += 1
            i += 1                  # Move past the closing quote
            continue

        # ── Skip regex literal (/pattern/flags) ────────────────────────────
        # Inside Object.freeze([...]) arrays `/` is always a regex literal —
        # division never appears here. (Comments handled above come first.)
        if c == '/':
            i += 1
            while i < len(source):
                if source[i] == '\\':
                    i += 2          # Skip escaped character (e.g. \/, \[)
                    continue
                if source[i] == '[':
                    # Regex character class — skip to its closing ]
                    # (] inside [] is NOT an array bracket; track it separately)
                    i += 1
                    while i < len(source):
                        if source[i] == '\\':
                            i += 2
                            continue
                        if source[i] == ']':
                            break
                        i += 1
                    i += 1
                    continue
                if source[i] == '/':
                    break
                i += 1
            i += 1                  # Past closing /
            while i < len(source) and source[i] in 'gimsuy':
                i += 1              # Skip flags (i, g, m, s, u, y)
            continue

        # ── Track bracket depth (only reaches here for bare [ and ]) ───────
        if c == '[':
            depth += 1
        elif c == ']':
            depth -= 1
            if depth == 0:
                return source[bracket_start + 1:i]

        i += 1

    line_num = source[:bracket_start].count('\n') + 1
    raise ValueError(f'Unmatched [ at line {line_num} after marker: {marker!r}')


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

    # Cross-check: every non-comment line starting with / should yield one pattern.
    # A mismatch means the parser silently skipped something — fail loudly so the
    # bug is diagnosed as "parser problem" not "detection problem".
    expected = sum(
        1 for line in content.splitlines()
        if line.strip().startswith('/') and not line.strip().startswith('//')
    )
    if len(patterns) != expected:
        raise ValueError(
            f'{const_name}: counted {expected} regex literal lines but compiled '
            f'{len(patterns)} patterns — parser may have truncated or skipped some'
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
    # The state machine in _extract_bracket_content handles the nested structure.
    legit_content      = _extract_bracket_content(source, 'legitimate: Object.freeze([')
    suspicious_content = _extract_bracket_content(source, 'suspicious: Object.freeze([')

    return {
        'CLICKBAIT_PATTERNS':           _load_regex_array(source, 'CLICKBAIT_PATTERNS'),
        'BODY_CRYPTO_PATTERNS':         _load_regex_array(source, 'BODY_CRYPTO_PATTERNS'),
        'BODY_FEAR_PATTERNS':           _load_regex_array(source, 'BODY_FEAR_PATTERNS'),
        'FEAR_PATTERNS':                _load_regex_array(source, 'FEAR_PATTERNS'),
        'MARKETING_PATTERNS':           _load_regex_array(source, 'MARKETING_PATTERNS'),
        'BULK_EMAIL_FINGERPRINTS':      _load_string_array(source, 'BULK_EMAIL_FINGERPRINTS'),
        'IMPERSONATION_SUBJECT_PATTERNS': _load_regex_array(source, 'IMPERSONATION_SUBJECT_PATTERNS'),
        'CLOUD_SERVICE_DOMAINS':        _load_string_array(source, 'CLOUD_SERVICE_DOMAINS'),
        'RFC2822_QUOTED_NAME':          _load_single_regex(source, 'RFC2822_QUOTED_NAME'),
        'LIMITS':                       limits,
        'DEFAULT_DOMAINS': {
            'legitimate': re.findall(r"""['"]([^'"]+)['"]""", legit_content),
            'suspicious':  re.findall(r"""['"]([^'"]+)['"]""", suspicious_content),
        },
    }


# =============================================================================
# Loaded Constants (single source of truth — all from SpamDetector.gs)
# =============================================================================

_GS_PATH = Path(__file__).parent.parent / 'SpamDetector.gs'
try:
    _gs = _load_gs_constants(_GS_PATH)
except Exception as _e:
    print(f'\nFATAL: Could not parse SpamDetector.gs — {_e}', file=sys.stderr)
    print('Check that SpamDetector.gs exists and has not been reformatted.', file=sys.stderr)
    sys.exit(1)

CLICKBAIT_PATTERNS              = _gs['CLICKBAIT_PATTERNS']
BODY_CRYPTO_PATTERNS            = _gs['BODY_CRYPTO_PATTERNS']
BODY_FEAR_PATTERNS              = _gs['BODY_FEAR_PATTERNS']
FEAR_PATTERNS                   = _gs['FEAR_PATTERNS']
MARKETING_PATTERNS              = _gs['MARKETING_PATTERNS']
BULK_EMAIL_FINGERPRINTS         = _gs['BULK_EMAIL_FINGERPRINTS']
IMPERSONATION_SUBJECT_PATTERNS  = _gs['IMPERSONATION_SUBJECT_PATTERNS']
CLOUD_SERVICE_DOMAINS           = _gs['CLOUD_SERVICE_DOMAINS']
RFC2822_QUOTED_NAME             = _gs['RFC2822_QUOTED_NAME']
WHITELISTED_DOMAINS             = _gs['DEFAULT_DOMAINS']['legitimate']
BLACKLISTED_DOMAINS             = _gs['DEFAULT_DOMAINS']['suspicious']
MAX_DISPLAY_NAME_LENGTH         = _gs['LIMITS']['maxDisplayNameLength']
MAX_INPUT_CHARS                 = _gs['LIMITS']['maxInputChars']
MAX_LOG_CHARS                   = _gs['LIMITS']['maxLogChars']


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
    try:
        with open(filepath, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
    except Exception as e:
        raise ValueError(f'Failed to parse {Path(filepath).name}: {e}') from e

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
    elif msg.get_content_type() == 'text/html':
        # HTML-only single-part message — strip tags, mirrors stripHtmlTags() in GS
        body = re.sub(r'<[^>]+>', ' ', msg.get_content())
        body = re.sub(r'\s+', ' ', body).strip()

    # HTML fallback for multipart messages with no text/plain part
    if not body and msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/html' and not part.get_content_disposition():
                raw_html = part.get_content()
                body = re.sub(r'<[^>]+>', ' ', raw_html)
                body = re.sub(r'\s+', ' ', body).strip()
                break

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
    # Whitelist check — known legitimate senders bypass all detection.
    # Match against the email address only (not the display name) to prevent
    # display-name spoofing: "LinkedIn News <spammer@spam.com>" must NOT bypass.
    email_match = re.search(r'<([^>]+)>', from_field)
    sender_address = (email_match.group(1) if email_match else from_field).lower()
    for domain in WHITELISTED_DOMAINS:
        if domain in sender_address:
            return {'bulk_email': has_amazon_ses, 'blacklisted_sender': False,
                    'clickbait_count': 0, 'fear_mongering': False,
                    'marketing_format': False, 'suspicious_from_name': False,
                    'empty_subject_with_attachment': False,
                    'service_impersonation': False,
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
        'service_impersonation': False,
        'matched_patterns': []          # Audit trail of which patterns fired
    }

    # Concatenate subject + from for pattern matching (same as SpamDetector.gs)
    text_to_check = subject + ' ' + from_field
    from_lower = from_field.lower()

    # ── Signal: Blacklisted sender domain ──────────────────────────────────
    # Substring match against known spam mill domains (one match is enough).
    # Use sender_address (email only, not display name) — mirrors SpamDetector.gs.
    for domain in BLACKLISTED_DOMAINS:
        if domain in sender_address:
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

    # ── Signal: Body fear patterns ─────────────────────────────────────────
    # Phishing-specific conditional-fear phrases in body ("could be compromised").
    # Each match increments clickbait_count (same pool as BODY_CRYPTO).
    for i, pattern in enumerate(BODY_FEAR_PATTERNS):
        if pattern.search(body):
            signals['clickbait_count'] += 1
            signals['matched_patterns'].append(f'body_fear[{i}]')

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

    # ── Signal: Service impersonation phishing ──────────────────────────────
    # Cloud service share notifications only come from the service's own domain.
    # A "Document shared with you" from ywammaui.org is 100% phishing.
    matches_service_subject = any(p.search(subject) for p in IMPERSONATION_SUBJECT_PATTERNS)
    if matches_service_subject:
        from_trusted = any(
            sender_address.endswith('@' + d) or sender_address.endswith('.' + d)
            for d in CLOUD_SERVICE_DOMAINS
        )
        if not from_trusted:
            signals['service_impersonation'] = True
            signals['matched_patterns'].append('service_impersonation')

    # ── Decision Logic (6 rules, evaluated in priority order) ──────────────
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

        # Rule 6: Service impersonation phishing (no bulk email required)
        #   Rationale: Cloud service notifications (Google Docs, OneDrive, etc.)
        #   always come from the service's own domain. Any other sender using
        #   these subject templates is phishing via a compromised account.
        elif signals['service_impersonation']:
            is_spam = True
            rule = 'RULE 6: Service impersonation phishing'

    return signals, is_spam, rule


# =============================================================================
# Phase 0: Parser Self-Tests
# =============================================================================

def run_parser_tests():
    """
    Unit-test the JS→Python parser functions before running detection tests.

    Catches parser bugs early so failures are diagnosed as "parser broken"
    rather than "detection broken". Each check() call asserts a specific
    expected output from a single parser function.

    Returns True if all assertions pass, False (with printed failures) if any fail.
    """
    failures = []

    def check(desc, got, expected):
        if got != expected:
            failures.append(f'  {desc}\n    expected {expected!r}\n    got      {got!r}')

    # ── _parse_js_regex_literal ─────────────────────────────────────────────
    check('basic pattern + flag',       _parse_js_regex_literal('  /foo/i,'),      ('foo', 'i'))
    check('multiple flags',             _parse_js_regex_literal('/bar/im'),         ('bar', 'im'))
    check('no flags',                   _parse_js_regex_literal('/baz/,'),          ('baz', ''))
    check('escaped slash in pattern',   _parse_js_regex_literal(r'/foo\/bar/'),     (r'foo\/bar', ''))
    check('comment line → None',        _parse_js_regex_literal('// comment'),      None)
    check('blank line → None',         _parse_js_regex_literal(''),                None)
    check('closing bracket → None',    _parse_js_regex_literal(']);'),             None)

    # ── _js_flags_to_python ─────────────────────────────────────────────────
    check('empty flags → 0',            _js_flags_to_python(''),                   0)
    check('i → IGNORECASE',             _js_flags_to_python('i'),                  re.IGNORECASE)
    check('im → IGNORECASE|MULTILINE',  _js_flags_to_python('im'),                 re.IGNORECASE | re.MULTILINE)
    check('ims → all three',            _js_flags_to_python('ims'),                re.IGNORECASE | re.MULTILINE | re.DOTALL)

    for bad in ('g', 'u', 'y', 'z'):
        try:
            _js_flags_to_python(bad)
            failures.append(f'  _js_flags_to_python({bad!r}) should raise ValueError')
        except ValueError:
            pass  # Expected

    # ── _js_pattern_to_python ──────────────────────────────────────────────
    converted = _js_pattern_to_python(r'\uD835foo')
    if r'[\U0001D400-\U0001D7FF]' not in converted:
        failures.append(f'  \\uD835 not converted: {converted!r}')
    check('passthrough — char class',     _js_pattern_to_python('[a-z]'),          '[a-z]')
    check('passthrough — word boundary',  _js_pattern_to_python(r'\bword\b'),      r'\bword\b')

    # ── _extract_bracket_content ────────────────────────────────────────────
    # Basic string array
    src = "const FOO = Object.freeze([\n  'a',\n  'b'\n]);"
    content = _extract_bracket_content(src, 'const FOO = Object.freeze([')
    if "'a'" not in content or "'b'" not in content:
        failures.append(f"  basic string array extraction: {content!r}")

    # Regex array with character classes — the key regression test.
    # A naive depth-counter sees /[a-z]/ as opening a nested bracket level,
    # which causes it to stop at the wrong ] and return truncated content.
    src2 = "const BAR = Object.freeze([\n  /[a-z]/i,\n  /[0-9]+/\n]);"
    content2 = _extract_bracket_content(src2, 'const BAR = Object.freeze([')
    if '/[a-z]/i,' not in content2 or '/[0-9]+/' not in content2:
        failures.append(f"  regex with character classes truncated: {content2!r}")

    # Marker not found → ValueError
    try:
        _extract_bracket_content('const OTHER = []', 'const MISSING = Object.freeze([')
        failures.append('  missing marker should raise ValueError')
    except ValueError:
        pass  # Expected

    if failures:
        print('❌ PARSER SELF-TESTS FAILED:')
        for msg in failures:
            print(msg)
        return False

    print('✅ All parser self-tests passed')
    return True


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
# Phase 6: Performance Benchmark
# =============================================================================

def run_performance_tests(all_emails):
    """
    Benchmark analyze_email() throughput across the full test corpus.

    Informational only — not a pass/fail test. Prints P50/P95/P99 per-email
    timings and a rough Apps Script estimate. Helps verify that the detection
    engine won't approach the 6-minute per-trigger timeout even at the
    50-email-per-run limit.

    Python executes regex 5-10x faster than Apps Script V8. Multiply the
    measured P99 by 10 and by MAX_EMAILS_PER_RUN (50) to get a conservative
    upper-bound GAS estimate.

    Args:
        all_emails: List of (subject, from_field, has_amazon_ses, body, has_attachment)
                    tuples — typically the combined spam + scam + ham corpus.
    """
    if not all_emails:
        print('  (no emails to benchmark)')
        return

    RUNS = 10  # repeat the full corpus N times for stable percentiles
    timings_ms = []

    for _ in range(RUNS):
        for subject, from_field, has_ses, body, has_att in all_emails:
            t0 = time.perf_counter()
            analyze_email(subject, from_field, has_ses, body, has_att)
            timings_ms.append((time.perf_counter() - t0) * 1000)

    timings_ms.sort()
    n = len(timings_ms)
    p50 = timings_ms[n // 2]
    p95 = timings_ms[int(n * 0.95)]
    p99 = timings_ms[int(n * 0.99)]

    print('=' * 80)
    print('Performance Benchmark (informational)')
    print('=' * 80)
    print(f'  Corpus: {len(all_emails)} emails × {RUNS} runs = {n} samples')
    print(f'  Per-email timing (Python):  P50={p50:.3f}ms  P95={p95:.3f}ms  P99={p99:.3f}ms')

    # Conservative GAS estimate: Python is ~10x faster than Apps Script V8.
    # Multiply P99 × 10 (GAS overhead) × 50 (max emails/run) for worst case.
    gas_estimate_s = p99 * 10 * 50 / 1000
    print(f'  Estimated GAS worst case:   P99 × 10x × 50 emails ≈ {gas_estimate_s:.1f}s '
          f'(budget: 360s)')
    if gas_estimate_s > 60:
        print('  ⚠️  WARNING: extrapolated GAS time exceeds 60s — review pattern complexity')
    else:
        print('  ✅ Well within 6-minute Apps Script trigger budget')


# =============================================================================
# Phase 5: Edge Case Tests
# =============================================================================

def run_edge_case_tests():
    """
    Verify robustness against malformed, pathological, and boundary inputs.

    These tests call analyze_email() directly with crafted inputs — no .eml
    files needed. They target crashes and mis-classifications rather than
    detection accuracy. A failure here means the engine is fragile in ways
    that could cause silent misses or unhandled exceptions in production.

    Returns:
        True if all edge cases pass, False if any fail.
    """
    passed = 0
    failed = 0

    def check(name, condition, explanation=''):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f'  ✅ {name}')
        else:
            failed += 1
            print(f'  ❌ FAIL: {name}' + (f' — {explanation}' if explanation else ''))

    print('=' * 80)
    print('Edge Case Tests')
    print('=' * 80)

    # ── Bare address From (no display name, no angle brackets) ───────────────
    # extractEmailAddress() must fall back to full string and not crash
    _, is_spam, _ = analyze_email('', 'noreply@example.com', False)
    check('bare address From: no crash', not is_spam,
          'empty subject + no signals should not be spam')

    # ── Display name only (no @ address) ────────────────────────────────────
    # Malformed From with no email address at all — should not crash or whitelist
    _, is_spam, _ = analyze_email('Amazing shocking offer', 'A Random Person', True)
    check('display-name-only From: no crash', True)  # just no exception

    # ── Display-name spoofing: whitelisted domain in name, spammer address ───
    # "LinkedIn News <spammer@spam.com>" must NOT bypass whitelist
    signals, is_spam, rule = analyze_email(
        'Shocking investment secret revealed',
        'LinkedIn News <info@smartinvestmenttools.com>',
        has_amazon_ses=True
    )
    check('display-name spoof: not whitelisted',
          signals['blacklisted_sender'],
          'smartinvestmenttools.com in address should be blacklisted')

    # ── Null bytes and control characters in subject ─────────────────────────
    # sanitizeInput() must truncate cleanly; no crash or unexpected pattern fire
    null_subject = 'Hello\x00World\x01\x02\x03'
    _, is_spam, _ = analyze_email(null_subject, 'sender@example.com', False)
    check('null bytes in subject: no crash', True)

    # ── Maximum-length display name triggers suspiciousFromName ─────────────
    # MAX_DISPLAY_NAME_LENGTH is 50; a 51-char name must trip the signal
    long_name = 'A' * (MAX_DISPLAY_NAME_LENGTH + 1)
    signals, _, _ = analyze_email('Hello', f'{long_name} <sender@example.com>', False)
    check('51-char display name → suspiciousFromName',
          signals['suspicious_from_name'],
          f'name length {MAX_DISPLAY_NAME_LENGTH + 1} > limit {MAX_DISPLAY_NAME_LENGTH}')

    # ── Exactly at display name limit: no false positive ────────────────────
    exact_name = 'B' * MAX_DISPLAY_NAME_LENGTH
    signals, _, _ = analyze_email('Hello', f'{exact_name} <sender@example.com>', False)
    check(f'{MAX_DISPLAY_NAME_LENGTH}-char display name: no suspiciousFromName flag',
          not signals['suspicious_from_name'],
          f'name length exactly {MAX_DISPLAY_NAME_LENGTH} should not trigger')

    # ── Empty subject + attachment triggers Rule 5 ───────────────────────────
    signals, is_spam, rule = analyze_email('', 'sender@example.com', False,
                                            body='', has_attachment=True)
    check('empty subject + attachment → Rule 5 spam',
          is_spam and 'RULE 5' in rule)

    # ── Empty subject + NO attachment: not spam ──────────────────────────────
    _, is_spam, _ = analyze_email('', 'sender@example.com', False,
                                   body='', has_attachment=False)
    check('empty subject without attachment: not spam', not is_spam)

    # ── All-empty inputs: no crash, not spam ─────────────────────────────────
    _, is_spam, _ = analyze_email('', '', False, body='', has_attachment=False)
    check('all-empty inputs: no crash, not spam', not is_spam)

    # ── 100KB subject: truncated, no crash, no false positive ───────────────
    # sanitizeInput() caps at LIMITS.maxInputChars; verify no exception and
    # that a string of neutral chars doesn't trigger any pattern
    big_subject = 'a' * 100_001
    _, is_spam, _ = analyze_email(big_subject, 'sender@example.com', False)
    check('100KB subject: no crash, not spam', not is_spam)

    # ── Rule 6: Service impersonation — Google Docs subject from attacker ────
    signals, is_spam, rule = analyze_email(
        'Document shared with you',
        'registrar@ywammaui.org',
        has_amazon_ses=False
    )
    check('Google Docs subject from non-Google sender → Rule 6 phishing',
          is_spam and 'RULE 6' in rule,
          'service impersonation should fire without bulk email requirement')

    # ── Rule 6: Service impersonation — invite subject from attacker ─────────
    signals, is_spam, rule = analyze_email(
        'Registrar YWAM Maui invited you to edit the following document',
        'registrar@ywammaui.org',
        has_amazon_ses=False
    )
    check('Google Docs invite subject from non-Google sender → Rule 6 phishing',
          is_spam and 'RULE 6' in rule)

    # ── Rule 6 ham: real Google Docs notification should NOT trigger ──────────
    _, is_spam, _ = analyze_email(
        'Document shared with you',
        'drive-shares-noreply@google.com',
        has_amazon_ses=False
    )
    check('Google Docs subject from google.com → not spam',
          not is_spam,
          'real Google notifications must not be false-positived')

    print()
    print(f'Edge case results: {passed} passed, {failed} failed')
    return failed == 0


# =============================================================================
# Main Entry Point
# =============================================================================

def main():
    """
    Run all test phases and exit with appropriate code for CI.

    Executes seven phases in order, failing fast on critical errors:
        Phase 0: Parser self-tests — verifies JS→Python extraction before anything else.
        Phase 1: Gmail API method validation — fails fast because there's no
                 point testing detection if the deployed code will crash on
                 bad API calls.
        Phase 2: Spam detection against spam_examples/.
        Phase 3: Scam detection against scam_examples/.
        Phase 4: Ham verification against ham_examples/.
        Phase 5: Edge cases — robustness against malformed/boundary inputs.
        Phase 6: Performance — informational timing benchmark (not pass/fail).

    Exits 0 if all phases pass, 1 if any phase fails.
    """
    # ── Phase 0: Parser Self-Tests ─────────────────────────────────────────
    # Run before detection tests so a parser bug is diagnosed correctly.
    # If the parser is broken, detection failures are misdiagnosed as pattern
    # problems — waste of debugging time.
    print('=' * 80)
    print('Parser Self-Tests')
    print('=' * 80)
    if not run_parser_tests():
        print('\nFix the parser before running detection tests.')
        sys.exit(1)
    print()

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

    # Collect parsed email tuples for the performance benchmark (Phase 6)
    all_email_tuples = []
    for filepath in sorted([f for f in spam_dir.iterdir() if f.suffix == '.eml']):
        all_email_tuples.append(parse_eml(filepath))

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
        for filepath in sorted([f for f in scam_dir.iterdir() if f.suffix == '.eml']):
            all_email_tuples.append(parse_eml(filepath))

    # ── Phase 4: Ham Verification ──────────────────────────────────────────
    # Every .eml in ham_examples/ must NOT be flagged (no false positives).
    ham_dir = Path(__file__).parent / 'ham_examples'
    ham_passed = 0
    ham_total = 0
    ham_false_positives = []

    if ham_dir.exists():
        ham_passed, ham_total, ham_false_positives = run_ham_tests(ham_dir)
        for filepath in sorted([f for f in ham_dir.iterdir() if f.suffix == '.eml']):
            all_email_tuples.append(parse_eml(filepath))

    # ── Phase 5: Edge Case Tests ───────────────────────────────────────────
    # Robustness checks: malformed inputs, boundary values, spoofing attempts.
    # These catch crashes and mis-classifications that .eml tests can't cover.
    print()
    edge_cases_passed = run_edge_case_tests()

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

    # Report edge case results
    if not edge_cases_passed:
        print('❌ EDGE CASES: one or more edge case tests failed')
        all_good = False
    else:
        print('✅ EDGE CASES: all passed')

    # ── Phase 6: Performance Benchmark ────────────────────────────────────
    # Informational only — does not affect pass/fail.
    print()
    run_performance_tests(all_email_tuples)

    # Exit 0 for CI success, 1 for failure
    if all_good:
        print('\n🎉 ALL TESTS PASSED!')
        sys.exit(0)
    else:
        print('\n💥 TESTS FAILED!')
        sys.exit(1)


if __name__ == '__main__':
    main()
