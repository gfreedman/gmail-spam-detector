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
from typing import NamedTuple


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


def _strip_js_comments(text):
    """
    Remove // and /* */ comments from JS source, leaving string literals intact.

    Required before extracting quoted strings with a regex. An apostrophe in a
    prose comment — "// Email service providers' click tracking" — otherwise
    desynchronizes quote pairing and silently corrupts every entry that
    follows. That is not hypothetical: it shipped, and the symptom was a
    46-element LINK_WRAPPER_DOMAINS containing ', ' and ' click tracking\\n  '
    instead of domains, which made the brand-CTA signal false-positive on
    legitimate SendGrid-tracked mail. The element count looked plausible, so no
    cross-check caught it.
    """
    out = []
    i, n = 0, len(text)
    quote = None
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == '\\' and i + 1 < n:      # escaped char inside string
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
        elif ch in ('"', "'"):
            quote = ch
            out.append(ch)
            i += 1
        elif ch == '/' and i + 1 < n and text[i + 1] == '/':
            while i < n and text[i] != '\n':
                i += 1
        elif ch == '/' and i + 1 < n and text[i + 1] == '*':
            end = text.find('*/', i + 2)
            i = n if end == -1 else end + 2
        else:
            out.append(ch)
            i += 1
    return ''.join(out)


def _load_string_array(source, const_name):
    """Extract a JS Object.freeze([...]) string array as a Python list."""
    content = _extract_bracket_content(source, f'const {const_name} = Object.freeze([')
    return _extract_quoted_strings(content, const_name)


def _extract_quoted_strings(content, const_name):
    """
    Pull quoted string literals out of a JS array body, comments removed first.

    Validates that no entry contains whitespace. Every string array in
    SpamDetector.gs holds domains, header fingerprints or hostname labels —
    none of which contain spaces or newlines. A whitespace-bearing entry means
    quote pairing has desynchronized, so fail loudly here rather than let a
    corrupted allowlist silently change detection behaviour.
    """
    values = re.findall(r"""['"]([^'"]+)['"]""", _strip_js_comments(content))
    bad = [v for v in values if re.search(r'\s', v)]
    if bad:
        raise ValueError(
            f'{const_name}: {len(bad)} entries contain whitespace '
            f'(e.g. {bad[0]!r}) — quote pairing desynchronized, '
            f'likely an apostrophe or quote inside a comment'
        )
    return values


def _load_object_of_string_arrays(source, const_name):
    """
    Extract `const NAME = Object.freeze({ key: Object.freeze([...]), ... })`
    as {key: [strings]}.

    This is the shape DEFAULT_DOMAINS and BRAND_CTA_DOMAINS both use, so one
    loader serves both. Keys are discovered from the object body rather than
    hardcoded, so adding a brand in SpamDetector.gs needs no parser change.

    Each key's array is extracted with _extract_bracket_content, whose state
    machine correctly skips regex character classes and string literals when
    tracking bracket depth.

    CONSTRAINT: the object body must contain no { or } characters.
    _extract_brace_content is a naive brace counter that does not skip strings,
    comments or regex literals, so a brace anywhere inside truncates the parse.
    Keep these objects strings-only.
    """
    body = _extract_brace_content(source, f'const {const_name} = Object.freeze({{')

    # Match on the real text rather than reconstructing a marker as
    # f'{key}: Object.freeze(['. Reconstruction assumes exactly one space and
    # breaks the moment someone aligns the values in a column — a brittleness
    # that fails at import time with a confusing "marker not found".
    result = {}
    for m in re.finditer(r'(\w+)\s*:\s*Object\.freeze\(\[', body):
        key = m.group(1)
        content = _extract_bracket_content(body, m.group(0))
        result[key] = _extract_quoted_strings(content, f'{const_name}.{key}')

    # Cross-check, same spirit as _load_regex_array's line count validation:
    # one parsed key per nested Object.freeze([ in the body. A mismatch means
    # the key regex skipped one — fail loudly as a PARSER bug rather than
    # silently under-loading detection data.
    expected = body.count('Object.freeze([')
    if len(result) != expected:
        raise ValueError(
            f'{const_name}: found {expected} nested Object.freeze([ blocks but '
            f'parsed {len(result)} keys — parser may have skipped one'
        )
    return result


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

    return {
        'CLICKBAIT_PATTERNS':           _load_regex_array(source, 'CLICKBAIT_PATTERNS'),
        'BODY_CRYPTO_PATTERNS':         _load_regex_array(source, 'BODY_CRYPTO_PATTERNS'),
        'BODY_FEAR_PATTERNS':           _load_regex_array(source, 'BODY_FEAR_PATTERNS'),
        'BODY_UNICODE_PATTERNS':        _load_regex_array(source, 'BODY_UNICODE_PATTERNS'),
        'FEAR_PATTERNS':                _load_regex_array(source, 'FEAR_PATTERNS'),
        'MARKETING_PATTERNS':           _load_regex_array(source, 'MARKETING_PATTERNS'),
        'BULK_EMAIL_FINGERPRINTS':      _load_string_array(source, 'BULK_EMAIL_FINGERPRINTS'),
        'IMPERSONATION_SUBJECT_PATTERNS': _load_regex_array(source, 'IMPERSONATION_SUBJECT_PATTERNS'),
        'CLOUD_SERVICE_DOMAINS':        _load_string_array(source, 'CLOUD_SERVICE_DOMAINS'),
        'LINK_WRAPPER_DOMAINS':         _load_string_array(source, 'LINK_WRAPPER_DOMAINS'),
        'TRACKER_LABELS':               _load_string_array(source, 'TRACKER_LABELS'),
        'CTA_VERB_PATTERN':             _load_single_regex(source, 'CTA_VERB_PATTERN'),
        'RFC2822_QUOTED_NAME':          _load_single_regex(source, 'RFC2822_QUOTED_NAME'),
        'LIMITS':                       limits,
        # Both parsed by the same generic loader — keys are discovered from the
        # source, not hardcoded, so new brands/domain groups need no edit here.
        'DEFAULT_DOMAINS':              _load_object_of_string_arrays(source, 'DEFAULT_DOMAINS'),
        'BRAND_CTA_DOMAINS':            _load_object_of_string_arrays(source, 'BRAND_CTA_DOMAINS'),
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
BODY_UNICODE_PATTERNS           = _gs['BODY_UNICODE_PATTERNS']
FEAR_PATTERNS                   = _gs['FEAR_PATTERNS']
MARKETING_PATTERNS              = _gs['MARKETING_PATTERNS']
BULK_EMAIL_FINGERPRINTS         = _gs['BULK_EMAIL_FINGERPRINTS']
IMPERSONATION_SUBJECT_PATTERNS  = _gs['IMPERSONATION_SUBJECT_PATTERNS']
CLOUD_SERVICE_DOMAINS           = _gs['CLOUD_SERVICE_DOMAINS']
BRAND_CTA_DOMAINS               = _gs['BRAND_CTA_DOMAINS']
LINK_WRAPPER_DOMAINS            = _gs['LINK_WRAPPER_DOMAINS']
TRACKER_LABELS                  = _gs['TRACKER_LABELS']
CTA_VERB_PATTERN                = _gs['CTA_VERB_PATTERN']
RFC2822_QUOTED_NAME             = _gs['RFC2822_QUOTED_NAME']
WHITELISTED_DOMAINS             = _gs['DEFAULT_DOMAINS']['legitimate']
BLACKLISTED_DOMAINS             = _gs['DEFAULT_DOMAINS']['suspicious']
MAX_DISPLAY_NAME_LENGTH         = _gs['LIMITS']['maxDisplayNameLength']
MAX_INPUT_CHARS                 = _gs['LIMITS']['maxInputChars']
MAX_LOG_CHARS                   = _gs['LIMITS']['maxLogChars']
MAX_HTML_SCAN_CHARS             = _gs['LIMITS']['maxHtmlScanChars']
MAX_ANCHORS_SCANNED             = _gs['LIMITS']['maxAnchorsScanned']
MAX_ANCHOR_TEXT_CHARS           = _gs['LIMITS']['maxAnchorTextChars']


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

# =============================================================================
# Link-Graph Helpers — mirrors of the SpamDetector.gs implementations
#
# These four functions must behave identically to decodeHtmlEntities(),
# extractUrlHost(), hostMatchesDomain() and extractAnchors() in SpamDetector.gs.
# They cannot be loaded from source (they are code, not data), so parity is
# maintained by the shared test tables in run_edge_case_tests(). If you change
# one side, change the other and extend those tables.
# =============================================================================

_ENTITY_HEX = re.compile(r'&#x([0-9a-f]{1,6});', re.I)
_ENTITY_DEC = re.compile(r'&#(\d{1,7});')
_TAG_RE     = re.compile(r'<[^>]{0,2000}>')
_OPEN_TAG   = re.compile(r'<a\s[^>]{0,2000}>', re.I)
_HREF_ATTR  = re.compile(
    r'''\shref\s*=\s*(?:"([^"]{0,2000})"|'([^']{0,2000})'|([^\s"'>]{0,2000}))''', re.I)
_SCHEME_RE  = re.compile(r'^([a-z][a-z0-9+.\-]*):/*', re.I)


def _decode_entity(match, base):
    """Shared body for hex/decimal entity substitution, with a range guard."""
    try:
        cp = int(match.group(1), base)
    except ValueError:
        return ''
    return chr(cp) if 0 < cp <= 0x10FFFF else ''


def _decode_html_entities(text):
    """Mirror of decodeHtmlEntities(). Numeric first, &amp; last (no double-decode)."""
    if not text:
        return ''
    s = _ENTITY_HEX.sub(lambda m: _decode_entity(m, 16), str(text))
    s = _ENTITY_DEC.sub(lambda m: _decode_entity(m, 10), s)
    for ent, rep in (('&nbsp;', ' '), ('&shy;', ''), ('&quot;', '"'),
                     ('&apos;', "'"), ('&lt;', '<'), ('&gt;', '>'), ('&amp;', '&')):
        s = re.sub(ent, rep, s, flags=re.I)
    return s


def _extract_url_host(href):
    """Mirror of extractUrlHost(). See that function for why each step exists."""
    if not href:
        return ''
    s = re.sub(r'[\t\r\n]', '', str(href)).strip()
    if not s:
        return ''
    s = s.replace('\\', '/')

    scheme = _SCHEME_RE.match(s)
    if scheme:
        if scheme.group(1).lower() not in ('http', 'https'):
            return ''
        authority = s[len(scheme.group(0)):]
    elif s[:2] == '//':
        authority = s[2:]
    else:
        return ''

    end = re.search(r'[/?#]', authority)
    if end:
        authority = authority[:end.start()]

    at = authority.rfind('@')          # LAST '@' — browser semantics
    if at != -1:
        authority = authority[at + 1:]

    if authority[:1] == '[':           # IPv6 literal
        close = authority.find(']')
        if close != -1:
            authority = authority[:close + 1]
    else:
        colon = authority.find(':')
        if colon != -1:
            authority = authority[:colon]

    return authority.lower().rstrip('.')


def _host_matches_domain(host, domain):
    """Mirror of hostMatchesDomain(). Exact or dot-suffix — never substring."""
    if not host or not domain:
        return False
    return host == domain or host.endswith('.' + domain)


def _address_matches_domain(address, domain):
    """Mirror of addressMatchesDomain().

    Substring entries are tested against the HOST only — never the full
    address. The local part is attacker-chosen, so matching it made
    'dragonfly' whitelist dragonfly@attacker.tld and 'financebuzz' blacklist
    (hence permanently delete) financebuzz@realcompany.com.
    """
    if not address or not domain:
        return False
    at = address.rfind('@')
    host = (address if at == -1 else address[at + 1:]).lower().rstrip('.')
    if '.' not in domain or '@' in domain:
        if '@' in domain:
            # localpart@hostprefix entries must start the address AND end on a
            # domain-label boundary, or 'customerservice@stan' also whitelists
            # 'customerservice@stanley-evil.com'.
            if not address.startswith(domain):
                return False
            nxt = address[len(domain):len(domain) + 1]
            return nxt == '' or nxt == '.'
        return domain in host
    return _host_matches_domain(host, domain)


def _is_link_wrapper_host(host, sender_host=''):
    """Mirror of isLinkWrapperHost().

    The leftmost-label heuristic is honoured ONLY when the host sits under the
    sender's own domain. Applied globally it was a one-CNAME bypass: a lure at
    r.evil.com or click.evil.com made Signal 7 abstain regardless of who owned
    the parent domain.
    """
    if not host:
        return False
    if any(_host_matches_domain(host, d) for d in LINK_WRAPPER_DOMAINS):
        return True
    if not sender_host:
        return False
    first = host.split('.')[0]
    if first not in TRACKER_LABELS:
        return False
    parent = host[len(first) + 1:]
    return bool(parent) and (_host_matches_domain(parent, sender_host) or
                             _host_matches_domain(sender_host, parent))


def _extract_anchors(html):
    """Mirror of extractAnchors(). Bounded open-tag regex + find() for the close."""
    out = []
    if not html:
        return out

    scan = html[:MAX_HTML_SCAN_CHARS] if len(html) > MAX_HTML_SCAN_CHARS else html

    for m in _OPEN_TAG.finditer(scan):
        if len(out) >= MAX_ANCHORS_SCANNED:
            break
        h = _HREF_ATTR.search(m.group(0))
        if not h:
            continue
        href = h.group(1) if h.group(1) is not None else (
            h.group(2) if h.group(2) is not None else h.group(3))
        if not href:
            continue

        text_start = m.end()
        close_idx = scan.find('</a', text_start)
        cap = min(text_start + MAX_ANCHOR_TEXT_CHARS, len(scan))
        text_end = cap if (close_idx == -1 or close_idx > cap) else close_idx

        inner = _TAG_RE.sub('', scan[text_start:text_end])
        text = re.sub(r'\s+', ' ', _decode_html_entities(inner)).strip()
        out.append({'href': _decode_html_entities(href), 'text': text})

    return out


def _has_brand_mismatched_cta(html, sender_address):
    """Mirror of hasBrandMismatchedCta(). See that function for the four conditions."""
    if not html or '<a' not in html:
        return False

    at = sender_address.rfind('@') if sender_address else -1
    sender_host = '' if at == -1 else sender_address[at + 1:]

    for anchor in _extract_anchors(html):
        text = anchor['text']
        if not text:
            continue
        if not CTA_VERB_PATTERN.search(text):
            continue

        norm_text = re.sub(r'[^a-z0-9]+', '', text.lower())
        # Bound measured on the NORMALIZED text. Raw length was evadable two
        # ways: padding with U+200B (category Cf, which neither Python nor JS
        # \s matches, so it survived whitespace collapsing and inflated the
        # raw count) and plain verbosity — a natural 67-char label slipped
        # through. Counting only alphanumerics defeats both.
        if len(norm_text) > 80:
            continue

        for brand, legit in BRAND_CTA_DOMAINS.items():
            if brand not in norm_text:
                continue
            host = _extract_url_host(anchor['href'])
            if not host:
                break
            if any(_host_matches_domain(host, d) for d in legit):
                break
            if _is_link_wrapper_host(host, sender_host):
                break
            if sender_host and (_host_matches_domain(host, sender_host) or
                                _host_matches_domain(sender_host, host)):
                break
            return True

    return False


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


class ParsedEmail(NamedTuple):
    """
    Fields extracted from an .eml, mirroring what collectSignals() reads.

    A NamedTuple rather than a bare tuple: this shape has grown three times
    (body, has_attachment, html) and each growth silently broke every unpack
    site with an arity error at runtime. Named access means the next field is
    free. Field order matches analyze_email()'s positional parameters so
    analyze_email(*parsed) stays valid, but prefer named access at call sites.
    """
    subject: str
    from_field: str
    has_bulk_service: bool
    body: str
    has_attachment: bool
    html: str


def parse_eml(filepath):
    """
    Parse an .eml file and extract the fields needed for spam analysis.

    Reads the file twice: once as a structured email (for decoded headers) and
    once as raw text (to check for bulk email service signatures in headers
    that the email library doesn't expose).

    Args:
        filepath: Path to the .eml file.

    Returns:
        A ParsedEmail. `html` is the raw, UNSTRIPPED HTML part — required by
        the brand-CTA signal, which needs anchor hrefs paired with link text.
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

    # Raw HTML part, retained UNSTRIPPED — mirrors message.getBody() in GS.
    #
    # Collected in its own independent pass, NOT bolted onto the `if not body`
    # fallback below. A multipart/alternative message with a text/plain part
    # never reaches that fallback, so hanging `html` off it would silently
    # yield '' for most real email — including the brand-CTA phish fixture,
    # leaving the new signal dead in the harness while live in production.
    #
    # Parity note: GAS getBody() on a plain-text-only message returns the
    # HTML-escaped plain text, whereas this returns ''. Inert for an anchor
    # scan (plain text has no <a href>), but don't "fix" it without checking.
    html = ''
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/html' and not part.get_content_disposition():
                html = part.get_content()
                break
    elif msg.get_content_type() == 'text/html':
        html = msg.get_content()

    # HTML fallback for multipart messages with no text/plain part
    if not body and html:
        body = re.sub(r'<[^>]+>', ' ', html)
        body = re.sub(r'\s+', ' ', body).strip()

    return ParsedEmail(subject, from_field, has_amazon_ses, body, has_attachment, html)


def analyze_email(subject, from_field, has_amazon_ses, body='', has_attachment=False, html=''):
    """
    Run the detection logic against a single email's fields.

    Mirrors the analyzeMessage() function in SpamDetector.gs. Collects signals
    from multiple pattern categories, then applies the 7-rule decision logic.

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
        8. Apply 7-rule decision logic (rules evaluated in priority order)

    Args:
        subject:        Decoded email subject line.
        from_field:     Decoded From header (display name + email address).
        has_amazon_ses: Whether bulk email service signatures were found.
        body:           Plain-text body for body-only pattern checks.
        has_attachment: Whether the message has one or more attachments.
        html:           Raw HTML body, for the link-graph (brand-CTA) signal.

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
    # Strict domain matching — NOT `domain in sender_address`. Substring
    # matching here was a full detection bypass: "mail@linkedin.com.secure-
    # login.top" and "a@notlinkedin.com" both contain "linkedin.com".
    for domain in WHITELISTED_DOMAINS:
        if _address_matches_domain(sender_address, domain):
            return {'bulk_email': has_amazon_ses, 'blacklisted_sender': False,
                    'clickbait_count': 0, 'fear_mongering': False,
                    'marketing_format': False, 'suspicious_from_name': False,
                    'empty_subject_with_attachment': False,
                    'service_impersonation': False,
                    'brand_mismatched_cta': False,
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
        'brand_mismatched_cta': False,
        'matched_patterns': []          # Audit trail of which patterns fired
    }

    # Concatenate subject + from for pattern matching (same as SpamDetector.gs)
    text_to_check = subject + ' ' + from_field
    from_lower = from_field.lower()

    # ── Signal: Blacklisted sender domain ──────────────────────────────────
    # Substring match against known spam mill domains (one match is enough).
    # Use sender_address (email only, not display name) — mirrors SpamDetector.gs.
    for domain in BLACKLISTED_DOMAINS:
        if _address_matches_domain(sender_address, domain):
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

    # ── Signal: Unicode obfuscation in body ────────────────────────────────
    # Cyrillic/Greek/fullwidth/math-alphanumeric characters hidden in body
    # anchors while the subject stays clean. Break after the first match: all
    # patterns detect the same technique, so counting them independently would
    # over-inflate clickbait_count. Mirrors Signal 2d in SpamDetector.gs.
    #
    # This block was MISSING from the harness entirely (added with the v6.42.0
    # brand-CTA work). BODY_UNICODE_PATTERNS shipped in v6.39.0 and was applied
    # in production but never loaded here, so clickbait_count could read one
    # lower in Python than in GAS — ham could pass CI while production
    # false-positived, and vice versa. The single-source-of-truth property was
    # silently broken for three releases.
    for i, pattern in enumerate(BODY_UNICODE_PATTERNS):
        if pattern.search(body):
            signals['clickbait_count'] += 1
            signals['matched_patterns'].append(f'body_unicode[{i}]')
            break

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

    # ── Signal: Brand-mismatched CTA phishing ──────────────────────────────
    # A button naming DocuSign/Adobe Sign/SharePoint whose href the brand does
    # not control. The only signal that reads the LINK GRAPH rather than
    # sender-side vocabulary — which is how it reaches phishing that carries no
    # clickbait, no urgency and a valid DKIM signature for its own domain.
    if _has_brand_mismatched_cta(html, sender_address):
        signals['brand_mismatched_cta'] = True
        signals['matched_patterns'].append('brand_mismatched_cta')

    # ── Decision Logic (7 rules, evaluated in priority order) ──────────────
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

        # Rule 7: Brand-mismatched CTA phishing (no bulk email required)
        #   Rationale: a CTA naming a document brand that resolves to a host
        #   the brand does not control has no legitimate form. Click-trackers,
        #   link-wrappers and sender-aligned hosts are already exempted inside
        #   the signal, so what reaches here is an unexplained mismatch.
        elif signals['brand_mismatched_cta']:
            is_spam = True
            rule = 'RULE 7: Brand-mismatched CTA phishing'

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

    # ── _strip_js_comments ─────────────────────────────────────────────────
    # An apostrophe in a prose comment must not affect quoted-string
    # extraction. This is the exact shape that silently corrupted
    # LINK_WRAPPER_DOMAINS into 46 punctuation fragments.
    src_apos = ("  // Email service providers' click tracking\n"
                "  'sendgrid.net', 'awstrack.me'\n")
    got_apos = _extract_quoted_strings(src_apos, 'TEST')
    if got_apos != ['sendgrid.net', 'awstrack.me']:
        failures.append(f"  apostrophe in comment corrupted extraction: {got_apos!r}")

    # A // sequence INSIDE a string literal must survive comment stripping.
    if _strip_js_comments("""x = 'https://a.com'; // note""").strip() != "x = 'https://a.com';":
        failures.append('  // inside a string literal was stripped as a comment')

    # Block comments too.
    if _extract_quoted_strings("/* don't */ 'a.com'", 'TEST') != ['a.com']:
        failures.append('  block comment with apostrophe corrupted extraction')

    # Whitespace-bearing entries must raise rather than load silently.
    try:
        _extract_quoted_strings("' bad entry '", 'TEST')
        failures.append('  whitespace-bearing entry should raise ValueError')
    except ValueError:
        pass  # Expected

    # ── _load_object_of_string_arrays ──────────────────────────────────────
    src3 = ("const MAP = Object.freeze({\n"
            "  docusign:    Object.freeze(['docusign.net', 'docusign.com']),\n"
            "  adobesign: Object.freeze(['adobesign.com'])\n"
            "});")
    got3 = _load_object_of_string_arrays(src3, 'MAP')
    if sorted(got3) != ['adobesign', 'docusign']:
        failures.append(f'  object-of-arrays keys: {sorted(got3)!r}')
    if got3.get('docusign') != ['docusign.net', 'docusign.com']:
        failures.append(f'  object-of-arrays values: {got3.get("docusign")!r}')

    # DEFAULT_DOMAINS must round-trip identically through the generic loader —
    # the guard that replacing its two hardcoded markers changed nothing.
    _dd = _load_object_of_string_arrays(_GS_PATH.read_text(encoding='utf-8'),
                                        'DEFAULT_DOMAINS')
    if _dd.get('legitimate') != WHITELISTED_DOMAINS:
        failures.append('  DEFAULT_DOMAINS.legitimate differs via generic loader')
    if _dd.get('suspicious') != BLACKLISTED_DOMAINS:
        failures.append('  DEFAULT_DOMAINS.suspicious differs via generic loader')

    # ── BRAND_CTA_DOMAINS shape contract ───────────────────────────────────
    # Anchor text is normalized to [a-z0-9] before matching, so a key holding a
    # space or capital could never match anything. Enforce mechanically rather
    # than trusting a comment.
    if not BRAND_CTA_DOMAINS:
        failures.append('  BRAND_CTA_DOMAINS is empty')
    bad_keys = [k for k in BRAND_CTA_DOMAINS if not re.fullmatch(r'[a-z0-9]+', k)]
    if bad_keys:
        failures.append(f'  brand keys must be [a-z0-9]+ only: {bad_keys!r}')
    bad_doms = [d for ds in BRAND_CTA_DOMAINS.values() for d in ds
                if not re.fullmatch(r'[a-z0-9-]+(\.[a-z0-9-]+)+', d)]
    if bad_doms:
        failures.append(f'  brand domains must be bare hostnames: {bad_doms!r}')

    # Wrapper domains and tracker labels must be bare too — a scheme or path
    # here would silently never match a host from extractUrlHost().
    bad_wrap = [d for d in LINK_WRAPPER_DOMAINS
                if not re.fullmatch(r'[a-z0-9-]+(\.[a-z0-9-]+)+', d)]
    if bad_wrap:
        failures.append(f'  LINK_WRAPPER_DOMAINS must be bare hostnames: {bad_wrap!r}')
    bad_lab = [l for l in TRACKER_LABELS if not re.fullmatch(r'[a-z0-9-]+', l)]
    if bad_lab:
        failures.append(f'  TRACKER_LABELS must be single labels: {bad_lab!r}')

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
        parsed = parse_eml(filepath)
        subject, from_field = parsed.subject, parsed.from_field
        signals, is_spam, rule = analyze_email(*parsed)

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
        parsed = parse_eml(filepath)
        subject, from_field = parsed.subject, parsed.from_field
        signals, is_spam, rule = analyze_email(*parsed)

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
        for parsed in all_emails:
            t0 = time.perf_counter()
            analyze_email(*parsed)
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

    # ── URL host extraction: the bypass table ──────────────────────────────
    # Security-critical parsing. Each row is a real technique for making a
    # host look like one thing to a filter and another to a mail client. Keep
    # in sync with the identical table in the Node test for SpamDetector.gs.
    for href, expected in [
        ('https://cptlbpolicy.com/',       'cptlbpolicy.com'),
        # userinfo: browsers resolve this to evil.com, so we must too
        ('https://docusign.net@evil.com/', 'evil.com'),
        ('https://a@b@evil.com/',          'evil.com'),
        # suffix bug: must NOT be treated as docusign.net
        ('https://docusign.net.evil.com/', 'docusign.net.evil.com'),
        ('https://EU.DocuSign.NET:443/x',  'eu.docusign.net'),
        ('https://docusign.net./',         'docusign.net'),
        ('//docusign.net/x',               'docusign.net'),
        ('https:evil.com',                 'evil.com'),
        ('https:\\\\evil.com',             'evil.com'),
        ('https://ev\til.com',             'evil.com'),
        ('mailto:x@docusign.net',          ''),
        ('javascript:alert(1)',            ''),
        ('#anchor',                        ''),
        ('/relative/path',                 ''),
        ('',                               ''),
        ('https://[2001:db8::1]:8443/x',   '[2001:db8::1]'),
    ]:
        got = _extract_url_host(href)
        check(f'extractUrlHost({href!r}) → {expected!r}', got == expected,
              f'got {got!r}')

    for host, dom, want in [
        ('docusign.net',          'docusign.net', True),
        ('eu.docusign.net',       'docusign.net', True),
        ('notdocusign.net',       'docusign.net', False),   # prefix bug
        ('docusign.net.evil.com', 'docusign.net', False),   # suffix bug
        ('evil.com',              'docusign.net', False),
    ]:
        check(f'hostMatchesDomain({host!r}, {dom!r}) is {want}',
              _host_matches_domain(host, dom) == want)

    # ── Whitelist bypass regression ────────────────────────────────────────
    # Substring matching here was a total detection bypass.
    for addr, want in [
        ('mail@linkedin.com.secure-login.top', False),
        ('a@notlinkedin.com',                  False),
        ('news@linkedin.com',                  True),
        ('news@e.linkedin.com',                True),
    ]:
        check(f'addressMatchesDomain({addr!r}, linkedin.com) is {want}',
              _address_matches_domain(addr, 'linkedin.com') == want,
              'substring matching here bypasses ALL detection')

    signals, is_spam, _ = analyze_email(
        'URGENT: account TERMINATED - act NOW!!!',
        'Breaking News <mail@linkedin.com.secure-login.top>', True,
        'wallet drainer airdrop claim your bitcoin now')
    check('lookalike whitelist domain no longer bypasses detection',
          'whitelisted' not in signals['matched_patterns'] and is_spam,
          'a domain merely CONTAINING a whitelisted string must not be trusted')

    # ── Brand-mismatched CTA ───────────────────────────────────────────────
    signals, _, rule = analyze_email(
        'Capital B | Bitcoin Policy Brief', 'Capital B <info@cptlbnews.press>', True,
        html='<a href="https://cptlbpolicy.com/">VIEW IN DOCUSIGN&#x2192;</a>')
    check('brand-mismatched CTA → Rule 7 phishing',
          signals['brand_mismatched_cta'] and rule.startswith('RULE 7'))

    signals, _, _ = analyze_email(
        'Complete with DocuSign', 'DocuSign <dse@docusign.net>', False,
        html='<a href="https://eu.docusign.net/Signing?a=1"><span>VIEW IN '
             '<span>DOCUSIGN</span></span></a>')
    check('genuine docusign.net CTA does not fire',
          not signals['brand_mismatched_cta'],
          'real DocuSign mail must never be flagged')

    signals, _, _ = analyze_email(
        'Invoice ready', 'Vendor <billing@vendor.ca>', True,
        html='<a href="https://u88.ct.sendgrid.net/ls/click?upn=x">View in DocuSign</a>')
    check('ESP-wrapped brand CTA abstains',
          not signals['brand_mismatched_cta'],
          'a click-tracker hides the destination — unverifiable, not malicious')

    signals, _, _ = analyze_email(
        'Sign please', 'Acme <a@acme.com>', False,
        html='<a href="https://click.acme.com/x">Review in DocuSign</a>')
    check('CNAMEd tracker label abstains', not signals['brand_mismatched_cta'])

    signals, _, _ = analyze_email(
        'About us', 'X <a@b.com>', False,
        html='<a href="https://evil.com/">About DocuSign</a>')
    check('brand in prose without a CTA verb does not fire',
          not signals['brand_mismatched_cta'],
          'a genuine DocuSign footer says "About DocuSign"')

    signals, _, _ = analyze_email(
        'x', 'X <a@b.com>', False,
        html='<a href="https://evil.com/">Open D&#111;cu&shy;Sign</a>')
    check('entity-obfuscated brand name still detected',
          signals['brand_mismatched_cta'],
          'entity decoding is load-bearing, not cosmetic')

    signals, _, _ = analyze_email(
        'x', 'X <a@b.com>', False,
        html='<a href="https://evil.com/">View <span>Docu</span><span>Sign</span></a>')
    check('brand split across nested elements still detected',
          signals['brand_mismatched_cta'])

    signals, _, _ = analyze_email(
        'x', 'Acme <a@acme.com>', False,
        html='<a href="https://sign.acme.com/x">View in DocuSign</a>')
    check('sender-aligned host abstains', not signals['brand_mismatched_cta'],
          'a company linking its own infrastructure impersonates no one')

    signals, _, _ = analyze_email(
        'x', 'X <a@b.com>', False,
        html='<a href="https://docusign.net@evil.com/">Review in DocuSign</a>')
    check('userinfo-disguised host still detected',
          signals['brand_mismatched_cta'])

    # ── Anchor scan bounds (ReDoS) ─────────────────────────────────────────
    # An unclosed <a> is tolerated by mail clients, so a paired-tag regex
    # scanning to end-of-document per anchor is attacker-reachable and
    # polynomial. These assert the bound holds.
    pathological = '<a href="https://evil.com/">DOCUSIGN' * 900
    t0 = time.perf_counter()
    signals, _, _ = analyze_email('hi', 'x@y.com', False, html=pathological)
    elapsed = time.perf_counter() - t0
    check('900 unclosed anchors complete in < 250ms', elapsed < 0.25,
          f'took {elapsed * 1000:.0f}ms — anchor scan may be unbounded')
    check('anchor count is bounded by LIMITS',
          len(_extract_anchors(pathological)) <= MAX_ANCHORS_SCANNED)

    huge = 'x' * 500000 + '<a href="https://evil.com/">View in DocuSign</a>'
    t0 = time.perf_counter()
    analyze_email('hi', 'x@y.com', False, html=huge)
    elapsed = time.perf_counter() - t0
    check('500KB body completes in < 250ms', elapsed < 0.25,
          f'took {elapsed * 1000:.0f}ms')

    # ── Parity cases with tests/test_link_graph.js ─────────────────────────
    # These mirror rows in the JS suite. The Python helpers are a hand-written
    # mirror of the .gs implementations, so a fix applied to one side and not
    # the other is the expected failure mode — it happened once already, and a
    # new scam fixture caught it. Keep both tables in step.
    for addr, dom, want in [
        ('dragonfly@attacker.tld',           'dragonfly',            False),
        ('a@dragonfly-evil.ru',              'dragonfly',            True),
        ('financebuzz@realcompany.com',      'financebuzz',          False),
        ('x@news.financebuzz.com',           'financebuzz',          True),
        ('customerservice@stanley-evil.com', 'customerservice@stan', False),
        ('customerservice@stan.com',         'customerservice@stan', True),
    ]:
        check(f'addressMatchesDomain({addr!r}, {dom!r}) is {want}',
              _address_matches_domain(addr, dom) == want,
              'the local part is attacker-chosen — substring entries must test the host')

    for label in ('r', 'go', 'click', 't', 'e', 'em', 'link', 'url'):
        signals, _, _ = analyze_email(
            'x', 'Capital B <info@cptlbnews.press>', True,
            html=f'<a href="https://{label}.cptlbpolicy.com/">VIEW IN DOCUSIGN</a>')
        check(f'tracker label on attacker domain fires: {label}.cptlbpolicy.com',
              signals['brand_mismatched_cta'],
              'one CNAME must not defeat Signal 7')

    signals, _, _ = analyze_email(
        'x', 'Acme <billing@acme.com>', True,
        html='<a href="https://click.acme.com/x">View in DocuSign</a>')
    check('sender-owned CNAMEd tracker still abstains',
          not signals['brand_mismatched_cta'])

    signals, _, _ = analyze_email(
        'x', 'Ironclad <n@ironclad.com>', False,
        html='<a href="https://app.ironcladapp.com/x">Sign Now</a>')
    check('"Sign Now" does not fire (signnow key removed)',
          not signals['brand_mismatched_cta'],
          'normalisation collapses "Sign Now" to "signnow"')

    signals, _, _ = analyze_email(
        'x', 'X <a@b.com>', False,
        html='<a href="https://evil.com/">Please review and open your secure '
             'DocuSign document envelope today</a>')
    check('67-char natural CTA label fires', signals['brand_mismatched_cta'],
          'the length bound must be measured on normalised text')

    signals, _, _ = analyze_email(
        'x', 'News <e@news.com>', False,
        html='<a href="https://news.example.com/">This newsletter discusses how '
             'DocuSign and other electronic signature vendors approach compliance '
             'review across regulated industries today</a>')
    check('long prose mentioning the brand still abstains',
          not signals['brand_mismatched_cta'])

    check('entity decoding does not double-decode',
          _decode_html_entities('&amp;#47;') == '&#47;',
          'double-decoding hands the attacker a free layer of indirection')
    check('out-of-range codepoint does not raise',
          _decode_html_entities('a&#1114112;b') == 'ab')

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
