#!/usr/bin/env python3
"""
Test suite for SpamDetector v6.

Validates the spam detection engine against real-world .eml samples and ensures
the deployed Google Apps Script only calls methods that actually exist on the
Gmail Advanced Service API.

Three test phases run in order:
    1. Gmail API method validation — static analysis of SpamDetector.gs
    2. Spam detection — every .eml in spam_examples/ must be flagged
    3. Ham verification — every .eml in ham_examples/ must NOT be flagged

Exit codes:
    0 — all tests passed
    1 — one or more tests failed (CI will block deploy)
"""

import os
import re
import sys
import email
from email import policy
from email.header import decode_header
from pathlib import Path


# =============================================================================
# Detection Patterns (mirrored from SpamDetector.gs)
#
# These MUST stay in sync with the patterns in the Apps Script source.
# Each pattern targets a *category* of spam tactic, not specific phrases.
# =============================================================================

# --- Clickbait / Sensationalism Patterns ---
# Matched against the concatenation of subject + from field.
# Each hit increments clickbait_count by 1.
CLICKBAIT_PATTERNS = [
    # Sensationalist adjectives: shocking, bizarre, bombshell, etc.
    re.compile(r'\b(shocking|stunning|bizarre|mysterious|secret|hidden|leaked|exposed|forbidden|bombshell)\b', re.I),
    # Terrifying/alarming adjectives (often stuffed into From display names)
    re.compile(r'\b(terrifying|alarming|devastating|horrifying|frightening|chilling|disturbing)\b', re.I),
    # Curiosity gap: mystery word + visual/media word ("secret photo", "leaked footage")
    re.compile(r'(strange|secret|hidden|mysterious|shocking|bizarre|unusual|leaked).*(picture|photo|image|video|camera|footage|document)', re.I),
    # Urgency + sensationalism: "breaking news", "urgent warning", etc.
    re.compile(r'(breaking|urgent|warning|alert|stop|exposed|banned).*(news|truth|secret|scandal|exposed|revealed)', re.I),
    # Financial fear-mongering: market/money word + crisis word
    re.compile(r'(market|stock|economy|dollar|gold|bitcoin|investment|crypto).*(crash|collapse|shift|crisis|warning|alert|plunge|tank|dying)', re.I),
    # "Caught" visual-proof framing: "caught on camera", "caught red-handed"
    re.compile(r'caught (on|doing|in|red-handed)', re.I),
    # Transformation clickbait: "this changes everything", "what stunned everyone"
    re.compile(r'(what|this).*(changes everything|stunned everyone|shocked|amazed|surprised)', re.I),
    # Celebrity/political name-dropping for false credibility
    re.compile(r'\b(RFK|Trump|Biden|Musk|Elon|Kennedy|Obama|Fauci|Gates)\b.*(warning|says|reveals|exposes|issues|predicts|warns|showed|shows)', re.I),
    # Political legitimization: "Trump approved/signed/backed [product]"
    re.compile(r'\b(Trump|Biden|Obama|Musk|Kennedy|RFK)\b.*(approved|signed|backed|endorsed|directed|ordered|mandated)', re.I),
    # Celebrity merchandise/collectible scams
    re.compile(r'\b(Trump|Biden|Obama|Kennedy)\b.*(coin|bill|medal|card|stamp|legacy|commemorat|collect|mint|gold|silver)', re.I),
    # Demographic targeting: age-based fear ("Seniors Most At Risk")
    re.compile(r'\b(seniors?|elderly|retirees?|boomers?|over \d{2}|born before|age \d{2})\b.*(risk|warning|alert|danger|affected|target)', re.I),
    # Year-based urgency: current year + threat word ("2026 Warning")
    re.compile(r'\b202[4-9]\b.*(warning|alert|prediction|forecast|crisis)', re.I),
    # Conspiracy/hiding: "what they don't want you to know"
    re.compile(r'(what|who).*(hiding|don\'t want you|truth|they won\'t tell)', re.I),
    # Impending doom framing: "What's Coming", "Not Prepared for what's ahead"
    re.compile(r"\bwhat.s (coming|ahead)\b|\bnot prepared\b", re.I),
    # Military/war sensationalism: "declared war", "bombing", "invasion"
    re.compile(r'\b(declared war|bombed|bombing|attack|attacked|destroyed|invasion)\b', re.I),
    # Pre-IPO investment solicitation: always spam in bulk email
    re.compile(r'\bpre-?ipo\b', re.I),
    # Stock price hype: "$5 a share", "$0.85 per share", "penny stock"
    re.compile(r'\$\d+(\.\d+)?\s*(?:(?:a|per)\s+)?share|\bpenny stock\b', re.I),
    # Watch/see curiosity gap: "watch what happened", "see this"
    re.compile(r'\b(watch|see)\s+(what|this|the moment)', re.I),

    # --- Structural / Formatting Indicators ---
    re.compile(r'【.*】'),           # Japanese-style brackets (spammer tactic)
    re.compile(r'\[.{3,}[?!]\]'),    # Square brackets with punctuation: [Like This?]
    re.compile(r'💼|📸|⏯️|🚨|⚠️|📰|💰|⚡'),  # Sensationalist emoji
    re.compile(r'\?\?\?|!!!'),       # Triple punctuation (urgency tactic)
    re.compile(r'\u2026|\.{3,}'),    # Ellipsis dramatic pause (Unicode … or ASCII ...)
    re.compile(r'\bWATCH\b.*\?$', re.I),  # "WATCH ...?" clickbait structure

    # --- Unicode Obfuscation (filter evasion) ---
    re.compile(r'[\u0400-\u04FF]'),          # Cyrillic lookalikes ("Еlоn" with Cyrillic Е, о)
    re.compile(r'[\u0370-\u03FF]'),          # Greek lookalikes ("Βanks" with Greek Β)
    re.compile(r'[\uFF00-\uFFEF]'),          # Fullwidth chars ("＄2 Bill") — never legit in English
    re.compile(r'[\U0001D400-\U0001D7FF]'),  # Mathematical bold/italic ("𝗔𝗺𝗮𝘇𝗼𝗻")
    re.compile(r'[\u2215\u2044\u29F8]'),     # Lookalike slash chars (division/fraction slash)

    # --- Topic-Specific Spam Categories ---
    # Jobs/employment fear: "jobs disappeared", "layoffs"
    re.compile(r'\b(jobs?|employment).*(disappeared|vanished|never existed|fake|fraud|layoffs?)', re.I),
    # Bank/branch closing fear: "banks closing", "ATMs shutting down"
    re.compile(r'\b(banks?|branch|branches|ATMs?).*(clos|shut|disappear|eliminat)', re.I),
    # Building/institution emoji (banks, hospitals)
    re.compile(r'🏦|🏥|🏛️|🏢'),
    # Collectible/commemorative scams: "limited edition", "rare coin"
    re.compile(r'\b(minted|commemorat|collector\'?s?|limited edition|rare coin|gold.?plated|silver.?plated)\b', re.I),
    # Bullet-point date format: "• January 29 •" (newsletter spam tactic)
    re.compile(r'•\s*(January|February|March|April|May|June|July|August|September|October|November|December)\b', re.I),
    # Pipe-date subject format: "| February 23" (same tactic, pipe variant)
    re.compile(r'\|\s*(January|February|March|April|May|June|July|August|September|October|November|December)\b', re.I),
    # Bracket-date subject format: "[March 09]" — same tactic, bracket variant
    re.compile(r'\[\s*(January|February|March|April|May|June|July|August|September|October|November|December)\b', re.I),
    # Dash-date subject format: "- Mar 11, 2026" — same tactic, dash variant with abbreviated months
    re.compile(r'[-]\s*(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b', re.I),
    # Historical atrocity clickbait: Nazi/Holocaust references as engagement bait
    re.compile(r'\b(nazi|hitler|auschwitz|gestapo|mengele|third reich)\b', re.I),
    # Health condition anxiety triggers: "blood sugar", "brain fog", etc.
    re.compile(r'\b(fatigue|insomnia|inflammation|blood sugar|cholesterol|blood pressure|joint pain|brain fog|belly fat)\b', re.I),
    # Financial scam products: gift cards, tax liens, instant approval
    re.compile(r'\b(gift card|tax lien|tax sale|foreclosure list|pre-?approved|instant approval|no annual fee)\b', re.I),
    # "Now you can see/watch" exclusive access clickbait
    re.compile(r'\bnow you can (see|watch|view|get)\b', re.I),
    # Financial product solicitation: "0% APR", "balance transfer"
    re.compile(r'\b(0\s*%\s*(interest|apr)|balance transfer|transfer your.*(balance|debt))\b', re.I),
]

# --- Fear-Mongering Patterns ---
# Matched against subject + from. A single hit sets fear_mongering = True.
FEAR_PATTERNS = [
    # Government fear: IRS/NSA/FBI + threat/revelation verb
    re.compile(r'\b(IRS|NSA|FBI|CIA|government|federal)\b.*(warn|hiding|secret|spy|track|audit|investigation|admission|reveal|expose|confiscat)', re.I),
    # Financial fear: bank/money terms + seizure/theft verbs
    re.compile(r'\b(banks?|bank account|credit card|social security|identity|savings|cash|money)\b.*(seize|steal|stolen|hacked|freeze|frozen|close|closed|warning|alert|confiscat|take|taking|lost)', re.I),
    # Health fear: medical terms + danger verbs
    re.compile(r'\b(blood thinner|medication|drug|vaccine|doctor|FDA|health crisis|at risk)\b.*(warning|danger|deadly|killing|risk|avoid|corrupt)', re.I),
    # Standalone urgency words: "WARNING", "ALERT", "BREAKING"
    re.compile(r'\b(warning|alert|urgent|breaking|exposed|banned|stopped)\b', re.I),
    # "STOP using/taking" imperative pattern
    re.compile(r'\bSTOP (using|taking|doing|buying)\b', re.I),
]

# --- Blacklisted Sender Domains ---
# Known spam mill domains. Substring-matched against the From field.
BLACKLISTED_DOMAINS = [
    'financeinsiderpro.com', 'financebuzz', 'smartinvestmenttools',
    'investorplace', 'weissratings', 'americanprofitinsight.com',
    'saferetirementreports.com', 'thinkrichtoday.com',
    'brightcrestcapital.com', 'turbotradepro.com',
    'budgetingjournals.com', 'investorbusinesstalk.com',
    'expertmodernadvice',
    'investingtrendstoday',
    'smartpeoplemail',
    'onlineinvestingdaily',
    'beststockvillage',
]

# --- Marketing Sender Format Patterns ---
# Matched against the From field only. Detects spammy sender name formatting.
MARKETING_PATTERNS = [
    re.compile(r'["|,]\s*[A-Z]', re.I),      # "Name | Org" or "Topic, Company"
    re.compile(r'\s+at\s+[A-Z]', re.I),       # "Name at Organization"
    re.compile(r'\|\s*'),                       # Pipe separator in display name
    re.compile(r'\b(investment|trading|wealth|profit|finance|insider|market)\s*(tools?|pro|tips?|alert)', re.I),  # Spammy business names
    re.compile(r'grow@with\.', re.I),           # Suspicious email pattern
    re.compile(r'@[a-z]\.[a-z]+\.(com|net)', re.I),  # Subdomain pattern (@F.FinanceInsiderPro.com)
]


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
        Tuple of (subject, from_field, has_bulk_service) where:
            - subject: Decoded subject line
            - from_field: Decoded From header (display name + address)
            - has_bulk_service: True if Amazon SES or SendGrid signatures found
    """
    # Parse structured email for decoded headers (Subject, From, etc.)
    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    # Re-read as raw text — bulk service indicators (amazonses.com, sendgrid.net)
    # live in Received/Return-Path headers that the email library doesn't decode
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Case-insensitive check for bulk email service fingerprints
    content_lower = content.lower()
    has_amazon_ses = 'amazonses.com' in content_lower or 'sendgrid.net' in content_lower

    # Decode headers (handles RFC 2047 encoded-words like =?utf-8?B?...?=)
    subject = decode_email_header(msg.get('subject', ''))
    from_field = decode_email_header(msg.get('from', ''))

    return subject, from_field, has_amazon_ses


def analyze_email(subject, from_field, has_amazon_ses):
    """
    Run the v6 detection logic against a single email's fields.

    Mirrors the analyzeMessage() function in SpamDetector.gs. Collects signals
    from multiple pattern categories, then applies the 4-rule decision logic.

    The detection pipeline:
        1. Check sender against blacklisted domains
        2. Inspect From display name for suspicious formatting
        3. Count clickbait pattern matches in subject + from
        4. Check for fear-mongering language
        5. Check for marketing sender format
        6. Apply 4-rule decision logic (rules evaluated in priority order)

    Args:
        subject:        Decoded email subject line.
        from_field:     Decoded From header (display name + email address).
        has_amazon_ses: Whether bulk email service signatures were found.

    Returns:
        Tuple of (signals, is_spam, rule) where:
            - signals: Dict of all detected signal values and matched patterns
            - is_spam: Boolean verdict
            - rule: String describing which rule triggered (empty if not spam)
    """
    # Initialize signal accumulators — each detection phase populates one signal
    signals = {
        'bulk_email': has_amazon_ses,
        'blacklisted_sender': False,
        'clickbait_count': 0,
        'fear_mongering': False,
        'marketing_format': False,
        'suspicious_from_name': False,
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
    if '•' in display_name or len(display_name) > 50:
        signals['suspicious_from_name'] = True
        signals['matched_patterns'].append('suspicious_from')

    # Subject echo: 2+ significant words (4+ chars) from subject appear in From display name
    if not signals['suspicious_from_name'] and subject and display_name:
        subject_words = re.findall(r'\b[a-z]{4,}\b', subject.lower())
        from_name_lower = display_name.lower()
        # Word-boundary match — prevents "mission" matching inside "missioncreekah"
        echo_count = sum(1 for w in subject_words if re.search(r'\b' + w + r'\b', from_name_lower))
        if echo_count >= 2:
            signals['suspicious_from_name'] = True
            signals['matched_patterns'].append('subject_echo')

    # ── Signal: Clickbait pattern count ────────────────────────────────────
    # Each matching pattern increments the counter independently — this allows
    # Rule 1 (bulk + 2 clickbait) and Rule 3 (3+ clickbait alone) to trigger
    for i, pattern in enumerate(CLICKBAIT_PATTERNS):
        if pattern.search(text_to_check):
            signals['clickbait_count'] += 1
            signals['matched_patterns'].append(f'clickbait[{i}]')

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

    # ── Decision Logic (4 rules, evaluated in priority order) ──────────────
    #
    # The rules cascade from most-specific (Rule 0) to broadest (Rule 3).
    # Only one rule can fire per email. This matches SpamDetector.gs exactly.
    is_spam = False
    rule = ''

    # Rule 0: Bulk email + blacklisted sender = definitive spam
    #   Rationale: Known spam domain + bulk infrastructure = no false positives
    if signals['bulk_email'] and signals['blacklisted_sender']:
        is_spam = True
        rule = 'RULE 0: Bulk + blacklisted sender'

    # Rule 1: Bulk email + 2+ clickbait patterns = spam
    #   Rationale: Legitimate bulk senders rarely use multiple clickbait tactics
    elif signals['bulk_email'] and signals['clickbait_count'] >= 2:
        is_spam = True
        rule = 'RULE 1: Bulk + 2+ clickbait'

    else:
        # Rule 2: Bulk email + 2+ distinct spam behaviors = spam
        #   Rationale: Convergent signals — no single behavior is conclusive,
        #   but two independent spam behaviors from a bulk sender are
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
            rule = 'RULE 2: Bulk + 2+ behaviors'

        # Rule 3: Extreme clickbait alone (no bulk email required)
        #   Rationale: 3+ clickbait hits is so anomalous that even non-bulk
        #   senders are almost certainly spam (catches direct-send spam)
        elif signals['clickbait_count'] >= 3:
            is_spam = True
            rule = 'RULE 3: Extreme clickbait'

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
    # Locate SpamDetector.gs relative to this test file (../SpamDetector.gs)
    gs_path = Path(__file__).parent.parent / 'SpamDetector.gs'
    if not gs_path.exists():
        print(f"ERROR: SpamDetector.gs not found at {gs_path}")
        return False

    source = gs_path.read_text()

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

def run_spam_tests(spam_dir):
    """
    Test that every .eml in spam_dir is correctly detected as spam.

    Iterates over all .eml files alphabetically, runs analyze_email() on each,
    and expects a spam verdict. Prints per-file results with the triggering
    rule and signal summary for visibility in CI logs.

    A failure here means the detection engine missed a real spam email — the
    patterns or rules need tightening.

    Args:
        spam_dir: Path to directory containing spam .eml files.

    Returns:
        Tuple of (passed, failed, failures) where:
            - passed:   Count of correctly detected spam emails
            - failed:   Count of missed spam emails (false negatives)
            - failures: List of dicts with details for each missed email
    """
    # Collect and sort .eml files for deterministic ordering across platforms
    files = sorted([f for f in spam_dir.iterdir() if f.suffix == '.eml'])

    print('=' * 80)
    print('SpamDetector v6.9 Test Results')
    print('=' * 80)
    print(f'Testing {len(files)} spam examples...\n')

    passed = 0
    failed = 0
    failures = []

    for filepath in files:
        # Parse email and run detection pipeline
        subject, from_field, has_amazon_ses = parse_eml(filepath)
        signals, is_spam, rule = analyze_email(subject, from_field, has_amazon_ses)

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
        subject, from_field, has_amazon_ses = parse_eml(filepath)
        signals, is_spam, rule = analyze_email(subject, from_field, has_amazon_ses)

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

    Executes three phases in order, failing fast on critical errors:
        Phase 1: Gmail API method validation — fails fast because there's no
                 point testing detection if the deployed code will crash on
                 bad API calls.
        Phase 2: Spam detection against spam_examples/.
        Phase 3: Ham verification against ham_examples/.

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

    # ── Phase 3: Ham Verification ──────────────────────────────────────────
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
