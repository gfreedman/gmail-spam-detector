#!/usr/bin/env python3
"""
Test script for SpamDetector v6.0
Tests all spam examples against the new detection patterns
"""

import os
import re
import sys
import email
from email import policy
from email.header import decode_header
from pathlib import Path

# v6.0 Clickbait patterns (same as SpamDetector.gs)
CLICKBAIT_PATTERNS = [
    re.compile(r'\b(shocking|stunning|bizarre|mysterious|secret|hidden|leaked|exposed|forbidden)\b', re.I),
    re.compile(r'\b(terrifying|alarming|devastating|horrifying|frightening|chilling|disturbing)\b', re.I),
    re.compile(r'(strange|secret|hidden|mysterious|shocking|bizarre|unusual|leaked).*(picture|photo|image|video|camera|footage|document)', re.I),
    re.compile(r'(breaking|urgent|warning|alert|stop|exposed|banned).*(news|truth|secret|scandal|exposed|revealed)', re.I),
    re.compile(r'(market|stock|economy|dollar|gold|bitcoin|investment|crypto).*(crash|collapse|shift|crisis|warning|alert|plunge|tank)', re.I),
    re.compile(r'caught (on|doing|in|red-handed)', re.I),
    re.compile(r'(what|this).*(changes everything|stunned everyone|shocked|amazed|surprised)', re.I),
    re.compile(r'\b(RFK|Trump|Biden|Musk|Elon|Kennedy|Obama|Fauci|Gates)\b.*(warning|says|reveals|exposes|issues|predicts|warns)', re.I),
    re.compile(r'\b(seniors?|elderly|retirees?|boomers?|over \d{2}|born before|age \d{2})\b.*(risk|warning|alert|danger|affected|target)', re.I),
    re.compile(r'\b202[4-9]\b.*(warning|alert|prediction|forecast|crisis)', re.I),
    # v6.0 NEW: Conspiracy/hiding pattern
    re.compile(r'(what|who).*(hiding|don\'t want you|truth|they won\'t tell)', re.I),
    # v6.0 NEW: Military/war sensationalism
    re.compile(r'\b(declared war|bombed|bombing|attack|attacked|destroyed|invasion)\b', re.I),
    # v6.0 NEW: Stock price hype
    re.compile(r'\$\d+(\.\d+)?\s*(a\s+)?share|\bpenny stock\b', re.I),
    # v6.0 NEW: Watch/see curiosity gap
    re.compile(r'\b(watch|see)\s+(what|this|the moment)', re.I),
    # Structural indicators
    re.compile(r'【.*】'),
    re.compile(r'\[.{3,}[?!]\]'),
    re.compile(r'[💼📸⏯️🚨⚠️📰💰]'),
    re.compile(r'\?\?\?|!!!'),
    re.compile(r'\bWATCH\b.*\?$', re.I),
    # v6.0 NEW: Cyrillic/Unicode obfuscation (spam evasion tactic)
    re.compile(r'[\u0400-\u04FF]'),
    # v6.1 NEW: Greek character obfuscation (Β instead of B, etc.)
    re.compile(r'[\u0370-\u03FF]'),
    # v6.0 NEW: Jobs/employment fear
    re.compile(r'\b(jobs?|employment).*(disappeared|vanished|never existed|fake|fraud|layoffs?)', re.I),
    # v6.1 NEW: Bank/branch closing fear
    re.compile(r'\b(banks?|branch|branches|ATMs?).*(clos|shut|disappear|eliminat)', re.I),
    # v6.1 NEW: Building/institution emoji
    re.compile(r'[🏦🏥🏛️🏢]'),
]

# v6.0 Fear patterns (same as SpamDetector.gs)
FEAR_PATTERNS = [
    re.compile(r'\b(IRS|NSA|FBI|CIA|government|federal)\b.*(warn|hiding|secret|spy|track|audit|investigation|admission|reveal|expose|confiscat)', re.I),
    re.compile(r'\b(banks?|bank account|credit card|social security|identity|savings|cash|money)\b.*(seize|steal|stolen|hacked|freeze|frozen|close|closed|warning|alert|confiscat|take|taking|lost)', re.I),
    re.compile(r'\b(blood thinner|medication|drug|vaccine|doctor|FDA|health crisis|at risk)\b.*(warning|danger|deadly|killing|risk|avoid|corrupt)', re.I),
    re.compile(r'\b(warning|alert|urgent|breaking|exposed|banned|stopped)\b', re.I),
    re.compile(r'\bSTOP (using|taking|doing|buying)\b', re.I),
]

# Marketing format patterns (v6.0 expanded)
MARKETING_PATTERNS = [
    re.compile(r'["|,]\s*[A-Z]', re.I),
    re.compile(r'\s+at\s+[A-Z]', re.I),
    re.compile(r'\|\s*'),
    re.compile(r'\b(investment|trading|wealth|profit|finance|insider|market)\s*(tools?|pro|tips?|alert)', re.I),
    re.compile(r'grow@with\.', re.I),
    re.compile(r'@[a-z]\.[a-z]+\.(com|net)', re.I),
]


def decode_email_header(header_value):
    """Properly decode email header with RFC 2047 encoding."""
    if not header_value:
        return ''

    decoded_parts = decode_header(header_value)
    result = ''
    for part, encoding in decoded_parts:
        if isinstance(part, bytes):
            result += part.decode(encoding or 'utf-8', errors='replace')
        else:
            result += part
    return result


def parse_eml(filepath):
    """Parse an .eml file and extract subject, from, and check for Amazon SES."""
    with open(filepath, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    # Read raw content for Amazon SES check
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    # Check for Amazon SES
    content_lower = content.lower()
    has_amazon_ses = 'amazonses.com' in content_lower or 'sendgrid.net' in content_lower

    # Get properly decoded headers
    subject = decode_email_header(msg.get('subject', ''))
    from_field = decode_email_header(msg.get('from', ''))

    return subject, from_field, has_amazon_ses


def analyze_email(subject, from_field, has_amazon_ses):
    """Analyze email using v6.0 detection logic."""
    signals = {
        'bulk_email': has_amazon_ses,
        'clickbait_count': 0,
        'fear_mongering': False,
        'marketing_format': False,
        'matched_patterns': []
    }

    text_to_check = subject + ' ' + from_field

    # Check clickbait patterns
    for i, pattern in enumerate(CLICKBAIT_PATTERNS):
        if pattern.search(text_to_check):
            signals['clickbait_count'] += 1
            signals['matched_patterns'].append(f'clickbait[{i}]')

    # Check fear patterns
    for i, pattern in enumerate(FEAR_PATTERNS):
        if pattern.search(text_to_check):
            signals['fear_mongering'] = True
            signals['matched_patterns'].append(f'fear[{i}]')
            break

    # Check marketing format (v6.0: multiple patterns)
    for pattern in MARKETING_PATTERNS:
        if pattern.search(from_field):
            signals['marketing_format'] = True
            signals['matched_patterns'].append('marketing')
            break

    # Decision logic
    is_spam = False
    rule = ''

    if signals['bulk_email'] and signals['clickbait_count'] >= 2:
        is_spam = True
        rule = 'RULE 1: Bulk + 2+ clickbait'
    else:
        behavior_count = 0
        if signals['clickbait_count'] >= 1:
            behavior_count += 1
        if signals['fear_mongering']:
            behavior_count += 1
        if signals['marketing_format']:
            behavior_count += 1

        if signals['bulk_email'] and behavior_count >= 2:
            is_spam = True
            rule = 'RULE 2: Bulk + 2+ behaviors'
        elif (signals['bulk_email'] and signals['marketing_format'] and
              (signals['clickbait_count'] >= 1 or signals['fear_mongering'])):
            is_spam = True
            rule = 'RULE 3: Bulk + marketing + warning'
        elif signals['clickbait_count'] >= 3:
            is_spam = True
            rule = 'RULE 4: Extreme clickbait'

    return signals, is_spam, rule


def main():
    spam_dir = Path(__file__).parent / 'spam_examples'

    if not spam_dir.exists():
        print(f"ERROR: spam_examples directory not found at {spam_dir}")
        sys.exit(1)

    files = sorted([f for f in spam_dir.iterdir() if f.suffix == '.eml'])

    print('=' * 80)
    print('SpamDetector v6.0 Test Results')
    print('=' * 80)
    print(f'Testing {len(files)} spam examples...\n')

    passed = 0
    failed = 0
    failures = []

    for filepath in files:
        subject, from_field, has_amazon_ses = parse_eml(filepath)
        signals, is_spam, rule = analyze_email(subject, from_field, has_amazon_ses)

        if is_spam:
            passed += 1
            print(f'✅ PASS: {filepath.name[:60]}')
            print(f'   Subject: {subject[:60]}')
            print(f'   Rule: {rule}')
            print(f'   Signals: bulk={signals["bulk_email"]}, clickbait={signals["clickbait_count"]}, '
                  f'fear={signals["fear_mongering"]}, marketing={signals["marketing_format"]}')
            print()
        else:
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

    print('=' * 80)
    print('SPAM DETECTION SUMMARY')
    print('=' * 80)
    print(f'Total: {len(files)}')
    print(f'Detected: {passed} ({passed/len(files)*100:.1f}%)')
    print(f'Missed: {failed} ({failed/len(files)*100:.1f}%)')

    spam_failures = failures.copy()

    # Test HAM (legitimate emails) - should NOT be marked as spam
    ham_dir = Path(__file__).parent / 'ham_examples'
    ham_false_positives = []
    ham_passed = 0
    ham_total = 0

    if ham_dir.exists():
        ham_files = sorted([f for f in ham_dir.iterdir() if f.suffix == '.eml'])
        ham_total = len(ham_files)

        if ham_files:
            print('\n' + '=' * 80)
            print('HAM (Legitimate Email) Testing')
            print('=' * 80)
            print(f'Testing {len(ham_files)} ham examples...\n')

            for filepath in ham_files:
                subject, from_field, has_amazon_ses = parse_eml(filepath)
                signals, is_spam, rule = analyze_email(subject, from_field, has_amazon_ses)

                if not is_spam:
                    ham_passed += 1
                    print(f'✅ PASS (not spam): {filepath.name[:60]}')
                    print(f'   Subject: {subject[:60]}')
                    print(f'   From: {from_field[:60]}')
                    print()
                else:
                    ham_false_positives.append({
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

            print('=' * 80)
            print('HAM TESTING SUMMARY')
            print('=' * 80)
            print(f'Total: {ham_total}')
            print(f'Correctly allowed: {ham_passed} ({ham_passed/ham_total*100:.1f}%)')
            print(f'False positives: {len(ham_false_positives)} ({len(ham_false_positives)/ham_total*100:.1f}%)')

    # Final summary
    print('\n' + '=' * 80)
    print('FINAL RESULTS')
    print('=' * 80)

    all_good = True

    if spam_failures:
        print(f'❌ SPAM MISSED: {len(spam_failures)}')
        for f in spam_failures:
            print(f'   - {f["file"]}: {f["subject"][:50]}')
        all_good = False
    else:
        print(f'✅ SPAM: {passed}/{len(files)} detected (100%)')

    if ham_false_positives:
        print(f'❌ FALSE POSITIVES: {len(ham_false_positives)}')
        for f in ham_false_positives:
            print(f'   - {f["file"]}: {f["subject"][:50]}')
        all_good = False
    elif ham_total > 0:
        print(f'✅ HAM: {ham_passed}/{ham_total} correctly allowed (0% false positives)')

    if all_good:
        print('\n🎉 ALL TESTS PASSED!')
        sys.exit(0)
    else:
        print('\n💥 TESTS FAILED!')
        sys.exit(1)


if __name__ == '__main__':
    main()
