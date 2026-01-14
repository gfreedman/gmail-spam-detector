#!/usr/bin/env python3
"""
Spam Detector Test Suite

This script tests the spam detection algorithm against all spam examples
in the spam_examples directory. It provides detailed scoring breakdowns
to help tune the detection thresholds and weights.

Usage:
    python test_spam_detector.py
    python test_spam_detector.py --verbose
    python test_spam_detector.py --threshold 70
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple
from dataclasses import dataclass
from collections import defaultdict

try:
    import PyPDF2
except ImportError:
    print("ERROR: PyPDF2 not installed. Run: pip install PyPDF2")
    sys.exit(1)


# Configuration (matches SpamDetector.gs)
@dataclass
class Config:
    spam_threshold: int = 50  # Raised to reduce false positives (with whitelist protection)
    verbose: bool = False
    show_all_scores: bool = True


# Scoring weights (matches SCORING_WEIGHTS in SpamDetector.gs)
# Architecture: Tier 1 (structural) > Tier 2 (behavioral) > Tier 3 (content)
SCORING_WEIGHTS = {
    # TIER 1: Structural indicators (very high confidence - 40-50 points)
    'MALFORMED_HEADERS': 50,
    'DISPLAY_NAME_MISMATCH': 40,
    'MULTIPLE_SENDERS': 35,
    'SUSPICIOUS_FROM_PATTERN': 30,

    # TIER 2: Behavioral indicators (high confidence - 15-25 points)
    'SUSPICIOUS_DOMAIN': 25,
    'UNICODE_OBFUSCATION': 20,
    'AFFILIATE_DISCLAIMER': 15,
    'UNSUBSCRIBE_LANGUAGE': 12,
    'NOREPLY_SENDER': 8,

    # TIER 3: Content indicators (medium confidence - 5-12 points)
    'ALL_CAPS_SUBJECT': 12,
    'SENSATIONALIST_KEYWORD': 10,
    'HEALTH_SCAM': 10,
    'MANY_LINKS_HIGH': 10,
    'DATE_URGENCY': 8,
    'EXCESSIVE_EXCLAMATION_SUBJECT': 8,
    'FINANCIAL_SCAM': 8,
    'CLICK_TRACKING': 8,
    'FEAR_MONGERING': 7,
    'MULTIPLE_CTAS': 7,
    'TECH_HYPE': 6,
    'MANY_LINKS_MEDIUM': 5,
    'EXCLAMATION_PER_COUNT': 2,
    'MAX_EXCLAMATION_SCORE': 15
}

# Keywords (matches KEYWORDS in SpamDetector.gs)
KEYWORDS = {
    'sensationalist': [
        'breaking news', 'urgent', 'warning', 'caught on camera',
        'just exposed', 'shocking', 'stunned everyone', 'alert',
        'do not ignore', 'this changes everything', 'secret'
    ],
    'suspicious_domains': [
        'financeinsiderpro.com', 'financebuzz', 'smartinvestmenttools',
        'investorplace', 'weissratings', 'americanprofitinsight.com'
    ],
    'legitimate_domains': [
        'sardine.ai', 'meetup.com', 'substack.com', 'conservative.ca',
        'sundaymass.store', 'customerservice@stan', 'privaterelay.appleid.com',
        'email.meetup.com', 'ben-evans.com', 'linkedin.com', 'dsf.ca',
        'dragonfly'
    ],
    'financial_scam': [
        'investment opportunity', 'cash back', 'bonus instantly',
        'approval decision', 'wealth transfer', 'smart money',
        'government infrastructure spending', 'stock tips',
        'make money', 'earn cash', 'financial freedom'
    ],
    'fear_mongering': [
        'jobs disappeared', 'massive layoffs', 'market crash',
        'wealth confiscation', 'government hiding', 'exposed',
        'economic collapse', 'crisis'
    ],
    'health_scam': [
        'cure', 'erases', 'brain health', 'neuropathy',
        'miracle', 'breakthrough', 'doctors hate'
    ],
    'tech_hype': [
        'tesla', 'spacex', 'self-driving', 'ai takeover',
        'cybertruck', 'elon'
    ]
}

# Compiled regexes (matches REGEX_CACHE in SpamDetector.gs)
REGEX_PATTERNS = {
    'date_urgency': re.compile(
        r'january|february|march|april|may|june|july|august|september|october|november|december.*\d{1,2}.*202[0-9]',
        re.IGNORECASE
    ),
    'exclamation_marks': re.compile(r'!'),
    'link_tags': re.compile(r'<a\s+(?:[^>]*?\s+)?href', re.IGNORECASE),
    'cta_patterns': re.compile(r'learn more|apply now|click here|get started|claim now', re.IGNORECASE),
    'cyrillic': re.compile(r'[а-яА-Я]'),
    'greek': re.compile(r'[\u0370-\u03FF]'),
    'phonetic_ext': re.compile(r'[\u1D00-\u1DBF]'),
    'latin_ext_add': re.compile(r'[\u1E00-\u1EFF]'),
    'latin_ext_c': re.compile(r'[\u2C60-\u2C7F]'),
    'latin_ext_d': re.compile(r'[\uA720-\uA7FF]'),
    'alpha_pres': re.compile(r'[\uFB00-\uFB4F]'),
    'math_alpha': re.compile(r'[\uD835]')
}


@dataclass
class EmailData:
    """Represents extracted email data from PDF"""
    filename: str
    subject: str
    sender: str
    date: str
    recipient: str
    body_text: str
    body_html: str


@dataclass
class ScoreBreakdown:
    """Detailed breakdown of spam score"""
    total_score: int
    structural_score: int   # TIER 1 structural indicators
    subject_score: int
    sender_score: int
    body_score: int
    links_score: int
    unicode_score: int
    reasons: List[str]
    matched_keywords: Dict[str, List[str]]


def extract_email_from_pdf(pdf_path: str) -> EmailData:
    """
    Extract email data from a PDF file.

    Args:
        pdf_path: Path to the PDF file

    Returns:
        EmailData object with extracted information
    """
    try:
        with open(pdf_path, 'rb') as file:
            reader = PyPDF2.PdfReader(file)

            # Extract text from all pages
            full_text = ''
            for page in reader.pages:
                full_text += page.extract_text() + '\n'

            # Parse email headers from first page
            first_page = reader.pages[0].extract_text() if len(reader.pages) > 0 else ''

            # Extract headers (basic parsing)
            subject = ''
            sender = ''
            date = ''
            recipient = ''

            lines = first_page.split('\n')
            for i, line in enumerate(lines):
                line_lower = line.lower()
                if line_lower.startswith('subject:'):
                    subject = line.split(':', 1)[1].strip() if ':' in line else ''
                elif line_lower.startswith('from:'):
                    sender = line.split(':', 1)[1].strip() if ':' in line else ''
                elif line_lower.startswith('date:'):
                    date = line.split(':', 1)[1].strip() if ':' in line else ''
                elif line_lower.startswith('to:'):
                    recipient = line.split(':', 1)[1].strip() if ':' in line else ''

            # Use filename as fallback subject
            if not subject:
                subject = Path(pdf_path).stem

            return EmailData(
                filename=Path(pdf_path).name,
                subject=subject,
                sender=sender,
                date=date,
                recipient=recipient,
                body_text=full_text,
                body_html=full_text  # PDFs don't have HTML, use text
            )
    except Exception as e:
        print(f"Error reading {pdf_path}: {e}")
        return EmailData(
            filename=Path(pdf_path).name,
            subject=Path(pdf_path).stem,
            sender='',
            date='',
            recipient='',
            body_text='',
            body_html=''
        )


def count_keyword_matches(text: str, keywords: List[str], weight: int) -> Tuple[int, List[str]]:
    """
    Count keyword matches and return score with matched keywords.

    Args:
        text: Text to search
        keywords: List of keywords to match
        weight: Score weight per match

    Returns:
        Tuple of (score, list of matched keywords)
    """
    if not text or not keywords:
        return 0, []

    text_lower = text.lower()
    score = 0
    matched = []

    for keyword in keywords:
        if keyword in text_lower:
            score += weight
            matched.append(keyword)

    return score, matched


def analyze_structural_indicators(sender: str, subject: str) -> Tuple[int, List[str]]:
    """
    Analyze TIER 1 structural/malformation indicators.
    These are very high confidence spam signals that are hard to fake.

    Args:
        sender: The sender email/display name
        subject: Email subject (for detecting header bleeding)

    Returns:
        Tuple of (score, list of reasons)
    """
    if not sender:
        return 0, []

    score = 0
    reasons = []

    # TIER 1.1: Malformed headers - "Subject:" bleeding into From field
    if 'subject:' in sender.lower():
        score += SCORING_WEIGHTS['MALFORMED_HEADERS']
        reasons.append(f"Malformed headers (Subject: in From field) (+{SCORING_WEIGHTS['MALFORMED_HEADERS']})")

    # TIER 1.2: Multiple senders in From field (using || separator)
    if '||' in sender:
        score += SCORING_WEIGHTS['MULTIPLE_SENDERS']
        reasons.append(f"Multiple sender names in From field (+{SCORING_WEIGHTS['MULTIPLE_SENDERS']})")

    # TIER 1.3: Display name mismatch
    email_match = re.search(r'[\w.-]+@[\w.-]+\.[a-z]{2,}', sender, re.IGNORECASE)
    if email_match:
        email = email_match.group(0)
        domain = email.split('@')[1]
        display_part = sender[:sender.index(email)].strip()

        if len(display_part) > 3:
            domain_words = set(re.sub(r'[^a-z0-9\s]', ' ', domain.lower()).split())
            display_words = set(re.sub(r'[^a-z0-9\s]', ' ', display_part.lower()).split())
            domain_words = {w for w in domain_words if len(w) > 2}
            display_words = {w for w in display_words if len(w) > 2}

            if display_words and not display_words.intersection(domain_words):
                score += SCORING_WEIGHTS['DISPLAY_NAME_MISMATCH']
                reasons.append(f"Display name does not match email domain (+{SCORING_WEIGHTS['DISPLAY_NAME_MISMATCH']})")

    # TIER 1.4: Suspicious From field patterns
    if (re.search(r'\.com[A-Z]', sender, re.IGNORECASE) or
        re.search(r'\.com[a-z]{3,}', sender) or
        'grow@with' in sender):
        score += SCORING_WEIGHTS['SUSPICIOUS_FROM_PATTERN']
        reasons.append(f"Suspicious From field formatting (+{SCORING_WEIGHTS['SUSPICIOUS_FROM_PATTERN']})")

    return score, reasons


def analyze_subject(subject: str) -> Tuple[int, List[str]]:
    """
    Analyze subject line for spam indicators.

    Args:
        subject: Email subject line

    Returns:
        Tuple of (score, list of reasons)
    """
    if not subject:
        return 0, []

    score = 0
    reasons = []

    # Sensationalist keywords
    kw_score, matched = count_keyword_matches(
        subject, KEYWORDS['sensationalist'], SCORING_WEIGHTS['SENSATIONALIST_KEYWORD']
    )
    if kw_score > 0:
        score += kw_score
        reasons.append(f"Sensationalist keywords: {', '.join(matched)} (+{kw_score})")

    # Date urgency
    if REGEX_PATTERNS['date_urgency'].search(subject):
        score += SCORING_WEIGHTS['DATE_URGENCY']
        reasons.append(f"Fake urgency with date (+{SCORING_WEIGHTS['DATE_URGENCY']})")

    # All caps
    if len(subject) > 10 and subject == subject.upper():
        score += SCORING_WEIGHTS['ALL_CAPS_SUBJECT']
        reasons.append(f"ALL CAPS subject (+{SCORING_WEIGHTS['ALL_CAPS_SUBJECT']})")

    # Excessive exclamation marks
    exclamation_count = len(REGEX_PATTERNS['exclamation_marks'].findall(subject))
    if exclamation_count >= 2:
        score += SCORING_WEIGHTS['EXCESSIVE_EXCLAMATION_SUBJECT']
        reasons.append(f"Excessive exclamation marks ({exclamation_count}) (+{SCORING_WEIGHTS['EXCESSIVE_EXCLAMATION_SUBJECT']})")

    return score, reasons


def analyze_sender(sender: str) -> Tuple[int, List[str]]:
    """
    Analyze sender for suspicious patterns.

    Args:
        sender: Sender email address

    Returns:
        Tuple of (score, list of reasons)
    """
    if not sender:
        return 0, []

    score = 0
    reasons = []
    sender_lower = sender.lower()

    # Suspicious domains
    kw_score, matched = count_keyword_matches(
        sender_lower, KEYWORDS['suspicious_domains'], SCORING_WEIGHTS['SUSPICIOUS_DOMAIN']
    )
    if kw_score > 0:
        score += kw_score
        reasons.append(f"Suspicious domain: {', '.join(matched)} (+{kw_score})")

    # No-reply patterns
    if 'noreply' in sender_lower or 'no-reply' in sender_lower:
        score += SCORING_WEIGHTS['NOREPLY_SENDER']
        reasons.append(f"No-reply sender (+{SCORING_WEIGHTS['NOREPLY_SENDER']})")

    return score, reasons


def analyze_body(body: str, html_body: str) -> Tuple[int, List[str], Dict[str, List[str]]]:
    """
    Analyze email body for spam patterns.

    Args:
        body: Plain text email body
        html_body: HTML email body

    Returns:
        Tuple of (score, list of reasons, dict of matched keywords by category)
    """
    if not body:
        return 0, [], {}

    score = 0
    reasons = []
    all_matched = {}
    body_lower = body.lower()

    # Financial scam keywords
    kw_score, matched = count_keyword_matches(
        body_lower, KEYWORDS['financial_scam'], SCORING_WEIGHTS['FINANCIAL_SCAM']
    )
    if kw_score > 0:
        score += kw_score
        all_matched['financial_scam'] = matched
        reasons.append(f"Financial scam keywords ({len(matched)}): {', '.join(matched[:3])}... (+{kw_score})")

    # Fear-mongering keywords
    kw_score, matched = count_keyword_matches(
        body_lower, KEYWORDS['fear_mongering'], SCORING_WEIGHTS['FEAR_MONGERING']
    )
    if kw_score > 0:
        score += kw_score
        all_matched['fear_mongering'] = matched
        reasons.append(f"Fear-mongering keywords ({len(matched)}): {', '.join(matched[:3])}... (+{kw_score})")

    # Health scam keywords
    kw_score, matched = count_keyword_matches(
        body_lower, KEYWORDS['health_scam'], SCORING_WEIGHTS['HEALTH_SCAM']
    )
    if kw_score > 0:
        score += kw_score
        all_matched['health_scam'] = matched
        reasons.append(f"Health scam keywords ({len(matched)}): {', '.join(matched[:3])}... (+{kw_score})")

    # Tech hype keywords
    kw_score, matched = count_keyword_matches(
        body_lower, KEYWORDS['tech_hype'], SCORING_WEIGHTS['TECH_HYPE']
    )
    if kw_score > 0:
        score += kw_score
        all_matched['tech_hype'] = matched
        reasons.append(f"Tech hype keywords ({len(matched)}): {', '.join(matched[:3])}... (+{kw_score})")

    # Unsubscribe language
    if 'unsubscribe' in body_lower and 'opt out' in body_lower:
        score += SCORING_WEIGHTS['UNSUBSCRIBE_LANGUAGE']
        reasons.append(f"Unsubscribe + opt out language (+{SCORING_WEIGHTS['UNSUBSCRIBE_LANGUAGE']})")

    # Affiliate disclaimer
    if 'this is an advertisement' in body_lower or 'we may receive compensation' in body_lower:
        score += SCORING_WEIGHTS['AFFILIATE_DISCLAIMER']
        reasons.append(f"Affiliate disclaimer (+{SCORING_WEIGHTS['AFFILIATE_DISCLAIMER']})")

    # Multiple exclamation marks
    exclamation_count = len(REGEX_PATTERNS['exclamation_marks'].findall(body))
    if exclamation_count >= 3:
        exclamation_score = min(
            exclamation_count * SCORING_WEIGHTS['EXCLAMATION_PER_COUNT'],
            SCORING_WEIGHTS['MAX_EXCLAMATION_SCORE']
        )
        score += exclamation_score
        reasons.append(f"Excessive exclamation marks ({exclamation_count}) (+{exclamation_score})")

    return score, reasons, all_matched


def analyze_links(html_body: str) -> Tuple[int, List[str]]:
    """
    Analyze links for suspicious patterns.

    Args:
        html_body: HTML email body

    Returns:
        Tuple of (score, list of reasons)
    """
    if not html_body:
        return 0, []

    score = 0
    reasons = []

    # Count links
    link_count = len(REGEX_PATTERNS['link_tags'].findall(html_body))

    if link_count > 10:
        score += SCORING_WEIGHTS['MANY_LINKS_HIGH']
        reasons.append(f"Many links ({link_count}) (+{SCORING_WEIGHTS['MANY_LINKS_HIGH']})")
    elif link_count > 5:
        score += SCORING_WEIGHTS['MANY_LINKS_MEDIUM']
        reasons.append(f"Multiple links ({link_count}) (+{SCORING_WEIGHTS['MANY_LINKS_MEDIUM']})")

    # Click tracking
    if 'click here' in html_body.lower() and link_count > 0:
        score += SCORING_WEIGHTS['CLICK_TRACKING']
        reasons.append(f"Click tracking language (+{SCORING_WEIGHTS['CLICK_TRACKING']})")

    # Multiple CTAs
    cta_count = len(REGEX_PATTERNS['cta_patterns'].findall(html_body))
    if cta_count >= 2:
        score += SCORING_WEIGHTS['MULTIPLE_CTAS']
        reasons.append(f"Multiple CTAs ({cta_count}) (+{SCORING_WEIGHTS['MULTIPLE_CTAS']})")

    return score, reasons


def analyze_unicode_obfuscation(text: str) -> Tuple[int, List[str]]:
    """
    Detect Unicode character obfuscation.

    Args:
        text: Text to analyze

    Returns:
        Tuple of (score, list of reasons)
    """
    if not text:
        return 0, []

    score = 0
    reasons = []
    matched_patterns = []

    # Check various Unicode patterns
    patterns = {
        'cyrillic': REGEX_PATTERNS['cyrillic'],
        'greek': REGEX_PATTERNS['greek'],
        'phonetic_ext': REGEX_PATTERNS['phonetic_ext'],
        'latin_ext_add': REGEX_PATTERNS['latin_ext_add'],
        'latin_ext_c': REGEX_PATTERNS['latin_ext_c'],
        'latin_ext_d': REGEX_PATTERNS['latin_ext_d'],
        'alpha_pres': REGEX_PATTERNS['alpha_pres']
    }

    for name, pattern in patterns.items():
        if pattern.search(text):
            matched_patterns.append(name)
            break  # Only count once

    if matched_patterns:
        score += SCORING_WEIGHTS['UNICODE_OBFUSCATION']
        reasons.append(f"Unicode obfuscation ({', '.join(matched_patterns)}) (+{SCORING_WEIGHTS['UNICODE_OBFUSCATION']})")

    # Mathematical alphanumeric symbols
    if REGEX_PATTERNS['math_alpha'].search(text):
        score += SCORING_WEIGHTS['UNICODE_OBFUSCATION']
        reasons.append(f"Mathematical unicode symbols (+{SCORING_WEIGHTS['UNICODE_OBFUSCATION']})")

    return score, reasons


def analyze_email(email: EmailData, config: Config) -> ScoreBreakdown:
    """
    Analyze an email and return detailed score breakdown.

    Args:
        email: EmailData object
        config: Configuration object

    Returns:
        ScoreBreakdown object with detailed analysis
    """
    all_reasons = []
    all_matched_keywords = {}

    # WHITELIST CHECK: Skip spam detection for known legitimate domains
    sender_lower = email.sender.lower()
    for domain in KEYWORDS['legitimate_domains']:
        if domain in sender_lower:
            all_reasons.append(f"[WHITELIST] Legitimate domain detected: {domain}")
            return ScoreBreakdown(
                structural_score=0,
                subject_score=0,
                sender_score=0,
                body_score=0,
                links_score=0,
                unicode_score=0,
                total_score=0,
                reasons=all_reasons,
                matched_keywords={}
            )

    # TIER 1: Analyze structural indicators first (highest confidence)
    structural_score, structural_reasons = analyze_structural_indicators(email.sender, email.subject)
    all_reasons.extend([f"[TIER 1 STRUCTURAL] {r}" for r in structural_reasons])

    # TIER 2 & 3: Analyze other indicators
    subject_score, subject_reasons = analyze_subject(email.subject)
    all_reasons.extend([f"[SUBJECT] {r}" for r in subject_reasons])

    # Analyze sender
    sender_score, sender_reasons = analyze_sender(email.sender)
    all_reasons.extend([f"[SENDER] {r}" for r in sender_reasons])

    # Analyze body
    body_score, body_reasons, body_keywords = analyze_body(email.body_text, email.body_html)
    all_reasons.extend([f"[BODY] {r}" for r in body_reasons])
    all_matched_keywords.update(body_keywords)

    # Analyze links
    links_score, links_reasons = analyze_links(email.body_html)
    all_reasons.extend([f"[LINKS] {r}" for r in links_reasons])

    # Analyze Unicode obfuscation
    unicode_score, unicode_reasons = analyze_unicode_obfuscation(email.subject + ' ' + email.body_text)
    all_reasons.extend([f"[UNICODE] {r}" for r in unicode_reasons])

    total_score = min(
        structural_score + subject_score + sender_score + body_score + links_score + unicode_score,
        100
    )

    return ScoreBreakdown(
        total_score=total_score,
        structural_score=structural_score,
        subject_score=subject_score,
        sender_score=sender_score,
        body_score=body_score,
        links_score=links_score,
        unicode_score=unicode_score,
        reasons=all_reasons,
        matched_keywords=all_matched_keywords
    )


def print_email_analysis(email: EmailData, breakdown: ScoreBreakdown, config: Config):
    """Print detailed analysis of an email."""
    is_spam = breakdown.total_score >= config.spam_threshold

    print("\n" + "=" * 80)
    print(f"File: {email.filename}")
    print("=" * 80)
    print(f"Subject: {email.subject[:100]}")
    print(f"From: {email.sender[:100]}")
    print(f"Date: {email.date}")
    print("-" * 80)
    print(f"SPAM SCORE: {breakdown.total_score}/100 {'[SPAM]' if is_spam else '[OK]'}")
    print(f"Threshold: {config.spam_threshold}")
    print("-" * 80)
    print(f"Structural:     {breakdown.structural_score:3d}  <- TIER 1 (High confidence)")
    print(f"Subject Score:  {breakdown.subject_score:3d}")
    print(f"Sender Score:   {breakdown.sender_score:3d}")
    print(f"Body Score:     {breakdown.body_score:3d}")
    print(f"Links Score:    {breakdown.links_score:3d}")
    print(f"Unicode Score:  {breakdown.unicode_score:3d}")
    print("-" * 80)

    if breakdown.reasons:
        print("Score Breakdown:")
        for reason in breakdown.reasons:
            print(f"  • {reason}")

    if config.verbose and breakdown.matched_keywords:
        print("\nMatched Keywords by Category:")
        for category, keywords in breakdown.matched_keywords.items():
            print(f"  {category}: {', '.join(keywords)}")

    print("=" * 80)


def main():
    """Main function to run spam detection tests."""
    # Parse command line arguments
    config = Config()

    if '--verbose' in sys.argv or '-v' in sys.argv:
        config.verbose = True

    if '--threshold' in sys.argv:
        idx = sys.argv.index('--threshold')
        if idx + 1 < len(sys.argv):
            try:
                config.spam_threshold = int(sys.argv[idx + 1])
            except ValueError:
                print("Invalid threshold value")
                sys.exit(1)

    # Find spam examples directory
    spam_dir = Path(__file__).parent / 'spam_examples'

    if not spam_dir.exists():
        print(f"ERROR: spam_examples directory not found at {spam_dir}")
        sys.exit(1)

    # Get all PDF files
    pdf_files = sorted(spam_dir.glob('*.pdf'))

    if not pdf_files:
        print(f"ERROR: No PDF files found in {spam_dir}")
        sys.exit(1)

    print(f"Found {len(pdf_files)} spam examples to analyze")
    print(f"Spam threshold: {config.spam_threshold}")
    print(f"Verbose mode: {config.verbose}")
    print()

    # Statistics
    total_analyzed = 0
    total_spam = 0
    total_ok = 0
    score_distribution = defaultdict(int)
    all_breakdowns = []

    # Analyze each PDF
    for pdf_file in pdf_files:
        try:
            email = extract_email_from_pdf(str(pdf_file))
            breakdown = analyze_email(email, config)

            total_analyzed += 1
            if breakdown.total_score >= config.spam_threshold:
                total_spam += 1
            else:
                total_ok += 1

            score_distribution[breakdown.total_score // 10] += 1
            all_breakdowns.append((email, breakdown))

            # Print individual results
            if config.show_all_scores:
                print_email_analysis(email, breakdown, config)

        except Exception as e:
            print(f"ERROR analyzing {pdf_file.name}: {e}")

    # Print summary statistics
    print("\n" + "=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)
    print(f"Total analyzed:     {total_analyzed}")
    print(f"Marked as SPAM:     {total_spam} ({total_spam/total_analyzed*100:.1f}%)")
    print(f"Marked as OK:       {total_ok} ({total_ok/total_analyzed*100:.1f}%)")
    print()
    print("Score Distribution:")
    for bucket in sorted(score_distribution.keys()):
        bar = '█' * score_distribution[bucket]
        print(f"  {bucket*10:3d}-{bucket*10+9:3d}: {bar} ({score_distribution[bucket]})")
    print()

    # Show lowest scoring emails (potential misses)
    if all_breakdowns:
        print("\nLOWEST SCORING EMAILS (potential false negatives):")
        print("-" * 80)
        sorted_breakdowns = sorted(all_breakdowns, key=lambda x: x[1].total_score)
        for email, breakdown in sorted_breakdowns[:5]:
            status = "SPAM" if breakdown.total_score >= config.spam_threshold else "OK"
            print(f"  {breakdown.total_score:3d} [{status}] {email.filename}")

        print("\nHIGHEST SCORING EMAILS:")
        print("-" * 80)
        for email, breakdown in sorted_breakdowns[-5:]:
            status = "SPAM" if breakdown.total_score >= config.spam_threshold else "OK"
            print(f"  {breakdown.total_score:3d} [{status}] {email.filename}")

    print("\n" + "=" * 80)


if __name__ == '__main__':
    main()
