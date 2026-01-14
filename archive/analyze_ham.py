#!/usr/bin/env python3
"""
Analyze HAM examples to identify false positives.
"""

import sys
from pathlib import Path

# Import functions from test_spam_detector
from test_spam_detector import (
    Config, extract_email_from_pdf, analyze_email, print_email_analysis
)

def main():
    ham_dir = Path('ham_examples')

    if not ham_dir.exists():
        print(f"ERROR: ham_examples directory not found")
        sys.exit(1)

    pdf_files = sorted(ham_dir.glob('*.pdf'))

    if not pdf_files:
        print(f"ERROR: No PDF files found in ham_examples/")
        sys.exit(1)

    config = Config(spam_threshold=50, verbose=True, show_all_scores=True)

    print("="  * 80)
    print("ANALYZING HAM EXAMPLES (Legitimate emails - should NOT be flagged as spam)")
    print("="  * 80)
    print(f"Found {len(pdf_files)} ham examples")
    print(f"Spam threshold: {config.spam_threshold}")
    print()

    false_positives = []

    for pdf_file in pdf_files:
        try:
            email = extract_email_from_pdf(str(pdf_file))
            breakdown = analyze_email(email, config)

            print_email_analysis(email, breakdown, config)

            if breakdown.total_score >= config.spam_threshold:
                false_positives.append((email, breakdown))
                print(f"\n⚠️  FALSE POSITIVE - This legitimate email scored {breakdown.total_score} >= {config.spam_threshold}")
                print("=" * 80)

        except Exception as e:
            print(f"ERROR analyzing {pdf_file.name}: {e}")
            print("=" * 80)

    # Summary
    print("\n" + "=" * 80)
    print("FALSE POSITIVE SUMMARY")
    print("=" * 80)
    print(f"Total ham examples analyzed: {len(pdf_files)}")
    print(f"False positives (incorrectly flagged as spam): {len(false_positives)}")
    print(f"False positive rate: {len(false_positives)/len(pdf_files)*100:.1f}%")

    if false_positives:
        print("\nFalse positives:")
        for email, breakdown in false_positives:
            print(f"  • {email.filename} (score: {breakdown.total_score})")
    else:
        print("\n✅ No false positives detected!")

    print("=" * 80)

if __name__ == '__main__':
    main()
