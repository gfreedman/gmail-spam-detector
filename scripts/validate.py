#!/usr/bin/env python3
"""
Pre-push validation — catches common commit nits before they hit CI.

Checks:
  1. README spam/ham counts match actual .eml file counts
  2. @version matches the newest CHANGELOG.md entry, and entries are newest-first
  3. @version header and the SCRIPT_VERSION constant agree

Run: python3 scripts/validate.py
Install as git hook: ln -sf ../../scripts/validate.py .git/hooks/pre-push && chmod +x .git/hooks/pre-push
"""

import re, sys
from pathlib import Path

ROOT    = Path(__file__).parent.parent
errors  = []

def fail(msg): errors.append(f'❌  {msg}')
def ok(msg):   print(f'✅  {msg}')

# ── 1. README counts match .eml files ────────────────────────────────────────
spam_count = len(list((ROOT / 'tests/spam_examples').glob('*.eml')))
ham_count  = len(list((ROOT / 'tests/ham_examples').glob('*.eml')))
readme     = (ROOT / 'README.md').read_text()

if f'{spam_count}/' in readme:
    ok(f'README spam count ({spam_count}/{spam_count})')
else:
    fail(f'README spam count stale — found {spam_count} .eml files, README missing "{spam_count}/"')

# Scam was unvalidated until v6.55.0 — the count drifted from 4 to 5 with
# nothing to catch it, which is the same gap the spam/ham checks exist to close.
scam_count = len(list((ROOT / 'tests/scam_examples').glob('*.eml')))
if f'{scam_count}/{scam_count} scam' in readme:
    ok(f'README scam count ({scam_count}/{scam_count})')
else:
    fail(f'README scam count stale — found {scam_count} .eml files, '
         f'README missing "{scam_count}/{scam_count} scam"')

if f'{ham_count}/' in readme:
    ok(f'README ham count ({ham_count}/{ham_count})')
else:
    fail(f'README ham count stale — found {ham_count} .eml files, README missing "{ham_count}/"')

# ── 2. @version matches the newest CHANGELOG.md entry ────────────────────────
#
# Reads CHANGELOG.md, not the source header. The changelog lived in the header
# comment until v6.49.0, where it had reached 459 lines and three consecutive
# entries described three incompatible designs for the same function. Moving it
# out shrank the header from 494 lines to 41, and this check moved with it.
gs = (ROOT / 'SpamDetector.gs').read_text()

header_match = re.search(r'^ \* @version\s+([\d.]+)$', gs, re.M)
header_ver   = header_match.group(1) if header_match else '(not found)'
header_vtag  = f'v{header_ver}'

changelog_path = ROOT / 'CHANGELOG.md'
if not changelog_path.exists():
    fail('CHANGELOG.md is missing — the release history lives there since v6.49.0')
else:
    changelog = changelog_path.read_text()
    first = re.search(r'^## v([\d.]+)$', changelog, re.M)
    changelog_ver = first.group(1) if first else '(not found)'

    if header_ver == changelog_ver:
        ok(f'@version matches the newest CHANGELOG.md entry ({header_vtag})')
    else:
        fail(f'@version ({header_vtag}) does not match the newest CHANGELOG.md '
             f'entry (v{changelog_ver}) — add an entry before releasing')

    # Entries must be newest-first, or "newest" above is meaningless.
    versions = [tuple(int(x) for x in v.split('.'))
                for v in re.findall(r'^## v([\d.]+)$', changelog, re.M)]
    if versions != sorted(versions, reverse=True):
        fail('CHANGELOG.md entries are not in descending version order')
    else:
        ok(f'CHANGELOG.md is newest-first ({len(versions)} entries)')

# ── 3. @version header and SCRIPT_VERSION constant agree ─────────────────────
#
# Replaces a check that required the current version to appear in README's
# CI/CD section. That section shows a deliberately illustrative tag example, so
# the check failed on every release and told the reader to "update" something
# never meant to track the version. It rotted unnoticed because nothing ran
# this script; it is now wired into CI.
#
# This check matters instead: CI patches both markers from the commit subject,
# masking drift at deploy time while leaving it in the repo, and a commit
# subject with no version deploys whatever was hand-edited. A stale
# SCRIPT_VERSION silently disables the new-deploy maintenance trigger.
gs_src       = (ROOT / 'SpamDetector.gs').read_text(encoding='utf-8')
header_match = re.search(r'^ \* @version (\S+)$', gs_src, re.M)
const_match  = re.search(r"^const SCRIPT_VERSION = '([^']*)';$", gs_src, re.M)

if not header_match:
    fail('no " * @version X.Y.Z" line found in SpamDetector.gs')
elif not const_match:
    fail('no "const SCRIPT_VERSION = ..." line found in SpamDetector.gs')
elif header_match.group(1) != const_match.group(1):
    fail(f'@version ({header_match.group(1)}) disagrees with SCRIPT_VERSION '
         f'({const_match.group(1)}) — a stale SCRIPT_VERSION silently disables '
         f'the new-deploy maintenance trigger')
else:
    ok(f'@version and SCRIPT_VERSION agree ({header_match.group(1)})')

# ── Result ────────────────────────────────────────────────────────────────────
print()
if not errors:
    print('🎉  All checks passed')
    sys.exit(0)
else:
    for e in errors:
        print(e)
    print(f'\n💥  {len(errors)} check(s) failed — fix before pushing')
    sys.exit(1)
