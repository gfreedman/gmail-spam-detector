#!/usr/bin/env python3
"""
Answer "is the deployed detector alive and healthy?" from outside Apps Script.

Why this exists
---------------
Every disposition bug this project shipped was invisible in production, and
until v6.58.0 prod health was not observable at all:

  * logInfo/logError wrote only via Logger.log, which lands in the Apps Script
    execution transcript. That transcript cannot be read by anything holding
    this project's credentials — the Apps Script API needs the
    script.processes scope the deploy credential lacks (403
    ACCESS_TOKEN_SCOPE_INSUFFICIENT).
  * console.log/console.error DO go to Cloud Logging, but under the GCP project
    attached to the script. This script uses the auto-created default project;
    the project named in .clasp.json has never received a single log entry.

So a clean run and a script that crashed on its first line looked identical
from outside: both write nothing readable. v6.58.0 writes one overwritten row
to a 'Health' tab in the existing log spreadsheet instead. This reads it back.

Checks
  1. LastRunAt is recent        -> the trigger is actually running
  2. Version matches local      -> the deploy took effect
  3. Status == OK               -> no in-run errors, no audit findings
                                   (see auditRunIntegrity in SpamDetector.gs)

Usage:  python3 scripts/prod_health.py [--max-age-min 10]

Exit 0 healthy, 1 otherwise, so cron or CI can gate on it.

Credentials: a token with spreadsheets.readonly. ~/.clasprc.json does NOT carry
that scope, so pass one via GOOGLE_OAUTH_ACCESS_TOKEN, or read the Health tab
directly in the spreadsheet UI — it is two columns wide and meant to be
human-glanceable too.
"""
import argparse, datetime, json, os, re, sys, urllib.error, urllib.request

ROOT     = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SHEET_ID = '1GAxEyshD0KChbV-C0karzQRt0dScmFAK_rhKtJQL9dY'

fail = []
def ok(m):  print('\033[92m✅\033[0m  ' + m)
def bad(m): fail.append(m); print('\033[91m❌\033[0m  ' + m)


def token():
    t = os.environ.get('GOOGLE_OAUTH_ACCESS_TOKEN')
    if t:
        return t
    sys.exit('Set GOOGLE_OAUTH_ACCESS_TOKEN to a token with '
             'spreadsheets.readonly (see module docstring).')


def local_version():
    src = open(os.path.join(ROOT, 'SpamDetector.gs'), encoding='utf-8').read()
    m = re.search(r"const SCRIPT_VERSION = '([\d.]+)'", src)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-age-min', type=int, default=10)
    ap.add_argument('--sheet-id', default=SHEET_ID)
    a = ap.parse_args()

    url = ('https://sheets.googleapis.com/v4/spreadsheets/%s/values/Health!A2:H2'
           % a.sheet_id)
    try:
        req = urllib.request.Request(url, headers={'Authorization': 'Bearer ' + token()})
        vals = json.load(urllib.request.urlopen(req)).get('values', [])
    except urllib.error.HTTPError as e:
        sys.exit('Sheets read failed: %s %s' % (e.code, e.read().decode()[:300]))

    if not vals:
        bad('Health tab is empty — the detector has never written a health row, '
            'so it has not run since v6.58.0 deployed')
        return 1

    (last_at, version, status, processed, spam,
     errors, findings, last_error) = (vals[0] + [''] * 8)[:8]
    print('\nHealth row: %s  v%s  %s  processed=%s spam=%s errors=%s findings=%s'
          % (last_at, version, status, processed, spam, errors, findings))
    if last_error:
        print('LastError : %s' % last_error)
    print()

    # 1. liveness
    try:
        ts  = datetime.datetime.fromisoformat(last_at.replace('Z', '+00:00'))
        age = (datetime.datetime.now(datetime.timezone.utc) - ts).total_seconds() / 60
        if age <= a.max_age_min:
            ok('trigger is running (last run %.1f min ago)' % age)
        else:
            bad('last run was %.1f min ago (limit %d) — trigger stalled or the '
                'script is throwing before it reports' % (age, a.max_age_min))
    except ValueError:
        bad('unparseable LastRunAt: %r' % last_at)

    # 2. deployed version
    want = local_version()
    if want and version == want:
        ok('live version is %s, matching local SCRIPT_VERSION' % version)
    elif want:
        bad('live version %s != local %s — the deploy did not take effect' % (version, want))

    # 3. invariants
    if status == 'OK':
        ok('status OK (run completed, no in-run errors, no audit findings)')
    elif status == 'THREW':
        bad('status THREW — the run did not complete: %s' % (last_error or '(no detail)'))
    else:
        bad('status is %s — check the Raw Log tab for AUDIT_* rows' % status)

    print()
    if fail:
        print('\033[91m%d check(s) FAILED\033[0m' % len(fail)); return 1
    print('\033[92mprod healthy\033[0m'); return 0


if __name__ == '__main__':
    sys.exit(main())
