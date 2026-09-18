#!/usr/bin/env python3
"""
Answer "is the deployed detector alive and healthy?" — no setup, no token.

    python3 scripts/prod_health.py

Uses the credentials `clasp login` already wrote to ~/.clasprc.json. Exits 0
when healthy and 1 otherwise, so cron or CI can gate on it.

Why it reads a Drive file NAME
------------------------------
Getting at prod health turned out to be the hard part, not producing it:

  * Logger.log writes to the Apps Script execution transcript, which the Apps
    Script API will not serve without the script.processes scope -> 403.
  * console.* writes to Cloud Logging under the GCP project attached to the
    script. This script uses the auto-created default project; the project named
    in .clasp.json has never received a single log entry. Attaching a standard
    project is a manual console procedure with an OAuth consent screen.
  * The Health tab in the log spreadsheet is the surface a human reads, but the
    Sheets API is not enabled for clasp's OAuth client, so reading it
    programmatically needs a separately minted access token. Requiring someone
    to hand-craft a token before they can ask "is it running?" is not a health
    check.

Drive *metadata* is readable with exactly the credentials clasp already has, and
a file name is metadata. So the detector renames one marker file each run and
this reads the name back. See updateHealthMarker() in src/Intelligence.gs.

Checks
  1. A marker exists and is recent   -> the trigger is actually running
  2. Marker version == local version -> the deploy took effect
  3. Marker status == OK             -> run completed, no in-run errors, and no
                                        audit findings (see auditRunIntegrity)
"""
import argparse, datetime, json, os, re, sys, urllib.error, urllib.parse, urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sources  # noqa: E402  (path must be set up first)

PREFIX = 'SpamDetector_health_'
# SpamDetector_health_<STATUS>_v<VERSION>_<ISO8601>
MARKER = re.compile(r'^' + PREFIX + r'(?P<status>[A-Z_]+)_v(?P<ver>[\d.]+)_(?P<ts>.+)$')

fail = []
def ok(m):  print('\033[92m✅\033[0m  ' + m)
def bad(m): fail.append(m); print('\033[91m❌\033[0m  ' + m)


def access_token():
    """
    Refresh the clasp credential.

    Handles every shape this file has been seen in, because the CI secret and a
    local `clasp login` do not agree: clasp@3.x writes {"tokens": {"default":
    {...}}}, older versions wrote {"token": {...}} or a flat object, and the
    client id/secret may sit in a sibling `oauth2ClientSettings` rather than
    alongside the refresh token. The deploy workflow already carries this same
    tolerance; keeping the two in step matters because CI runs this script
    against the secret, not against a local login.
    """
    p = os.path.expanduser('~/.clasprc.json')
    if not os.path.exists(p):
        sys.exit('No ~/.clasprc.json — run:  npx @google/clasp@3.3.0 login')
    raw = json.load(open(p))
    t = (raw.get('token')
         or (raw.get('tokens') or {}).get('default')
         or raw.get('tokens')
         or raw)

    refresh = t.get('refresh_token')
    if not refresh:
        sys.exit('No refresh_token in ~/.clasprc.json (top-level keys: %s) — '
                 're-run clasp login' % sorted(raw.keys()))

    oa   = raw.get('oauth2ClientSettings', t.get('oauth2ClientSettings', {})) or {}
    cid  = oa.get('clientId')     or raw.get('client_id')     or t.get('client_id')
    csec = oa.get('clientSecret') or raw.get('client_secret') or t.get('client_secret')
    if not cid or not csec:
        sys.exit('No OAuth client id/secret in ~/.clasprc.json — re-run clasp login')

    body = urllib.parse.urlencode({
        'client_id': cid, 'client_secret': csec,
        'refresh_token': refresh, 'grant_type': 'refresh_token'}).encode()
    try:
        return json.load(urllib.request.urlopen(
            'https://oauth2.googleapis.com/token', body))['access_token']
    except urllib.error.HTTPError as e:
        sys.exit('Token refresh failed (%s) — re-run clasp login: %s'
                 % (e.code, e.read().decode()[:200]))


def find_marker(token):
    q = urllib.parse.urlencode({
        'q': "name contains '%s' and trashed = false" % PREFIX,
        'fields': 'files(name,modifiedTime)',
        'orderBy': 'modifiedTime desc', 'pageSize': '10'})
    req = urllib.request.Request('https://www.googleapis.com/drive/v3/files?' + q,
                                 headers={'Authorization': 'Bearer ' + token})
    try:
        files = json.load(urllib.request.urlopen(req)).get('files', [])
    except urllib.error.HTTPError as e:
        sys.exit('Drive query failed: %s %s' % (e.code, e.read().decode()[:200]))
    for f in files:
        m = MARKER.match(f['name'])
        if m:
            return m.groupdict(), f
    return None, files


def local_version():
    src = sources.concat_source()
    m = re.search(r"const SCRIPT_VERSION = '([\d.]+)'", src)
    return m.group(1) if m else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-age-min', type=float, default=10.0,
                    help='fail if the last run is older than this (default 10)')
    a = ap.parse_args()

    marker, extra = find_marker(access_token())
    if not marker:
        bad('no health marker in Drive — the detector has not run since '
            'v6.58.3 deployed, or Drive is unreachable')
        if extra:
            print('   (files matched but unparseable: %s)'
                  % ', '.join(f['name'] for f in extra[:3]))
        print(); print('\033[91m1 check(s) FAILED\033[0m'); return 1

    print('\nMarker: status=%s version=%s at=%s\n'
          % (marker['status'], marker['ver'], marker['ts']))

    # 1. liveness
    try:
        ts  = datetime.datetime.fromisoformat(marker['ts'].replace('Z', '+00:00'))
        age = (datetime.datetime.now(datetime.timezone.utc) - ts).total_seconds() / 60
        if age <= a.max_age_min:
            ok('trigger is running (last run %.1f min ago)' % age)
        else:
            bad('last run was %.1f min ago (limit %.0f) — trigger stalled, or the '
                'script throws before it can report' % (age, a.max_age_min))
    except ValueError:
        bad('unparseable timestamp in marker: %r' % marker['ts'])

    # 2. the deploy took effect
    want = local_version()
    if want and marker['ver'] == want:
        ok('live version is %s, matching local SCRIPT_VERSION' % want)
    elif want:
        bad('live version %s != local %s — the deploy did not take effect'
            % (marker['ver'], want))

    # 3. invariants held
    st = marker['status']
    if st == 'OK':
        ok('status OK (run completed, no in-run errors, no audit findings)')
    elif st == 'THREW':
        bad('status THREW — the run did not complete; see the Health tab\'s '
            'LastError column in the Spam Intelligence Log')
    elif st == 'AUDIT_FINDINGS':
        bad('status AUDIT_FINDINGS — an invariant was violated; look for AUDIT_* '
            'rows in the Raw Log tab')
    else:
        bad('status %s — see the Health tab' % st)

    print()
    if fail:
        print('\033[91m%d check(s) FAILED\033[0m' % len(fail)); return 1
    print('\033[92mprod healthy\033[0m'); return 0


if __name__ == '__main__':
    sys.exit(main())
