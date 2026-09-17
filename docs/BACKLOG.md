# Backlog

Deferred work, as of **v6.60.1** (2026-09-17).

Everything here was surfaced by two external reviews — a Google L6 security pass
and a Palo Alto Networks L6 code/docs pass — plus findings from the day's own
incidents. The urgent items from both reviews are done; this is what was
deliberately *not* done, and why.

Each entry says **why it can wait** and **what would escalate it**. That second
part matters more than the ordering: priorities here are a judgement about
today's conditions, and conditions change.

---

## Where to pick up

**Prod state at v6.55.0.** Healthy and unattended. Verified: the 1-minute
trigger runs under the narrowed OAuth grant (v6.48.1 removed
`script.external_request`); inbox fully processed; no false positives;
detection log at 591 rows.

**Before touching anything,** run these and confirm green:

```bash
python3 tests/test_spam_detector.py     # corpus + edge cases
node tests/test_disposition.js          # the code that deletes mail
node tests/test_link_graph.js           # URL parsing + Signal 7
node tests/test_patch_version.js        # deploy-time version patch
python3 scripts/validate.py             # repo consistency
```

Then confirm prod is alive. Cheapest signal: new inbox mail picking up
`SpamChecked`. Also check `CHANGELOG.md`'s newest entry matches `@version`.

**First concrete action: Tier 1.2, the retention policy.** It is the only open
item with an ongoing cost rather than a hypothetical one — every misjudged
legitimate email's full content accumulates in Drive with no expiry. It is also
self-contained: one maintenance step, no scope change, no re-authorization, and
`destroySpam()`'s paging loop is the shape to copy.

**Watch before changing more.** Two behaviours shipped 2026-09-16 that have not
been observed over a meaningful period:

- `reviewGmailSpam()` (v6.50.0) re-judges Gmail's spam verdicts and deletes only
  on agreement. Its agreement rate is unknown. If it rarely agrees, our rules
  are weaker than Gmail's on that population and the folder stays cluttered.
  Look for `GMAIL_SPAM_CONFIRMED` rows in the Sheet.
- `holdForReview()` (v6.48.0) makes the recheck pass label instead of delete. A
  filling `SuspectedSpam` label is the early warning that a recently deployed
  pattern is over-matching.

**Not in the repo.** `BLOG.md` (813 lines) and `tests/SESSION_REPORT.md` (518)
are both in `.gitignore`, so neither survives a fresh clone. `BLOG.md` is the
best-written document in the project and is frozen at v6.33.0 — if it matters,
track it. `SESSION_REPORT.md` describes a 3-rule v5.1 architecture; delete it.

---

## The pattern worth remembering

Across eleven releases in one day, the recurring failure was **fixing the
instance and not the class**:

- The substring domain matcher was fixed in `collectSignals()` and missed the
  duplicate in `cleanseInbox()`, which then permanently deleted mail for three
  more releases.
- "Archive before delete" was asserted in **four** comments and enforced in
  **none** — the Drive write actually happened *after* the `batchDelete`.
- The memory fix was half-applied: `archiveRawEml()` went synchronous but
  `rawContent` stayed in the buffer with no consumer.
- Signal 8 (v6.52.0) was written to catch a specific free-mail sender and could
  not see it: the message already carried `SpamChecked` from the previous
  review logic, and phase 1 excludes that label unconditionally. Two releases
  aimed at six messages changed nothing about those six messages. v6.54.0 makes
  the exclusion version-aware.

- v6.54.0's forced re-review then made an existing cosmetic bug unbounded:
  phase 1 logged a Sheet row for whitelisted mail it deliberately kept, and
  since whitelisted mail never leaves the Spam folder, every deploy re-judged it
  and appended another pair of rows. Fixing one leak opened another of the same
  shape (v6.49.1, v6.50.1, now v6.54.0 — three in a row).

Two lessons worth carrying. First: **a cache of a decision must be
invalidated by a change to the thing that decides.** `SpamChecked` recorded
"reviewed" as a permanent property of the message when it is really a property
of the logic that reviewed it. Any state that lets work be skipped needs an
answer to "what invalidates this?" — and "nothing" is only correct when the
decision cannot change.

What held were the things encoded as **executable invariants**, not prose:
`disposeDetectedMessage()` refusing to delete without a Drive file id,
`destroySpam()` refusing to sweep without its label, and
`tests/test_disposition.js` asserting both.

Second: **before widening what a periodic pass looks at, check what that pass
writes.** A forced re-review is only safe if every branch it can reach is
idempotent. Phase 1's delete branches were (the message is gone), its
leave-alone branch was (no row), and its whitelist branch was not. The question
"what does this do on the second pass over the same message?" would have caught
it, and is worth asking of every branch in `reviewGmailSpam()` and
`recheckRecentSpamChecked()` before touching their scope again.

**The Python-mirror drift risk is closed** (v6.60.0). It was the oldest open
item here and the one with a proven bite: `tests/test_spam_detector.py`
hand-mirrors the detection logic, Option B covers only the pattern CONSTANTS,
and a fix applied to `SpamDetector.gs` and not to the mirror passed CI silently
— which happened once, caught by accident. Hand-copied "parity tables" in both
suites were the previous mitigation and had the same flaw one level up: a human
had to remember both copies.

Phase 7 now runs all 81 fixtures through the shipped JavaScript *and* the Python
mirror and fails on any disagreement, plus fails when a signal exists in the
`.gs` with no Python counterpart. Both failure paths were verified by
deliberately introducing each fault. It extends itself: new fixtures and new
signals are compared automatically.

A related gap, now closed: the README **scam** count was never CI-validated, and
it drifted 4 → 5 in v6.55.0 with nothing to catch it, while spam and ham had had
checks for releases. An unvalidated sibling of a validated thing is a good place
to look for the next silent drift.

> **Rule for anything touching irreversible deletion: write the assertion, not
> the comment.** A comment describing an invariant is a wish. A test is the
> invariant.

---

## Settled on 2026-09-16 — do not re-litigate

- **Spam folder disposition.** Took three attempts; the third is in v6.51.0.
  v6.46.0 stopped the blanket sweep (it was permanently deleting Gmail's false
  positives, unarchived). v6.50.0 required our own rules to agree before
  deleting — which left obvious spam in the folder, because those rules are
  tuned for inbox-delivered mail and have no reputation data. Inverting to
  "delete unless whitelisted" was drafted and **blocked in review**: it made a
  16-entry hand-maintained list the sole guard on a permanent-delete path, and
  verifiably destroyed bank alerts, 2FA mail and first-contact messages.
  **The answer was time, not a better verdict.** v6.51.0 age-gates the query
  (`older_than:CONFIG.gmailSpamGraceDays`, default 7). The folder empties on a
  rolling basis, Gmail's mistakes keep a visible one-click recovery window, and
  young mail is never fetched so the grace period is free. Whitelisted senders
  are never deleted at any age — belt-and-braces, not sole protection.
  Nothing is ever moved back to the inbox: a wrong whitelist entry would
  re-deliver real spam.
  *Lesson: when a destructive decision is uncertain, buy a recovery window
  rather than a better guess.*
- **Rule 7 quarantines; Rules 1–6 delete.** Rule 7 has an irreducible
  false-positive class; the others key on sender reputation or content the
  sender chose.
- **The recheck pass holds rather than deletes** (v6.48.0). It overrules a
  decision the user already made, using a pattern deployed minutes earlier.
  `checkFalseNegatives()` still deletes, because a manual `SpamMissed` label is
  the user *asking* for it — **but since v6.53.0 it refuses when the sender is
  whitelisted.** One deliberate click justifies deletion; a mis-click on a Gmail
  multi-select does not, and labelling forty threads is two keystrokes. Two
  standing instructions conflict there, so the non-destructive one wins and the
  thread moves to `SuspectedSpam` where the user can see it.
- **Nothing is deleted without a Drive archive** (v6.47.0). Enforced in
  `disposeDetectedMessage()`, asserted in `test_disposition.js`.

---

## Tier 1 — Do these next

### 1.1 `drive` → `drive.file`

**What.** The script can currently read and write *every file in your Drive*.
It only ever creates and reads its own `Spam Intelligence` folder.
`drive.file` grants access only to files the app itself created.

**Why it can wait.** It's a blast-radius reduction, not a live bug. The
higher-value half of the scope work already shipped in v6.48.1 — removing
`script.external_request` took away the *network* primitive, so code in this
project can destroy mail but can't send it anywhere.

**Why it's fiddly.** `drive.file` only sees files created *under that scope*.
The existing `Spam Intelligence` folder was created under full `drive`, so it
may become invisible and the script would create a fresh one. The 591-row Sheet
and archived EMLs wouldn't be lost, but might no longer be writable.

**Plan.**
1. Reproduce on a throwaway Apps Script project: create a folder under `drive`,
   switch the manifest to `drive.file`, confirm whether `getFolderById()` still
   resolves it.
2. If it doesn't: add a one-time migration that re-creates the folder under the
   new scope and moves existing files, or accept a fresh folder and document
   where the old archive lives.
3. Ship the manifest change, then revoke + re-approve (a narrowed manifest does
   **not** prompt — see v6.48.1 in `CHANGELOG.md`).

**Escalates if:** any other app gets granted broad Drive access, or the archive
starts holding mail you'd mind exposed.

### 1.2 Retention policy for the Drive archive

**What.** No expiry, no cap, no cleanup. Every detected message's full RFC822
is kept forever — **including legitimate mail the detector misjudged**.

**Why it matters more than it looks.** This isn't a compromise scenario, it's
normal operation. A false positive takes an email that lived only in Gmail and
copies its full content into Drive, where it's indexed by Drive search, visible
to Drive-sync clients, inside any future share of a parent folder, and reachable
by every app holding a Drive scope.

**Why it can wait.** Volume is low (591 detections since May) and the folder is
private-to-owner — verified: no `setSharing`, `addEditor`, `addViewer` or
`setOwner` call exists anywhere in the source.

**Plan.** Add a maintenance step deleting EMLs older than N days (90?), keeping
the Sheet row forever — the row is the training data, the EML is only the
recovery copy. Document the window in the README next to the recovery
instructions. Note `destroySpam()`'s paging loop is the shape to reuse.

**Escalates if:** detection volume rises, or you ever share the parent folder.

### 1.3 Signals fail open, one throw at a time

`collectSignals()` — Signals 5 and 7 are individually wrapped in `try/catch`,
which is correct and deliberate. Signals 1a, 2, 2b–2d, 3, 4 and 6 are not, so a
single throw from `getRawContent()` or `getPlainBody()` discards *all* of them,
and `analyzeMessage()`'s catch-all returns `{isSpam: false}`.

Worse, `processInbox()` still stamps `SpamChecked`, so the message is never
re-examined — an attacker-triggerable permanent exemption via malformed MIME.

**Plan.** Wrap each signal block the way 5 and 7 already are. Where the whole
verdict is unavailable, `logError` and **do not** apply `SpamChecked`, so the
message is retried rather than exempted. Add a disposition assertion: a message
whose `getRawContent()` throws must not end up labelled clean.

**Escalates immediately** if you ever see a message sail through that obviously
should have been caught — this is the mechanism that would explain it.

---

## Tier 2 — Worth doing, no urgency

### 2.1 CI/CD hardening

Four items, all in `.github/workflows/deploy.yml`:

| Item | Risk |
|---|---|
| Actions pinned to mutable major tags (`checkout@v5`, `setup-node@v5`, `cache@v5`) | A compromise of any action runs attacker code in the job holding `CLASP_TOKEN`. Pin to full commit SHAs. |
| `npm install -g @google/clasp@3.3.0` resolves the transitive tree fresh with install scripts enabled | A postinstall can't read the token (it's written *after* install) but can plant a wrapper that runs at `clasp push`. Use a lockfile + `npm ci`, or `--ignore-scripts`. |
| `validate` is fail-open and `tag` trusts it | Validate exits 0 when it can't get a token, and `Refresh OAuth token` is `continue-on-error: true`. So a release can be tagged for a deploy that was never verified. Distinguish *couldn't check* from *checked and passed*. |
| `concurrency: cancel-in-progress: true` spans all four jobs | A second push can cancel between `deploy` and `validate`, leaving new detection logic live, unverified and untagged. Scope cancellation to `test`, or set `false`. |

Also: no branch protection and no Environment gate on `deploy`. Anything that
can push to `main` deploys code holding `https://mail.google.com/`. That is the
single reason Tier 1.1 matters.

**Why it can wait.** The workflow runs on `push` to `main` only — no
`pull_request` trigger — so a fork PR cannot reach the secrets. That closes the
classic exfiltration route already.

### 2.2 Port the corpus harness to Node, delete the Python mirror

`tests/test_spam_detector.py` hand-reimplements seven link-graph helpers
(`_extract_url_host`, `_is_link_wrapper_host`, `_has_brand_mismatched_cta`, …) —
~200 lines of duplicated **logic**, which breaks the single-source-of-truth
property the whole parse-the-`.gs` architecture exists to provide.

**This has already bitten once:** v6.45.0's fixes landed in the `.gs` and not in
the mirror, and a new scam fixture caught it. Both sides now carry a parity
table, which is a mitigation, not a fix.

**Plan.** `tests/test_disposition.js` already proves the shipped `.gs` can run
against fake messages. `parse_eml` is the only genuinely Python-specific piece.
Port the corpus runner to Node, delete the mirror, and have all four suites test
one implementation. Interim step: delete the ~40 assertions in
`run_edge_case_tests()` that duplicate `test_link_graph.js`, keeping the mirror
as a scoring detail with one parity smoke test.

### 2.3 Split `SpamDetector.gs`

4,000 lines in one file. clasp pushes multiple `.gs` files into one project with
shared global scope, so there's no module boundary — but there *is* a file
boundary, and that's enough for navigation.

Proposed: `Config.gs`, `Patterns.gs` (~400 lines of constants), `Detect.gs`,
`LinkGraph.gs`, `Disposition.gs`, `Logging.gs`, `Admin.gs`.

**Cost.** The Python harness's `_GS_PATH` becomes a glob, and `.claspignore`'s
whitelist grows. **Worth it because** `Patterns.gs` alone would stop routine
pattern edits from touching the same file as disposition logic — which is
exactly how today's stale comments accumulated.

### 2.4 `LockService` only guards `processInbox()`

`cleanseInbox()`, `destroySpam()`, `checkFalseNegatives()`
and `reviewGmailSpam()` are all callable from the editor with no lock, alongside
the 1-minute trigger. `cleanseInbox()` is the dangerous combination: 500
threads, guaranteed to exceed the 6-minute limit. Every destructive entry point
should take the same script lock.

### 2.5 ~~`purgeAllSpamNow()` needs a dry run~~ — CLOSED in v6.60.1

Moot: the function is gone. It was a one-click editor function that deleted up
to 1,000 messages including Gmail-classified mail the script never evaluated,
with no preview — and it was never once invoked. Deleting unused code that can
destroy mail beats adding a dry-run flag to it.

Removed alongside `setupTrigger()` and `reviewSpamFolderNow()`, which were also
never called by anything. If the empty-the-folder capability is ever wanted
back, build it with a `DRY_RUN` default from the start.

---

## Tier 3 — Nits

- **`markAsSpam()` fallbacks are thread-scoped.** The primary path correctly
  targets one message id; both fallbacks call `thread.moveToSpam()`, moving your
  own replies in a reply-chain lure. Use `Gmail.Users.Messages.modify` on the
  single id, and `moveToArchive()` rather than `moveToSpam()`.
- **`shouldProcessMessage()` compares chars to bytes.** `getBody().length` is
  UTF-16 chars, `maxEmailSizeBytes` is bytes. Its docstring also claims these
  are "typically emails with large attachments" — `getBody()` returns the HTML
  part and never includes attachments. Both the unit mismatch and the rationale
  are wrong.
- **Module-level `let`s declared ~1,700 lines after their consumers.**
  `_cachedWhitelist`, `_quarantinedMessageIds`, `_labelIdCache` all live inside
  the logging section. It works, but it's invisible state — hoist to one
  `// Per-execution state` block near the top.
- **`BRAND_CTA_DOMAINS` carries a "no braces in this object" constraint**
  because the Python harness's `_extract_brace_content` is a naive brace counter
  while `_extract_bracket_content` has a proper state machine. Fix the parser and
  drop the constraint from production source.
- **`LIMITS.maxHtmlScanChars` carries a note about the test harness's regex.**
  Production code constrained by a test parser. The note belongs next to the
  parser.
- **Four suites, three output conventions, no single runner.** A `make test`
  running all four in CI order would help — and would have caught `validate.py`
  rotting unwired.
- **`BLOG.md` is frozen at v6.33.0** (16 releases back) and its "Technical Debt"
  section lists items since shipped. Either append v6.34–v6.49 or stamp it
  "frozen at v6.33.0". It's genuinely the best-written document here; its
  "Lessons" section is what the header changelog was trying and failing to be.
- **`tests/SESSION_REPORT.md`** describes a 3-rule v5.1 architecture and a
  1,256-line source file. Untracked, so it isn't rotting the repo — delete it.

---

## Known evasions — deliberately accepted

These are documented trade-offs, not oversights. Listing them so nobody
rediscovers them as bugs.

| Evasion | Cost | Why accepted |
|---|---|---|
| Name a brand not on the 13-key list (`VIEW IN QUICKBOOKS`) | zero | Inherent to a local list. And the list can't just be grown — `signnow` had to be *removed* because "Sign Now" is an ordinary button label. |
| Omit the CTA verb (`Your DocuSign document`) | one word | The verb requirement is load-bearing against footer-prose false positives. Genuine precision/recall trade. |
| Send from the lure's own domain | one domain (already owned) | Sender-alignment abstention is what keeps legitimate senders out. Partly fixable by conditioning on DKIM-authenticated alignment rather than the raw From header. |
| Pad past `maxAnchorsScanned` (300) or `maxHtmlScanChars` (256KB) | trivial | Documented cost bounds. Raising them trades ReDoS headroom for recall. |
| Send through an ESP not in the 5-string `BULK_EMAIL_FINGERPRINTS` | small | Disables Rules 1–3 outright, leaving only Rule 4's 3-clickbait threshold. Structural property of a fingerprint list. |
| A fresh cousin domain with valid DKIM and no clickbait vocabulary | one domain | **This is the class that motivated Signal 7 and it will recur.** No reputation, WHOIS-age or DMARC-alignment data is available locally. The durable answer is sender-familiarity state (first-contact detection), which needs persistence and should quarantine, not delete. |

---

## What I would *not* do

- **Hedged-financial-language patterns.** Rejected twice, and the reasoning
  holds: anything incrementing `clickbaitCount` feeds Rule 3 at a threshold of
  1, so one such pattern plus `Precedence: bulk` puts every legitimate tax and
  law-firm newsletter one signal from deletion.
- **Footer-disclaimer-as-evasion-marker.** Every legitimate financial sender
  carries "not investment advice" boilerplate. Treating legitimacy markers as
  suspicion is how filters get inverted, and it's trivially removable.
- **Ticker/brand display-name mismatch.** Needs a brand→domain mapping that
  doesn't exist offline, with unbounded false-positive exposure on every company
  whose sending domain differs from its corporate domain — which is most of them.
- **Restricting `isBulkEmail()` to the header block.** Narrowing bulk detection
  can only turn caught spam into misses. The body-wide scan is wasteful, now
  bounded to 64KB, and not worth the regression risk.
