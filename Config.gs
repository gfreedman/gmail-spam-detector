/**
 * Gmail Spam Detector - Google Apps Script
 * @version 6.62.0
 *
 * Automated spam detection and destruction for Gmail. Runs on a 10-minute
 * trigger (a scheduled task), scanning the inbox for unprocessed emails and
 * applying a multi-signal pattern detection engine.
 *
 * Detection strategy — target behavioral patterns spammers can't easily change:
 *   - Bulk email infrastructure (Amazon SES, SendGrid, Mailchimp)
 *   - Clickbait/fear-mongering subject patterns
 *   - Unicode obfuscation (Cyrillic, Greek, fullwidth, mathematical chars)
 *   - Marketing sender format
 *   - Blacklisted sender domains (known spam mills)
 *   - Suspicious From-field anomalies (headline-like display names)
 *   - Link-graph anomalies (CTA text naming a brand the destination lacks)
 *   - Machine-generated free-mail sender addresses (throwaway accounts)
 *
 * Execution flow:
 *   1. processInbox() — scan inbox, analyze each email, flag spam
 *   2. markAsSpam()   — report to Gmail (trains filters) + immediately delete by ID
 *      quarantineAsPhishing() — Rule 7 only: report + label, NO delete
 *   3. destroySpam()  — safety-net sweep of this detector's own verdicts
 *   5. auditRunIntegrity() — verifies the run did what it believes it did;
 *      writes AUDIT_* rows to the Sheet when an invariant is violated
 *   4. reviewGmailSpam() — deletes Gmail-classified spam after a grace period
 *      (CONFIG.gmailSpamGraceDays); whitelisted senders are never deleted.
 *      A version change re-reviews the whole folder, so an improved rule is
 *      applied to spam the previous logic already dismissed.
 *   6. writeSpamFolderSnapshot() — publishes the current Spam folder, and what
 *      this detector intends to do with each message, to the "Spam Folder" tab.
 *      The folder is invisible to API clients (SPAM is excluded from search by
 *      default), so this script is the only thing that can report it.
 *
 * Decision logic (9 rules, evaluated in priority order — first match wins):
 *   Rule 1: Bulk email + blacklisted sender domain → spam
 *   Rule 2: Bulk email + 2+ clickbait patterns → spam
 *   Rule 3: Bulk email + 2+ distinct spam behaviors → spam
 *   Rule 4: 3+ clickbait patterns (no bulk email required) → spam
 *   Rule 5: Empty subject + attachment → payload delivery scam
 *   Rule 6: Cloud service notification subject from non-service sender → phishing
 *   Rule 7: CTA link text names a document brand the href does not belong to → phishing
 *           (QUARANTINED: archived + labelled, never deleted — see quarantineAsPhishing)
 *   Rule 8: Free-mail machine-generated sender + 2+ spam behaviors → spam
 *   Rule 9: Free-mail sender invoicing as a brand it does not control, with a
 *           phone number as the payload → callback phishing
 *           (QUARANTINED: archived + labelled, never deleted)
 *
 * Changelog: see CHANGELOG.md. It is not reproduced here — it reached 459
 * lines and three consecutive entries described three incompatible designs for
 * the same function as if all were current, which made the live contract hard
 * to find. This block documents only what is true NOW.
 *
 * Setup: See README.md or run setup() and follow the logs.
 */


// =============================================================================
// Configuration
// =============================================================================

/**
 * Global configuration — frozen to prevent accidental modification at runtime.
 *
 * Why "frozen"? In JavaScript, objects are normally mutable — any code can do
 * CONFIG.maxEmailsPerRun = 999. Object.freeze() prevents that. If you try to
 * modify a frozen object, JavaScript throws a TypeError immediately instead of
 * silently ignoring the change (which is the default JS behavior and a common
 * source of hard-to-find bugs).
 *
 * These values control processing limits, detection thresholds, and safety caps.
 *
 * @const {Object}
 */
/**
 * Deployed script version, as a runtime-readable value.
 *
 * Mirrors the version tag in the header comment, but must be a real constant
 * because runPeriodicMaintenance() compares it against the last version seen
 * in Script Properties to detect that a new deploy has landed.
 *
 * Patched automatically by the deploy workflow from the commit message, in a
 * separate sed from the header tag. (The header-tag sed is anchored to
 * "^ * @version " as of v6.43.0, so it cannot reach this line.)
 *
 * @const {string}
 */
const SCRIPT_VERSION = '6.62.0';

const CONFIG = Object.freeze({
  /** Max emails per run — prevents Apps Script 6-minute execution timeout */
  maxEmailsPerRun: 50,

  /** How many days back to scan for unprocessed emails */
  daysToCheck: 1,

  /** Days a GMAIL-classified message sits in Spam before this detector will
   *  delete it.
   *
   *  This is the most safety-relevant number in the file. Gmail intercepts that
   *  mail before the inbox, so our rules never judged it, and Gmail's own
   *  false-positive classes — first contact from a new correspondent, 2FA from a
   *  small service with imperfect DKIM, an invoice on a cheap relay — are
   *  exactly the mail no whitelist can enumerate in advance. The grace period
   *  is their recovery window: the folder is visible, searchable, and one
   *  "Not spam" click from undoing Gmail's mistake.
   *
   *  Gmail's own retention is 30 days. Seven still empties the folder on a
   *  rolling basis while leaving a real window. Lowering it trades that window
   *  for tidiness; 0 would be the blanket sweep that destroyed mail in the
   *  first place. */
  gmailSpamGraceDays: 7,

  /** Gmail label applied to processed emails to prevent reprocessing */
  processedLabel: 'SpamChecked',

  /** Label for mail held for human review rather than acted on. Applied by
   *  cleanse mode, by the recheck pass, to messages too large to evaluate, and
   *  to anything a destructive rule matched but which could not be archived.
   *  Nothing carrying this label has been deleted. */
  reviewLabel: 'SuspectedSpam',

  /** Label applied by markAsSpam() before it deletes, so destroySpam() can
   *  sweep ONLY mail this detector condemned. Without it the sweep deleted the
   *  whole Spam folder, including mail GMAIL classified that this script never
   *  evaluated — permanently, with no Drive archive and no log row. Gmail's own
   *  false positives are now left alone; Gmail auto-purges Spam at 30 days. */
  purgeLabel: 'SpamDetectorPurge',

  /** Label applied to quarantined phishing (Rule 7). The message is archived
   *  out of the inbox and labelled, never deleted and never moved to Spam, so
   *  it stays in All Mail indefinitely — not subject to Gmail's 30-day spam
   *  purge. Also excluded by buildSearchQuery() so it is not re-detected. */
  phishingLabel: 'Phishing',

  /** Enable verbose debug logging (set true for troubleshooting) */
  debug: false,

  /** Max email size to process — prevents memory issues with large attachments */
  maxEmailSizeBytes: 5 * 1024 * 1024 // 5MB
});


// =============================================================================
// Default Domain Lists
// =============================================================================

/**
 * Default whitelist and blacklist for initial setup.
 * Actual runtime lists are stored in Script Properties (persistent key-value
 * store) and managed via addToWhitelist()/addToBlacklist().
 * These defaults are only written on first setup via initializeScriptProperties().
 *
 * @const {Object}
 */
const DEFAULT_DOMAINS = Object.freeze({
  /** Known legitimate senders — bypass spam detection entirely */
  legitimate: Object.freeze([
    'sardine.ai', 'meetup.com', 'substack.com', 'conservative.ca',
    'conservativebc.ca',
    'sundaymass.store', 'customerservice@stan', 'privaterelay.appleid.com',
    'email.meetup.com', 'ben-evans.com', 'linkedin.com', 'e.linkedin.com',
    'linkedin.email', 'dsf.ca', 'dragonfly', 'ezyvet.com'
  ]),
  /** Known spam mill domains — triggers Rule 1 when combined with bulk email */
  suspicious: Object.freeze([
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
    'frontiercapitalreport.com',
    'morningstockadviser',
    '1stamericanpath.com',
    'finrisex.com',
    'economicrulebook.com',
    'bondlyst.com',
    'atlantisinvestors.com'
  ])
});


// =============================================================================
// Internal Limits
// =============================================================================

/**
 * Named constants for internal thresholds — prevents magic numbers scattered
 * through detection and sanitization logic.
 *
 * @const {Object}
 */
const LIMITS = Object.freeze({
  /** From display names longer than this are flagged as suspicious (keyword stuffing) */
  maxDisplayNameLength: 50,

  /** Input truncation cap — some regex patterns take exponentially long on huge strings
   *  (called "ReDoS"). 100 000 chars is far more than any real email field needs. */
  maxInputChars: 100000,

  /** Log message truncation — prevents a crafted subject from inserting fake log lines
   *  (e.g. a subject of "OK\n[ERROR] Deleted everything" would print two log lines). */
  maxLogChars: 100,

  /** Max HTML characters scanned for anchors by extractAnchors(). Real marketing
   *  HTML is well under 100 000; 262 144 is generous headroom while still capping
   *  worst-case scan cost on a hostile 5 MB body.
   *  NOTE: write these as bare integers, never `256 * 1024` — the Python test
   *  harness parses LIMITS with /(\w+)\s*:\s*(\d+)/ and would load "256". */
  maxHtmlScanChars: 262144,

  /** Max anchors examined per message. Calls-to-action appear early; a document
   *  with 300+ links is a directory dump, not a lure. Bounds the exec() loop. */
  maxAnchorsScanned: 300,

  /** Max characters written to a single Google Sheets cell. Sheets' own limit
   *  is 50 000 and exceeding it makes setValues() throw, which discarded the
   *  log rows for an entire batch — all of which were already deleted. */
  maxSheetCellChars: 5000,

  /** Subject/From truncation for PATTERN MATCHING.
   *  maxInputChars (100 000) is three orders of magnitude larger than any real
   *  subject, and several patterns have the shape X.*Y, which is QUADRATIC when
   *  X matches at many positions. A 100KB subject of "Trump " measured 3.5s
   *  across the pattern set, and 200KB across subject+from measured 14s — one
   *  email exceeding the 6-minute budget, which kills the run, leaves the
   *  threads unlabelled, and makes the next trigger repeat it forever. */
  maxSubjectChars: 2000,
  maxFromChars: 500,

  /** Max characters of raw RFC822 scanned for bulk-sender fingerprints. All
   *  fingerprints live in headers, so scanning the whole message (which can be
   *  25MB with attachments) only allocated a second copy of it. */
  maxRawScanChars: 65536,

  /** Max characters scanned for a single opening <a ...> tag. Bounds the
   *  quote-aware findTagEnd() scan; a real anchor tag with inline styles is
   *  a few hundred characters. */
  maxAnchorTagChars: 4000,

  /** Max characters of inner text read per anchor before giving up on </a>.
   *  Without this an unclosed <a> would scan to end-of-document, and N unclosed
   *  anchors would cost O(N x doclen). */
  maxAnchorTextChars: 2048,

  /** Upper bounds used by validateConfig() to catch misconfiguration.
   *  For example, setting maxEmailsPerRun to 10 000 would hit Apps Script's
   *  6-minute timeout and crash every run. These constants prevent that.
   *  They are NOT used by the detector itself — only by validateConfig(). */
  maxAllowedEmailsPerRun: 500,
  maxAllowedDaysToCheck: 30
});
