/**
 * Gmail Spam Detector - Google Apps Script
 * @version 6.39.0
 *
 * Automated spam detection and destruction for Gmail. Runs on a 15-minute
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
 *
 * Execution flow:
 *   1. processInbox() — scan inbox, analyze each email, flag spam
 *   2. markAsSpam()   — report to Gmail (trains filters) + immediately delete by ID
 *   3. destroySpam()  — safety-net sweep of spam folder for stragglers
 *
 * Decision logic (5 rules, evaluated in priority order — first match wins):
 *   Rule 1: Bulk email + blacklisted sender domain → spam
 *   Rule 2: Bulk email + 2+ clickbait patterns → spam
 *   Rule 3: Bulk email + 2+ distinct spam behaviors → spam
 *   Rule 4: 3+ clickbait patterns (no bulk email required) → spam
 *   Rule 5: Empty subject + attachment → payload delivery scam
 *   Rule 6: Cloud service notification subject from non-service sender → phishing
 *
 * Changelog (see git log for full history):
 *   v6.39.0: Catch political-financial scam miss (economicrulebook.com). Add
 *            iterable.com to BULK_EMAIL_FINGERPRINTS (Iterable marketing
 *            platform). Add two clickbait patterns: political-looting narrative
 *            ("ripped off", "looted", "robbed", "bilked") and payback/revenge
 *            framing ("payback time", "now it's time"). Blacklist
 *            economicrulebook.com. Together these fire Rule 2 (bulk + 2
 *            clickbait) and Rule 1 (bulk + blacklist) on "America Was Ripped
 *            Off for 50 Years – Now It's Payback Time" class emails. Also add
 *            BODY_UNICODE_PATTERNS — Cyrillic/Greek/fullwidth/math-alphanumeric
 *            check against the email body (Signal 2c). Previously these Unicode
 *            obfuscation patterns only fired on subject+from; spammers evade
 *            that by embedding obfuscated text in HTML body anchors.
 *   v6.38.1: Fix logging for Rule 6. getRuleFromSignals() and buildSignalsCsv()
 *            were not updated when Rule 6 was added — phishing emails logged
 *            Rule=NONE, empty signals, and Log Type=SPAM_DETECTED. Now logs
 *            Rule 6, SERVICE_IMPERSONATION in signals, and PHISHING_DETECTED
 *            as the log type so phishing rows are visually distinct.
 *   v6.38.0: Rule 6 — service impersonation phishing detection. Adds
 *            IMPERSONATION_SUBJECT_PATTERNS (cloud service share notification
 *            subjects) and CLOUD_SERVICE_DOMAINS (trusted sender domains).
 *            Emails whose subject matches a known cloud service notification
 *            template (e.g. "Document shared with you") but whose sender is
 *            not from the expected service domain are classified as phishing
 *            without requiring bulk email infrastructure — compromised
 *            legitimate accounts are the typical delivery vector.
 *   v6.37.0: Three operational fixes. (1) Lock-skip log visibility: logDebug →
 *            logInfo so a blocked manual trigger shows "Skipping run — previous
 *            execution still in progress" instead of silence. (2) Mailchimp bulk
 *            detection: add mcsv.net to BULK_EMAIL_FINGERPRINTS so Mailchimp-
 *            routed spam is recognised as bulk email. (3) Military pattern: extend
 *            to attacks?|attacking so "-ing" verb forms fire the clickbait signal.
 *   v6.36.0: Auto-recheck false negatives — recheckRecentSpamChecked() runs at the
 *            end of every processInbox() trigger cycle. Re-evaluates inbox emails
 *            carrying SpamChecked from the last 2 days against current patterns.
 *            Any that now score as spam are logged FALSE_NEGATIVE and deleted
 *            automatically — no manual SpamMissed labeling needed after a fix deploy.
 *   v6.35.0: Catch health/political spam miss (finrisex.com). Blacklist finrisex.com.
 *            Whitelist conservativebc.ca. Add MAHA to celebrity pattern + "report"
 *            as a trailing verb. Expand STOP imperative to include "putting/eating/
 *            drinking". Add suppression conspiracy pattern ("watch before this gets
 *            buried"). Fix domain-list architecture: getBlacklist()/getWhitelist()
 *            now merge DEFAULT_DOMAINS directly at runtime so new source-code
 *            entries are live immediately after deploy — no manual refreshBlacklist()
 *            / refreshWhitelist() call needed ever again.
 *   v6.34.0: Add LockService guard to processInbox() — prevents overlapping
 *            executions when a run takes longer than the trigger interval.
 *            tryLock(0) skips (rather than queues) concurrent invocations.
 *   v6.33.0: Remove fixSheetHyperlinks() — one-time migration utility, already
 *            run. Dead code.
 *   v6.32.0: Spam intelligence logging — every detected spam is archived as a
 *            raw EML in Google Drive (Spam Intelligence/Detected/) and
 *            logged as a structured row in a Google Sheets spreadsheet (19 cols:
 *            timestamp, log type, IDs, Drive URL, sender info, rule fired,
 *            signals, and manual notes columns). False negatives supported via
 *            "SpamMissed" Gmail label — user labels escaped spam, next run logs
 *            and deletes it, populating a FALSE_NEGATIVE row. New functions:
 *            setupLogging() (one-time setup), checkFalseNegatives(),
 *            accumulateLogEntry(), flushSpamLog(), getOrCreateLogSubfolder(),
 *            getRuleFromSignals(), buildSignalsCsv(). Logging is fully
 *            non-blocking — any Drive/Sheets failure is caught and logged
 *            without affecting spam deletion. New OAuth scopes: drive,
 *            spreadsheets. Run setupLogging() once after deploy to authorize.
 *   v6.31.0: Blacklist 1stamericanpath.com (Pre-IPO investment spam mill).
 *            Fix stock price pattern to also match $X/share (slash separator).
 *   v6.30.0: Blacklist morningstockadviser. Add income-opportunity clickbait
 *            pattern (second/passive/extra/side income).
 *   v6.29.0: Security hardening — fix display-name spoofing bypass (whitelist/
 *            blacklist now match against extracted email address only, not full
 *            From string). Add stripHtmlTags() HTML body fallback so
 *            BODY_CRYPTO_PATTERNS fire on HTML-only emails. Add Phase 5 edge
 *            case tests, Phase 6 performance benchmark, ReDoS analysis comment.
 *            Pin clasp@3.3.0 in CI. Delete stale archive/.
 *   v6.28.0: Catch homoglyph-obfuscated health spam (frontiercapitalreport.com).
 *            Add Unicode homoglyph pattern to CLICKBAIT_PATTERNS.
 *   v6.27.0: Comment pass + README/CI fixes for 1st-year CS student clarity.
 *   v6.26.0: Harden test parser — state machine bracket tracking, flag
 *            validation, pattern count cross-checks, parser self-tests.
 *   v6.25.0: Option B — test suite parses SpamDetector.gs directly (single
 *            source of truth). Tests extract all patterns at import time;
 *            no pattern duplication between source and tests.
 *   v6.24.0: L3/L5 review fixes — RFC2822_QUOTED_NAME constant, Rule 0→1 comments,
 *            maxAllowedEmailsPerRun/maxAllowedDaysToCheck into LIMITS, empty-domain
 *            guard on addToWhitelist/addToBlacklist, \uD835 surrogate explanation.
 *   v6.23.0: Extract BULK_EMAIL_FINGERPRINTS constant + isBulkEmail() helper.
 *            Fixes cleanseInbox() missing toLowerCase and test_spam_detector.py missing x-ses-.
 *   v6.22.0: Improve all comments for clarity at introductory CS level.
 *            Fix @version tag, rule numbering in header and docstrings,
 *            plain-English explanations for ReDoS, log injection, RFC 2822.
 *   v6.21.0: CS professor refactor — JSON.parse fallback on corrupt Script
 *            Properties, patterns to module-level constants, split
 *            analyzeMessage() into collectSignals()/makeVerdict(), named
 *            LIMITS constants, boolean return type, rules renumbered 1-5,
 *            debugWhyFlagged() uses production pipeline, removed dead code.
 *   v6.20.0: Detect payload delivery scams — empty subject + attachment (Rule 5).
 *            Scam hides payload inside Excel/PDF; add scam_examples/ test phase.
 *   v6.19.0: Detect crypto airdrop/wallet-drainer scams via body patterns.
 *            Add crypto quantity pattern (\d+ $TICKER) and body-only airdrop/
 *            connect-wallet check; each increments clickbaitCount → Rule 4.
 *   v6.18.0: Systemic RFC 2822 normalization fix. Normalize `from` once at top
 *            of signal collection; remove comma from marketing pattern (false
 *            positives on legit org names like "Bay Meadows, San Mateo").
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
const CONFIG = Object.freeze({
  /** Max emails per run — prevents Apps Script 6-minute execution timeout */
  maxEmailsPerRun: 50,

  /** How many days back to scan for unprocessed emails */
  daysToCheck: 1,

  /** Gmail label applied to processed emails to prevent reprocessing */
  processedLabel: 'SpamChecked',

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
    'economicrulebook.com'
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
  /💼|📸|⏯️|🚨|⚠️|📰|💰|⚡/,  // Sensationalist emoji cluster
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
  /\bairdrop\b/i,                   // Crypto token airdrop
  /\bconnect\s+(your\s+)?wallet\b/i // "Connect your wallet" — wallet drainer
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


// =============================================================================
// Core Processing Pipeline
// =============================================================================

/**
 * Main entry point — scan inbox and process unprocessed emails.
 *
 * Should be configured as a time-driven trigger running every 15 minutes.
 * Processes up to CONFIG.maxEmailsPerRun emails per invocation, with
 * per-thread error isolation so one bad email doesn't abort the entire run.
 *
 * After processing, calls destroySpam() as a safety net to clean any
 * pre-existing spam or messages where immediate deletion failed.
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

  const startTime = Date.now();
  let spamCount = 0;
  let processedCount = 0;
  let errorCount = 0;

  try
  {
    // Validate config before doing any work. If something is misconfigured we
    // want a clear error immediately rather than silent misbehavior later on
    // ("fail fast" — crash early with a useful message instead of limping along).
    validateConfig();

    // Get or create the "SpamChecked" label used to track processed emails
    const label = getOrCreateLabel(CONFIG.processedLabel);

    // Build Gmail search query: inbox emails from the last N days without the label
    const searchQuery = buildSearchQuery();
    logInfo('Search query: ' + searchQuery);

    // Fetch up to maxEmailsPerRun threads matching the query
    const threads = GmailApp.search(searchQuery, 0, CONFIG.maxEmailsPerRun);
    logInfo('Found ' + threads.length + ' threads to process');

    // Process each thread independently — per-thread try/catch ensures one
    // bad email doesn't abort the entire batch
    for (let i = 0; i < threads.length; i++)
    {
      try
      {
        const thread = threads[i];
        const result = processThread(thread);

        spamCount += result.spamCount;
        processedCount += result.processedCount;

        // Label thread as processed so it won't be re-scanned next run.
        // Skip if the thread was spam — it's been permanently deleted and
        // addLabel() on a deleted thread throws "Not found".
        if (result.spamCount === 0)
        {
          thread.addLabel(label);
        }
      }
      catch (threadError)
      {
        errorCount++;
        logError('Error processing thread: ' + threadError.toString());
        // Continue to next thread — don't let one failure stop the batch
      }
    }

    const duration = Date.now() - startTime;
    logInfo('Completed in ' + duration + 'ms: Processed ' + processedCount +
            ' emails, marked ' + spamCount + ' as spam, ' + errorCount + ' errors');

    // 1. Log emails the user manually labeled SpamMissed.
    // 2. Re-evaluate SpamChecked inbox emails from the last 2 days — catches
    //    false negatives automatically after a pattern-fix deploy, with no
    //    manual labeling required.
    // 3. Flush all accumulated log entries to Drive + Sheets.
    checkFalseNegatives();
    recheckRecentSpamChecked();
    flushSpamLog();

    // Safety-net pass: clean pre-existing spam + any messages where
    // the immediate delete in markAsSpam() failed
    destroySpam();
  }
  catch (error)
  {
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
  const SUSPECT_LABEL = 'SuspectedSpam';

  let deletedCount  = 0;
  let suspectCount  = 0;
  let cleanCount    = 0;
  let errorCount    = 0;

  try
  {
    const checkedLabel = getOrCreateLabel(CONFIG.processedLabel);
    const suspectLabel = getOrCreateLabel(SUSPECT_LABEL);
    const blacklist    = getBlacklist();  // DEFAULT_DOMAINS + user-added, merged automatically
    const whitelist    = getWhitelist();

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

          for (let m = 0; m < messages.length; m++)
          {
            const message  = messages[m];
            const fromLower = sanitizeInput(message.getFrom()).toLowerCase();

            // Whitelist: skip entirely
            let whitelisted = false;
            for (let w = 0; w < whitelist.length; w++)
            {
              if (fromLower.includes(whitelist[w])) { whitelisted = true; break; }
            }
            if (whitelisted) continue;

            // Rule 1 pre-check: bulk + blacklisted = definitive, delete immediately
            const rawContent = message.getRawContent();
            const isBulk     = isBulkEmail(rawContent);
            let isBlacklisted = false;
            for (let b = 0; b < blacklist.length; b++)
            {
              if (fromLower.includes(blacklist[b])) { isBlacklisted = true; break; }
            }

            if (isBulk && isBlacklisted)
            {
              markAsSpam(message, thread);
              deletedCount++;
              threadDeleted = true;
              break; // Thread is gone — stop processing its messages
            }

            // Rules 2-5: pattern-based — quarantine for human review
            if (analyzeMessage(message).isSpam)
            {
              threadSuspect = true;
            }
          }

          if (threadDeleted) continue;

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
            suspectCount + ' quarantined (review SuspectedSpam label), ' +
            cleanCount + ' clean, ' + errorCount + ' errors');

    destroySpam();
  }
  catch (error)
  {
    logError('Critical error in cleanseInbox: ' + error.toString());
    throw error;
  }
}


/**
 * Safety-net cleanup of the entire spam folder.
 *
 * Primary deletion happens in markAsSpam() by known message ID. This function
 * handles two edge cases:
 *   1. Pre-existing spam that was in the folder before this script ran
 *   2. Messages where the immediate delete in markAsSpam() failed
 *
 * Uses batch deletion in pages of 100 with rate limiting between batches.
 * Caps at MAX_ITERATIONS (10 batches = ~1000 messages) to prevent runaway
 * loops if something goes wrong with the API.
 */
function destroySpam()
{
  // Guard: Gmail Advanced Service must be enabled in the project
  if (typeof Gmail === 'undefined' || !Gmail.Users || !Gmail.Users.Messages)
  {
    logInfo('Gmail API not available for spam destruction');
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
      response = Gmail.Users.Messages.list('me', {
        labelIds: ['SPAM'],
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

    // Extract message IDs for batch deletion
    const ids = response.messages.map(function(m) { return m.id; });

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
    logInfo('Destroy hit max iterations (' + MAX_ITERATIONS + ') - spam folder may still have messages');
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
 * @param {GmailThread} thread - The Gmail thread to process.
 * @return {Object} Object with {spamCount, processedCount} statistics.
 */
function processThread(thread)
{
  let spamCount = 0;
  let processedCount = 0;
  let threadMarkedAsSpam = false;

  const messages = thread.getMessages();

  // Process all messages in the thread
  for (let i = 0; i < messages.length; i++)
  {
    try
    {
      const message = messages[i];

      // Skip oversized emails (> 5MB) to prevent memory issues
      if (!shouldProcessMessage(message))
      {
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
        const detectionLogType = verdict.signals && verdict.signals.serviceImpersonation
          ? 'PHISHING_DETECTED' : 'SPAM_DETECTED';
        accumulateLogEntry(message, verdict.signals, detectionLogType);
        markAsSpam(message, thread);
        spamCount++;
        threadMarkedAsSpam = true;
        logDebug('SPAM DETECTED: ' + sanitizeForLog(message.getSubject()));
      }
    }
    catch (messageError)
    {
      logError('Error processing message: ' + messageError.toString());
      // Continue to next message — don't let one failure stop the thread
    }
  }

  return { spamCount: spamCount, processedCount: processedCount };
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
  return '{in:inbox category:updates category:promotions category:social category:forums}' +
         ' -label:' + CONFIG.processedLabel + ' after:' + dateStr;
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
  const lower = rawContent.toLowerCase();
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
  // ── Extract email fields ────────────────────────────────────────────────
  const subject = sanitizeInput(message.getSubject());
  // Fall back to HTML-stripped body if plain body is empty (HTML-only emails).
  // Without this fallback, BODY_CRYPTO_PATTERNS would silently never fire on
  // messages that have no text/plain part.
  const plainBody = message.getPlainBody();
  const body = sanitizeInput(plainBody || stripHtmlTags(message.getBody()));
  // Normalize RFC 2822 quoted display names: "Name" <email> → Name <email>
  // See RFC2822_QUOTED_NAME constant for regex anatomy.
  const from = sanitizeInput(message.getFrom()).replace(RFC2822_QUOTED_NAME, '$1$2');
  const rawContent = message.getRawContent(); // Full RFC 822 content (includes all headers)

  // ── Whitelist check (early exit) ────────────────────────────────────────
  // Known legitimate senders skip all detection — prevents false positives
  // on services like LinkedIn, Substack, etc. that use bulk infrastructure.
  // IMPORTANT: match against the email address only, not the full From string.
  // Matching the full string would allow display-name spoofing:
  //   "LinkedIn News <spammer@spam.com>" would incorrectly bypass detection
  //   if "linkedin" appeared in the display name.
  const whitelist = getWhitelist();
  const fromLower = from.toLowerCase();
  const senderAddress = extractEmailAddress(from);
  for (let i = 0; i < whitelist.length; i++)
  {
    if (senderAddress.includes(whitelist[i]))
    {
      logDebug('Whitelisted domain detected: ' + whitelist[i]);
      return null; // null = whitelisted, skip all detection
    }
  }

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
    serviceImpersonation: false        // Cloud service subject from non-service sender (phishing)
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
  const blacklist = getBlacklist();
  for (let i = 0; i < blacklist.length; i++)
  {
    if (senderAddress.includes(blacklist[i]))
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

  // ── Signal 2c: Unicode obfuscation in body ──────────────────────────────
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

  return signals;
}

/**
 * Apply the 6-rule decision cascade to a collected signals object.
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

  // No rule triggered — email is not spam
  logDebug('Not spam - signals: bulk=' + signals.bulkEmailService +
           ', blacklist=' + signals.blacklistedSender +
           ', clickbait=' + signals.clickbaitCount +
           ', fear=' + signals.fearMongering +
           ', marketing=' + signals.marketingFormat +
           ', suspiciousFrom=' + signals.suspiciousFromName +
           ', emptySubjectAttachment=' + signals.emptySubjectWithAttachment +
           ', serviceImpersonation=' + signals.serviceImpersonation);
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
 * @return {boolean} true if spam, false if not.
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
function markAsSpam(message, thread)
{
  const subject = sanitizeForLog(message.getSubject());

  try
  {
    const messageId = message.getId();

    // Prefer Gmail Advanced Service (REST API) for precise control
    if (typeof Gmail !== 'undefined' && Gmail.Users && Gmail.Users.Messages)
    {
      // Step 1: Report as spam — trains Gmail's spam filters for future emails
      Gmail.Users.Messages.modify(
        { addLabelIds: ['SPAM'], removeLabelIds: ['INBOX'] },
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
  const match = from.match(/<([^>]+)>/);
  return (match ? match[1] : from).toLowerCase();
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
}


// =============================================================================
// Setup and Initialization
// =============================================================================

/**
 * One-time setup function — run manually to authorize the script and
 * initialize Script Properties with default domain lists.
 *
 * After running, set up a time-driven trigger:
 *   Triggers > Add Trigger > processInbox > Time-driven > Every 15 minutes
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
    logInfo('  2. Set up a time-based trigger: Triggers > Add Trigger > processInbox > Time-driven > Every 15 minutes');
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
 * Refresh whitelist by adding any missing default domains.
 *
 * Run this after updating DEFAULT_DOMAINS.legitimate in the source code.
 * It merges new defaults into the existing list without removing any
 * manually-added domains.
 */
function refreshWhitelist()
{
  const props = PropertiesService.getScriptProperties();
  const currentWhitelist = getWhitelist();
  const defaults = DEFAULT_DOMAINS.legitimate;
  let addedCount = 0;

  // Add any defaults that aren't already in the list
  for (let i = 0; i < defaults.length; i++)
  {
    if (!currentWhitelist.includes(defaults[i]))
    {
      currentWhitelist.push(defaults[i]);
      logInfo('Added missing domain: ' + defaults[i]);
      addedCount++;
    }
  }

  if (addedCount > 0)
  {
    props.setProperty('LEGITIMATE_DOMAINS', JSON.stringify(currentWhitelist));
    logInfo('Whitelist refreshed! Added ' + addedCount + ' new domains.');
  }
  else
  {
    logInfo('Whitelist already up to date.');
  }

  viewWhitelist();
}

/**
 * Refresh blacklist by adding any missing default domains.
 *
 * Run this after updating DEFAULT_DOMAINS.suspicious in the source code.
 * It merges new defaults into the existing list without removing any
 * manually-added domains.
 */
function refreshBlacklist()
{
  const props = PropertiesService.getScriptProperties();
  const currentBlacklist = getBlacklist();
  const defaults = DEFAULT_DOMAINS.suspicious;
  let addedCount = 0;

  // Add any defaults that aren't already in the list
  for (let i = 0; i < defaults.length; i++)
  {
    if (!currentBlacklist.includes(defaults[i]))
    {
      currentBlacklist.push(defaults[i]);
      logInfo('Added missing domain: ' + defaults[i]);
      addedCount++;
    }
  }

  if (addedCount > 0)
  {
    props.setProperty('SUSPICIOUS_DOMAINS', JSON.stringify(currentBlacklist));
    logInfo('Blacklist refreshed! Added ' + addedCount + ' new domains.');
  }
  else
  {
    logInfo('Blacklist already up to date.');
  }

  viewBlacklist();
}


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
    const threads = GmailApp.search('label:' + SPAM_MISSED_LABEL);
    if (threads.length === 0) return;

    logInfo('Found ' + threads.length + ' false negative(s) to log');

    const label = GmailApp.getUserLabelByName(SPAM_MISSED_LABEL);

    for (let i = 0; i < threads.length; i++)
    {
      try
      {
        const thread  = threads[i];
        const message = thread.getMessages()[0];

        let signals = null;
        try { signals = collectSignals(message); }
        catch (e) { /* non-fatal — log entry still captured without signals */ }

        // Accumulate BEFORE deletion — getRawContent() is unavailable after batchDelete
        accumulateLogEntry(message, signals, 'FALSE_NEGATIVE');

        // Remove label before markAsSpam() — deleted threads can't have labels removed
        if (label) thread.removeLabel(label);

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
 * This function closes that gap automatically. On every trigger run it re-checks
 * inbox emails carrying SpamChecked from the last RECHECK_DAYS days. If any now
 * score as spam under the updated patterns, they are logged as FALSE_NEGATIVE and
 * permanently deleted — identical treatment to a manually labeled SpamMissed email.
 *
 * Performance: capped at RECHECK_LIMIT emails per run. analyzeMessage() averages
 * ~2ms per email in GAS, so 20 emails adds ~40ms — negligible vs. the 6-min budget.
 * getRawContent() is called once per email (needed for bulk-email detection).
 */
function recheckRecentSpamChecked()
{
  const RECHECK_DAYS  = 2;
  const RECHECK_LIMIT = 20;

  try
  {
    const query   = 'in:inbox label:' + CONFIG.processedLabel + ' newer_than:' + RECHECK_DAYS + 'd';
    const threads = GmailApp.search(query, 0, RECHECK_LIMIT);
    if (threads.length === 0) return;

    logDebug('Rechecking ' + threads.length + ' recent SpamChecked inbox email(s)');

    let recaughtCount = 0;

    for (let i = 0; i < threads.length; i++)
    {
      try
      {
        const thread  = threads[i];
        const message = thread.getMessages()[0];

        const verdict = analyzeMessage(message);
        if (!verdict.isSpam) continue;

        logInfo('Auto-recaught false negative: ' + sanitizeForLog(message.getSubject()));

        // Accumulate log entry BEFORE deletion — getRawContent() unavailable after batchDelete
        accumulateLogEntry(message, verdict.signals, 'FALSE_NEGATIVE');
        markAsSpam(message, thread);
        recaughtCount++;
      }
      catch (threadError)
      {
        logError('recheckRecentSpamChecked thread error: ' + threadError.toString());
      }
    }

    if (recaughtCount > 0)
    {
      logInfo('Recheck: auto-caught ' + recaughtCount + ' false negative(s) from last ' + RECHECK_DAYS + ' days');
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
function accumulateLogEntry(message, signals, logType)
{
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
    try { rawContent = message.getRawContent(); }
    catch (e) { logError('getRawContent failed for ' + message.getId() + ': ' + e.toString()); }

    _pendingLogEntries.push({
      detectedAt:             new Date().toISOString(),
      logType:                logType,
      messageId:              message.getId(),
      threadId:               message.getThread().getId(),
      rawContent:             rawContent,
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
  }
  catch (error)
  {
    logError('accumulateLogEntry failed: ' + error.toString());
  }
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

      // Write EML to Drive — colons are invalid in filenames, replace with dashes
      let driveUrl = '';
      try
      {
        const safeTs   = entry.detectedAt.replace(/:/g, '-').replace(/\.\d+Z$/, 'Z');
        const filename = safeTs + '_' + entry.messageId.substring(0, 8) + '.eml';
        const blob     = Utilities.newBlob(entry.rawContent, 'message/rfc822', filename);
        if (entry.logType === 'FALSE_NEGATIVE')
        {
          if (!fnFolder) fnFolder = getOrCreateLogSubfolder(rootFolder, ['False Negatives']);
        }
        const folder   = entry.logType === 'FALSE_NEGATIVE' ? fnFolder : detectedFolder;
        const fileUrl  = folder.createFile(blob).getUrl();
        driveUrl       = '=HYPERLINK("' + fileUrl + '","' + filename + '")';
      }
      catch (driveError)
      {
        logError('Drive write failed for ' + entry.messageId + ': ' + driveError.toString());
      }

      rows.push([
        entry.detectedAt,
        entry.logType,
        entry.messageId,
        entry.threadId,
        driveUrl,
        entry.subject,
        entry.fromDisplayName,
        entry.fromAddress,
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
    return { rule: 'NONE', description: 'False negative — no rule triggered' };
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
