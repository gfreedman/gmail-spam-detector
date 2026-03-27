/**
 * Gmail Spam Detector - Google Apps Script
 * @version 6.20.0
 *
 * Automated spam detection and destruction for Gmail. Runs on a 15-minute
 * trigger, scanning the inbox for unprocessed emails and applying a
 * multi-signal pattern detection engine.
 *
 * Detection strategy — target behavioral patterns spammers can't easily change:
 *   - Bulk email infrastructure (Amazon SES, SendGrid)
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
 * Decision logic (4 rules, evaluated in priority order):
 *   Rule 0: Bulk + blacklisted sender domain → spam
 *   Rule 1: Bulk + 2+ clickbait patterns → spam
 *   Rule 2: Bulk + 2+ distinct spam behaviors → spam
 *   Rule 3: 3+ clickbait patterns (no bulk required) → spam
 *   Rule 4: Empty subject + attachment → payload delivery scam
 *
 * Changelog (see git log for full history):
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
    'sundaymass.store', 'customerservice@stan', 'privaterelay.appleid.com',
    'email.meetup.com', 'ben-evans.com', 'linkedin.com', 'e.linkedin.com',
    'linkedin.email', 'dsf.ca', 'dragonfly', 'ezyvet.com'
  ]),
  /** Known spam mill domains — triggers Rule 0 when combined with bulk email */
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
    'beststockvillage'
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

  /** Input truncation cap — prevents regex backtracking DoS on malicious oversized inputs */
  maxInputChars: 100000,

  /** Log message truncation — prevents log injection via crafted subjects */
  maxLogChars: 100
});


// =============================================================================
// Detection Patterns
//
// Defined at module level so RegExp objects are compiled once, not on every
// call to analyzeMessage(). Each array is frozen to prevent accidental mutation.
// =============================================================================

/**
 * Clickbait / sensationalism patterns — checked against subject + from concatenated.
 * Each matching pattern increments clickbaitCount independently.
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

  // Celebrity credibility theft: "RFK Jr Issues Warning", "Musk Exposes"
  /\b(RFK|Trump|Biden|Musk|Elon|Kennedy|Obama|Fauci|Gates)\b.*(warning|says|reveals|exposes|issues|predicts|warns|showed|shows)/i,

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

  // Impending doom framing: "What's Coming", "Not Prepared for what's ahead"
  /\bwhat.s (coming|ahead)\b|\bnot prepared\b/i,

  // --- Violence and military sensationalism ---

  // Military/war clickbait: "declared war", "bombing", "invasion"
  /\b(declared war|bombed|bombing|attack|attacked|destroyed|invasion)\b/i,

  // --- Financial hype ---

  // Pre-IPO investment solicitation: always spam in bulk email
  /\bpre-?ipo\b/i,

  // Stock price hype: "$5 a share", "$0.85 per share", "penny stock"
  /\$\d+(\.\d+)?\s*(?:(?:a|per)\s+)?share|\bpenny stock\b/i,

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
  /\uD835/,           // Mathematical bold/italic: "𝗔𝗺𝗮𝘇𝗼𝗻" (surrogate pair)

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
  /\b\d+(?:\.\d+)?\s+\$[A-Z]{4,}\b/
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

  // "STOP using/taking" imperative pattern
  /\bSTOP (using|taking|doing|buying)\b/i
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
  const startTime = Date.now();
  let spamCount = 0;
  let processedCount = 0;
  let errorCount = 0;

  try
  {
    // Fail fast if config is invalid (before doing any work)
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

    // Safety-net pass: clean pre-existing spam + any messages where
    // the immediate delete in markAsSpam() failed
    destroySpam();
  }
  catch (error)
  {
    logError('Critical error in processInbox: ' + error.toString());
    throw error; // Re-throw so trigger failure is visible in Apps Script dashboard
  }
}

/**
 * Full historical inbox cleanse — two-speed mode:
 *
 *   DELETED:   Bulk + blacklisted sender (Rule 0 only) — zero false-positive risk.
 *   QUARANTINE: Everything else that scores as spam (Rules 1/2/3) — gets a
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
    // Sync Script Properties with source-code defaults before scanning
    refreshBlacklist();
    refreshWhitelist();

    const checkedLabel = getOrCreateLabel(CONFIG.processedLabel);
    const suspectLabel = getOrCreateLabel(SUSPECT_LABEL);
    const blacklist    = getBlacklist();
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

            // Rule 0 pre-check: bulk + blacklisted = definitive, delete immediately
            const rawContent = message.getRawContent().toLowerCase();
            const isBulk     = rawContent.includes('amazonses.com') ||
                               rawContent.includes('x-ses-') ||
                               rawContent.includes('sendgrid.net');
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
            if (analyzeMessage(message))
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

    logInfo('CLEANSE COMPLETE: ' + deletedCount + ' deleted (Rule 0), ' +
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
  const MAX_ITERATIONS = 10; // Safety cap: max 10 batches (~1000 messages)

  // Keep pulling pages of spam until the folder is empty or we hit the cap
  while (iterations < MAX_ITERATIONS)
  {
    iterations++;

    // Fetch a page of up to 100 spam messages
    let response;
    try
    {
      response = Gmail.Users.Messages.list('me', {
        labelIds: ['SPAM'],
        maxResults: 100
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

    // Brief pause between batches to respect Gmail API rate limits
    Utilities.sleep(500);
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
      const isSpam = analyzeMessage(message);

      logDebug('Email: "' + sanitizeForLog(message.getSubject()) + '" - Spam: ' + isSpam);

      // Only mark thread as spam once, even if multiple messages trigger detection.
      // This prevents duplicate API calls and redundant log entries.
      if (isSpam && !threadMarkedAsSpam)
      {
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
// Spam Detection Engine
// =============================================================================

/**
 * Collect all spam signals from a message.
 *
 * Extracts and normalizes email fields, checks the whitelist, then populates
 * a signals object from 6 independent detection categories. Each signal is
 * evaluated without reference to the others — verdict logic lives in
 * makeVerdict().
 *
 * @param {GmailMessage} message - The Gmail message to analyze.
 * @return {Object|null} Signals object, or null if sender is whitelisted.
 */
function collectSignals(message)
{
  // ── Extract email fields ────────────────────────────────────────────────
  const subject = sanitizeInput(message.getSubject());
  const body = sanitizeInput(message.getPlainBody());
  // Normalize RFC 2822 quoted display names: "Name" <email> → Name <email>
  // getFrom() returns raw headers; outer quotes must be stripped so downstream
  // pattern matching never sees the surrounding " characters.
  const from = sanitizeInput(message.getFrom())
                 .replace(/^"((?:[^"\\]|\\.)*)"(\s*<[^>]*>)$/, '$1$2');
  const rawContent = message.getRawContent(); // Full RFC 822 content (includes all headers)

  // ── Whitelist check (early exit) ────────────────────────────────────────
  // Known legitimate senders skip all detection — prevents false positives
  // on services like LinkedIn, Substack, etc. that use bulk infrastructure
  const whitelist = getWhitelist();
  const fromLower = from.toLowerCase();
  for (let i = 0; i < whitelist.length; i++)
  {
    if (fromLower.includes(whitelist[i]))
    {
      logDebug('Whitelisted domain detected: ' + whitelist[i]);
      return null; // null = whitelisted, skip all detection
    }
  }

  // ── Initialize signal accumulators ───────────────────────────────────────
  // Each detection phase below populates one signal. makeVerdict() combines
  // them to produce the spam/not-spam decision.
  const signals = {
    bulkEmailService: false,          // Sent via Amazon SES or SendGrid
    blacklistedSender: false,         // From a known spam mill domain
    clickbaitCount: 0,                // Number of clickbait patterns matched
    fearMongering: false,             // Contains fear-mongering language
    marketingFormat: false,           // From field uses marketing formatting
    suspiciousFromName: false,        // Display name is headline-like
    emptySubjectWithAttachment: false // Empty subject + has attachment (payload scam)
  };

  // ── Signal 1a: Bulk email service detection ─────────────────────────────
  // Check raw email headers for Amazon SES or SendGrid fingerprints.
  // These services are used by both legitimate senders and spam mills,
  // so this signal alone is not conclusive — it's a multiplier for
  // other signals in Rules 1-3.
  const rawLower = rawContent.toLowerCase();
  if (rawLower.includes('amazonses.com') ||
      rawLower.includes('x-ses-') ||
      rawLower.includes('sendgrid.net'))
  {
    signals.bulkEmailService = true;
    logDebug('Bulk email service detected');
  }

  // ── Signal 1b: Blacklisted sender domain ────────────────────────────────
  // Substring match against known spam mill domains from Script Properties.
  // One match is enough — these domains have no legitimate use.
  const blacklist = getBlacklist();
  for (let i = 0; i < blacklist.length; i++)
  {
    if (fromLower.includes(blacklist[i]))
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

  return signals;
}

/**
 * Apply the 5-rule decision cascade to a collected signals object.
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
    logInfo('SPAM detected: Bulk email + blacklisted sender');
    return true;
  }

  // Rule 2: Bulk email + 2+ clickbait patterns = spam
  // Rationale: Legitimate bulk senders rarely use multiple clickbait tactics
  if (signals.bulkEmailService && signals.clickbaitCount >= 2)
  {
    logInfo('SPAM detected: Bulk email + clickbait (' + signals.clickbaitCount + ' patterns)');
    return true;
  }

  // Rule 3: Bulk email + 2+ distinct spam behaviors = spam
  // Rationale: No single behavior is conclusive, but two independent spam
  // behaviors from a bulk sender is a strong convergent signal
  let spamBehaviorCount = 0;
  if (signals.clickbaitCount >= 1) spamBehaviorCount++;
  if (signals.fearMongering) spamBehaviorCount++;
  if (signals.marketingFormat) spamBehaviorCount++;
  if (signals.suspiciousFromName) spamBehaviorCount++;

  if (signals.bulkEmailService && spamBehaviorCount >= 2)
  {
    logInfo('SPAM detected: Bulk email + ' + spamBehaviorCount + ' spam behaviors');
    return true;
  }

  // Rule 4: Extreme clickbait alone (no bulk email required)
  // Rationale: 3+ clickbait hits is so anomalous that even non-bulk senders
  // are almost certainly spam (catches direct-send spam)
  if (signals.clickbaitCount >= 3)
  {
    logInfo('SPAM detected: Extreme clickbait (' + signals.clickbaitCount + ' patterns)');
    return true;
  }

  // Rule 5: Empty subject + attachment = payload delivery scam
  // Rationale: Legitimate email virtually never has both an empty subject
  // and an attachment. This pattern is the fingerprint of file-based scams
  // that hide phishing links or malware inside Excel/PDF attachments to
  // bypass text-pattern detection entirely.
  if (signals.emptySubjectWithAttachment)
  {
    logInfo('SPAM detected: Empty subject with attachment (payload delivery scam)');
    return true;
  }

  // No rule triggered — email is not spam
  logDebug('Not spam - signals: bulk=' + signals.bulkEmailService +
           ', blacklist=' + signals.blacklistedSender +
           ', clickbait=' + signals.clickbaitCount +
           ', fear=' + signals.fearMongering +
           ', marketing=' + signals.marketingFormat +
           ', suspiciousFrom=' + signals.suspiciousFromName +
           ', emptySubjectAttachment=' + signals.emptySubjectWithAttachment);
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
    if (signals === null) return false; // whitelisted
    return makeVerdict(signals);
  }
  catch (error)
  {
    logError('Error analyzing message: ' + error.toString());
    return false; // Default to not-spam on error — better to miss spam than delete legit mail
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
      logInfo('SPAM REPORTED: ' + subject);

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
      logInfo('SPAM REPORTED (fallback): ' + subject);
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
      logInfo('SPAM REPORTED (fallback): ' + subject);
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
  const MAX_EMAILS_PER_RUN = 500;
  const MAX_DAYS_TO_CHECK  = 30;

  if (CONFIG.maxEmailsPerRun < 1 || CONFIG.maxEmailsPerRun > MAX_EMAILS_PER_RUN)
  {
    throw new Error('Invalid maxEmailsPerRun: must be between 1 and ' + MAX_EMAILS_PER_RUN);
  }

  if (CONFIG.daysToCheck < 0 || CONFIG.daysToCheck > MAX_DAYS_TO_CHECK)
  {
    throw new Error('Invalid daysToCheck: must be between 0 and ' + MAX_DAYS_TO_CHECK);
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
 * Truncates to 100KB max. Applied to subject, body, and from fields before
 * pattern matching. This prevents regex backtracking DoS on maliciously
 * crafted emails with extremely long headers.
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
 * Sanitize text for safe inclusion in log messages.
 *
 * Truncates to 100 chars and strips newlines to prevent log injection
 * (where a crafted subject could insert fake log entries).
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

    logInfo('Setup complete! Now set up a time-based trigger to run processInbox() every 15 minutes.');
    logInfo('Go to: Triggers (clock icon) > Add Trigger > Function: processInbox > Time-driven > Minutes timer > Every 15 minutes');
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
 * Get the current whitelist from Script Properties.
 *
 * @return {Array<string>} Array of whitelisted domain substrings.
 */
function getWhitelist()
{
  const props = PropertiesService.getScriptProperties();
  const raw = props.getProperty('LEGITIMATE_DOMAINS');
  if (!raw) return Array.from(DEFAULT_DOMAINS.legitimate);
  try
  {
    return JSON.parse(raw);
  }
  catch (e)
  {
    logError('Whitelist JSON corrupt — falling back to defaults: ' + e.toString());
    return Array.from(DEFAULT_DOMAINS.legitimate);
  }
}

/**
 * Get the current blacklist from Script Properties.
 *
 * @return {Array<string>} Array of blacklisted domain substrings.
 */
function getBlacklist()
{
  const props = PropertiesService.getScriptProperties();
  const raw = props.getProperty('SUSPICIOUS_DOMAINS');
  if (!raw) return Array.from(DEFAULT_DOMAINS.suspicious);
  try
  {
    return JSON.parse(raw);
  }
  catch (e)
  {
    logError('Blacklist JSON corrupt — falling back to defaults: ' + e.toString());
    return Array.from(DEFAULT_DOMAINS.suspicious);
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
 * Add a domain to the blacklist (triggers Rule 0 when combined with bulk email).
 *
 * Duplicate-safe: silently skips if the domain is already in the list.
 *
 * @param {string} domain - Domain substring to blacklist (e.g., 'spammer.com').
 */
function addToBlacklist(domain)
{
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
