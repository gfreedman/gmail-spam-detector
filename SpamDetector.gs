/**
 * Gmail Spam Detector - Google Apps Script
 * @version 6.17.0
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
 *
 * Changelog:
 *   v6.16.1: Fix "per share" stock price miss. Extend stock price pattern to
 *            match "$0.85 per share" (was only matching "a share"). Gives
 *            clickbait=1 + marketing → Rule 2 independent of blacklist.
 *            Add 2 spam examples (39/39).
 *   v6.16.0: Fix "Trump approved precious metals" spam miss. Two new clickbait
 *            patterns: political legitimization ("Trump approved/signed/backed")
 *            and bracket-date format ("[March 09]"). Both fire on subject+from,
 *            giving clickbait=2 + bulk → Rule 1. Blacklist onlineinvestingdaily.
 *            Added spam example (37/37).
 *   v6.15.2: Fix silver/dollar financial spam miss. Add "dying" to financial
 *            fear clickbait pattern ("dollar dying"). Add pipe-date clickbait
 *            pattern ("| February 23") — pipe variant of existing bullet-date.
 *            Both give clickbait=2 + bulk → Rule 1, no blacklist dependency.
 *   v6.15.1: Fix "Not found" error after spam deletion. Skip thread.addLabel()
 *            on deleted threads. Added 2 spam examples (36/36).
 *            when a thread was deleted — calling addLabel() on a permanently
 *            deleted thread throws. Label is irrelevant on a deleted thread.
 *   v6.15.0: Blacklist smartpeoplemail (Pre-IPO investment spam). Add Pre-IPO
 *            clickbait pattern for defense-in-depth against similar senders.
 *            Added spam example (35/35).
 *   v6.14.0: Add refreshBlacklist() — merges new DEFAULT_DOMAINS.suspicious
 *            entries into runtime Script Properties. Fixes bug where blacklist
 *            additions in source code weren't reflected at runtime (Script
 *            Properties only initialize once, on first setup). Added spam
 *            example (34/34).
 *   v6.12.0: Detect polished financial spam — ellipsis clickbait pattern,
 *            subject-echo From name detection (flags when spammers stuff
 *            subject words into display name), blacklist investingtrendstoday.
 *   v6.11.1: Fix spam deletion — use batchDelete() instead of delete().
 *            The Advanced Gmail Service does not expose a single-message
 *            delete method. batchDelete({ids: [...]}, 'me') is the correct
 *            API for permanent deletion.
 *   v6.11.0: Fix spam deletion once and for all. Root cause: every version
 *            since v6.6.0 relied on QUERYING the spam folder after flagging,
 *            then deleting query results. Gmail has propagation delay between
 *            modify() and list() even on the same REST API. Fix: delete by
 *            known message ID immediately in markAsSpam(). destroySpam()
 *            retained as safety net for pre-existing spam.
 *   v6.9.0:  Catch "polished" financial spam — blacklist expertmodernadvice,
 *            detect Unicode punctuation obfuscation, financial solicitation.
 *   v6.8.0:  Blacklist hardening — bulk + blacklisted = spam. From-field
 *            anomaly detection for bullet separators / excessive length.
 *   v6.7.0:  Added mathematical Unicode, bullet-point dates, historical
 *            atrocity clickbait, health anxiety, financial scam products,
 *            "now you can see" curiosity gaps, bombshell, ⚡ emoji.
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

  /**
   * Minimum score to classify as spam.
   * The detection engine returns 0 (not spam) or 100 (spam) — binary decision.
   * Threshold of 50 means anything flagged as spam (score=100) triggers action.
   */
  spamThreshold: 50,

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
    'linkedin.email', 'dsf.ca', 'dragonfly'
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
    'onlineinvestingdaily'
  ])
});


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
      const spamScore = analyzeMessage(message);

      logDebug('Email: "' + sanitizeForLog(message.getSubject()) + '" - Score: ' + spamScore);

      // Only mark thread as spam once, even if multiple messages trigger detection.
      // This prevents duplicate API calls and redundant log entries.
      if (spamScore >= CONFIG.spamThreshold && !threadMarkedAsSpam)
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
 * Analyze a message using multi-signal pattern detection.
 *
 * This is the core detection engine. It collects signals across 6 categories,
 * then applies a 4-rule decision cascade. Returns a binary result (0 or 100)
 * rather than a granular score — an email is either spam or it isn't.
 *
 * Detection pipeline:
 *   1. Whitelist check — known legitimate senders bypass all detection
 *   2. Signal collection:
 *      a. Bulk email service (Amazon SES / SendGrid in raw headers)
 *      b. Blacklisted sender domain (known spam mills)
 *      c. Suspicious From display name (bullets, excessive length)
 *      d. Clickbait pattern count (40+ patterns across categories)
 *      e. Fear-mongering language (government/financial/health fear)
 *      f. Marketing sender format (pipe separators, spammy business names)
 *   3. Decision logic (4 rules in priority order):
 *      Rule 0: Bulk + blacklisted sender → spam (definitive)
 *      Rule 1: Bulk + 2+ clickbait patterns → spam
 *      Rule 2: Bulk + 2+ distinct spam behaviors → spam
 *      Rule 3: 3+ clickbait patterns alone → spam (catches direct-send)
 *
 * @param {GmailMessage} message - The Gmail message to analyze.
 * @return {number} 0 (not spam) or 100 (spam).
 */
function analyzeMessage(message)
{
  try
  {
    // ── Extract email fields ──────────────────────────────────────────────
    const subject = sanitizeInput(message.getSubject());
    const body = sanitizeInput(message.getPlainBody());
    const from = sanitizeInput(message.getFrom());
    const rawContent = message.getRawContent(); // Full RFC 822 content (includes all headers)

    // ── Whitelist check (early exit) ──────────────────────────────────────
    // Known legitimate senders skip all detection — prevents false positives
    // on services like LinkedIn, Substack, etc. that use bulk infrastructure
    const whitelist = getWhitelist();
    const fromLower = from.toLowerCase();
    for (let i = 0; i < whitelist.length; i++)
    {
      if (fromLower.includes(whitelist[i]))
      {
        logDebug('Whitelisted domain detected: ' + whitelist[i]);
        return 0;
      }
    }

    // ── Initialize signal accumulators ─────────────────────────────────────
    // Each detection phase below populates one signal. The decision logic
    // at the end combines these signals to make the spam/not-spam call.
    const signals = {
      bulkEmailService: false,    // Sent via Amazon SES or SendGrid
      blacklistedSender: false,   // From a known spam mill domain
      clickbaitCount: 0,          // Number of clickbait patterns matched
      fearMongering: false,       // Contains fear-mongering language
      marketingFormat: false,     // From field uses marketing formatting
      suspiciousFromName: false   // Display name is headline-like
    };

    // ── Signal 1a: Bulk email service detection ───────────────────────────
    // Check raw email headers for Amazon SES or SendGrid fingerprints.
    // These services are used by both legitimate senders and spam mills,
    // so this signal alone is not conclusive — it's a multiplier for
    // other signals in Rules 0-2.
    if (rawContent.toLowerCase().includes('amazonses.com') ||
        rawContent.toLowerCase().includes('x-ses-') ||
        rawContent.toLowerCase().includes('sendgrid.net'))
    {
      signals.bulkEmailService = true;
      logDebug('Bulk email service detected');
    }

    // ── Signal 1b: Blacklisted sender domain ──────────────────────────────
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

    // ── Signal 1c: Suspicious From display name ───────────────────────────
    // Strip the <email@address> portion, then check the remaining display name.
    // Legitimate senders use plain names ("John Smith"); spam mills stuff
    // headlines into display names ("Breaking • Banks Closing • Alert").
    const fromDisplayName = from.replace(/<[^>]*>$/, '').trim();
    if (fromDisplayName.includes('•') ||  // Bullet separator — never used by legitimate senders
        fromDisplayName.length > 50)      // Excessive length — keyword stuffing tactic
    {
      signals.suspiciousFromName = true;
      logDebug('Suspicious From name detected: ' + sanitizeForLog(fromDisplayName));
    }

    // Subject echo: spammers stuff subject content into the From display name
    // for maximum inbox visibility. Legitimate senders use brand names, not headlines.
    // Flag if 2+ significant words (4+ chars) from the subject appear in the display name.
    if (!signals.suspiciousFromName && subject && fromDisplayName)
    {
      var subjectWords = subject.toLowerCase().match(/\b[a-z]{4,}\b/g) || [];
      var fromNameLower = fromDisplayName.toLowerCase();
      var echoCount = 0;
      for (var w = 0; w < subjectWords.length; w++)
      {
        if (fromNameLower.includes(subjectWords[w]))
        {
          echoCount++;
        }
      }
      if (echoCount >= 2)
      {
        signals.suspiciousFromName = true;
        logDebug('Subject echo in From name detected: ' + echoCount + ' words overlap');
      }
    }

    // ── Signal 2: Clickbait / sensationalism patterns ─────────────────────
    // Each pattern targets a CATEGORY of spam tactic, not specific phrases.
    // Patterns are checked against both subject AND from field concatenated,
    // since spammers stuff clickbait into display names too.
    // Each matching pattern increments clickbaitCount independently.
    const clickbaitPatterns = [
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
      /\b(0\s*%\s*(interest|apr)|balance transfer|transfer your.*(balance|debt))\b/i
    ];

    // Check subject + from concatenated — spammers stuff clickbait into both
    const textToCheck = subject + ' ' + from;
    for (let i = 0; i < clickbaitPatterns.length; i++)
    {
      if (clickbaitPatterns[i].test(textToCheck))
      {
        signals.clickbaitCount++;
      }
    }

    // ── Signal 3: Fear-mongering detection ────────────────────────────────
    // Boolean signal — we only need to know if fear is present, not how many
    // patterns match. First match short-circuits the loop.
    const fearPatterns = [
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
    ];

    for (let i = 0; i < fearPatterns.length; i++)
    {
      if (fearPatterns[i].test(textToCheck))
      {
        signals.fearMongering = true;
        logDebug('Fear-mongering detected (pattern match)');
        break; // Boolean signal — one match is enough
      }
    }

    // ── Signal 4: Marketing sender format ─────────────────────────────────
    // Checked against From field only (not subject). Detects spammy sender
    // name formatting like "Name | Org", "Topic, Company", pipe separators,
    // spammy business names, and suspicious email address patterns.
    if (/["|,]\s*[A-Z]/.test(from) ||                                                          // "Name | Org" or "Topic, Company"
        /\s+at\s+[A-Z]/i.test(from) ||                                                         // "Name at Organization"
        /\|\s*/.test(from) ||                                                                   // Pipe separator in display name
        /\b(investment|trading|wealth|profit|finance|insider|market)\s*(tools?|pro|tips?|alert)/i.test(from) ||  // Spammy business names
        /grow@with\./i.test(from) ||                                                            // Suspicious email pattern
        /@[a-z]\.[a-z]+\.(com|net)/i.test(from))                                               // Subdomain pattern: @F.FinanceInsiderPro.com
    {
      signals.marketingFormat = true;
      logDebug('Marketing sender format detected');
    }

    // ── Decision Logic (4 rules, evaluated in priority order) ─────────────
    //
    // Rules cascade from most-specific (Rule 0) to broadest (Rule 3).
    // Only one rule fires per email. Each returns immediately on match.

    // Rule 0: Bulk email + blacklisted sender = definitive spam
    // Rationale: Known spam domain + bulk infrastructure = zero false positive risk
    if (signals.bulkEmailService && signals.blacklistedSender)
    {
      logInfo('SPAM detected: Bulk email + blacklisted sender');
      return 100;
    }

    // Rule 1: Bulk email + 2+ clickbait patterns = spam
    // Rationale: Legitimate bulk senders rarely use multiple clickbait tactics
    if (signals.bulkEmailService && signals.clickbaitCount >= 2)
    {
      logInfo('SPAM detected: Bulk email + clickbait (' + signals.clickbaitCount + ' patterns)');
      return 100;
    }

    // Rule 2: Bulk email + 2+ distinct spam behaviors = spam
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
      return 100;
    }

    // Rule 3: Extreme clickbait alone (no bulk email required)
    // Rationale: 3+ clickbait hits is so anomalous that even non-bulk senders
    // are almost certainly spam (catches direct-send spam)
    if (signals.clickbaitCount >= 3)
    {
      logInfo('SPAM detected: Extreme clickbait (' + signals.clickbaitCount + ' patterns)');
      return 100;
    }

    // No rule triggered — email is not spam
    logDebug('Not spam - signals: bulk=' + signals.bulkEmailService +
             ', blacklist=' + signals.blacklistedSender +
             ', clickbait=' + signals.clickbaitCount +
             ', fear=' + signals.fearMongering +
             ', marketing=' + signals.marketingFormat +
             ', suspiciousFrom=' + signals.suspiciousFromName);
    return 0;
  }
  catch (error)
  {
    logError('Error analyzing message: ' + error.toString());
    return 0; // Default to not-spam on error — better to miss spam than delete legit mail
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
  if (CONFIG.maxEmailsPerRun < 1 || CONFIG.maxEmailsPerRun > 500)
  {
    throw new Error('Invalid maxEmailsPerRun: must be between 1 and 500');
  }

  if (CONFIG.spamThreshold < 0 || CONFIG.spamThreshold > 100)
  {
    throw new Error('Invalid spamThreshold: must be between 0 and 100');
  }

  if (CONFIG.daysToCheck < 0 || CONFIG.daysToCheck > 30)
  {
    throw new Error('Invalid daysToCheck: must be between 0 and 30');
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
  if (!input)
  {
    return '';
  }

  const str = String(input);
  const maxLength = 100000; // 100KB max

  return str.length > maxLength ? str.substring(0, maxLength) : str;
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
  if (!text)
  {
    return '';
  }

  // Truncate to 100 chars and collapse newlines to spaces
  const sanitized = String(text).substring(0, 100).replace(/[\n\r]/g, ' ');
  return sanitized;
}


// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Count regex matches in a text string.
 *
 * @param {string} text    - Text to search.
 * @param {RegExp} pattern - Regex pattern (should have global flag for multiple matches).
 * @return {number} Number of matches found. Returns 0 if inputs are falsy.
 */
function countMatches(text, pattern)
{
  if (!text || !pattern)
  {
    return 0;
  }

  const matches = text.match(pattern);
  return matches ? matches.length : 0;
}

/**
 * Count keyword matches in text and return a weighted score.
 *
 * Performs case-sensitive substring matching for each keyword.
 * Each match adds the specified weight to the total score.
 *
 * @param {string} text          - Text to search.
 * @param {Array<string>} keywords - Array of keywords to match.
 * @param {number} weight        - Score points to add per match.
 * @return {number} Total weighted score. Returns 0 if inputs are falsy/empty.
 */
function countKeywordMatches(text, keywords, weight)
{
  if (!text || !keywords || keywords.length === 0)
  {
    return 0;
  }

  let score = 0;
  for (let i = 0; i < keywords.length; i++)
  {
    if (text.includes(keywords[i]))
    {
      score += weight;
    }
  }

  return score;
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
  const whitelist = props.getProperty('LEGITIMATE_DOMAINS');
  return whitelist ? JSON.parse(whitelist) : [];
}

/**
 * Get the current blacklist from Script Properties.
 *
 * @return {Array<string>} Array of blacklisted domain substrings.
 */
function getBlacklist()
{
  const props = PropertiesService.getScriptProperties();
  const blacklist = props.getProperty('SUSPICIOUS_DOMAINS');
  return blacklist ? JSON.parse(blacklist) : [];
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

    // Grab the first message from the first matching thread
    const message = threads[0].getMessages()[0];
    const subject = message.getSubject();
    const from = message.getFrom();
    const rawContent = message.getRawContent();

    logInfo('=== DEBUG: WHY FLAGGED? ===');
    logInfo('Subject: ' + subject);
    logInfo('From: ' + from);
    logInfo('');

    // Check whitelist status
    const whitelist = getWhitelist();
    const fromLower = from.toLowerCase();
    let isWhitelisted = false;
    for (let i = 0; i < whitelist.length; i++)
    {
      if (fromLower.includes(whitelist[i]))
      {
        logInfo('✓ WHITELISTED: matches "' + whitelist[i] + '"');
        isWhitelisted = true;
        break;
      }
    }
    if (!isWhitelisted)
    {
      logInfo('✗ NOT WHITELISTED');
      logInfo('  Whitelist domains: ' + whitelist.join(', '));
    }

    // Check bulk email service fingerprints in raw headers
    const rawLower = rawContent.toLowerCase();
    if (rawLower.includes('amazonses.com') || rawLower.includes('x-ses-'))
    {
      logInfo('⚠ Bulk email: Amazon SES detected');
    }
    if (rawLower.includes('sendgrid.net'))
    {
      logInfo('⚠ Bulk email: SendGrid detected');
    }

    // Check marketing format in From field
    if (/["|,]\s*[A-Z]/.test(from) || /\|\s*/.test(from))
    {
      logInfo('⚠ Marketing format detected in From field');
    }

    // Run the full detection pipeline and show final score
    logInfo('');
    logInfo('Final score: ' + analyzeMessage(message));
    logInfo('=== END DEBUG ===');
  }
  catch (error)
  {
    logError('Debug failed: ' + error.toString());
  }
}
