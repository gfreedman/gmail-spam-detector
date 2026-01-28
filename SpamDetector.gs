/**
 * Gmail Spam Detector - Google Apps Script
 * @version 6.5.0
 *
 * Detects spam using behavioral patterns spammers can't easily change:
 * - Bulk email infrastructure (Amazon SES, SendGrid)
 * - Clickbait/fear-mongering subject patterns
 * - Unicode obfuscation (Cyrillic, Greek, fullwidth chars)
 * - Marketing sender format
 *
 * Reports spam to Gmail and permanently deletes (vaporizes) it.
 *
 * Setup: See README.md or run setup() and follow the logs.
 */

// Configuration - frozen to prevent accidental modification
const CONFIG = Object.freeze({
  // Maximum number of emails to process per run (to avoid timeout)
  maxEmailsPerRun: 50,

  // Minimum spam score to mark as spam
  // NEW APPROACH: Pattern-based detection returns 0 (not spam) or 100 (spam)
  // Threshold is now simply 50 (anything marked as spam = 100)
  // This is a binary decision, not a scoring system
  spamThreshold: 50,

  // How many days back to check for unprocessed emails
  daysToCheck: 1,

  // Label to mark processed emails (to avoid reprocessing)
  processedLabel: 'SpamChecked',

  // Enable debug logging
  debug: false,

  // Maximum email size to process (in bytes) - prevents memory issues
  maxEmailSizeBytes: 5 * 1024 * 1024 // 5MB
});

// Default whitelist/blacklist for initial setup
// Actual lists are stored in Script Properties (use addToWhitelist/addToBlacklist to manage)
const DEFAULT_DOMAINS = Object.freeze({
  legitimate: Object.freeze([
    'sardine.ai', 'meetup.com', 'substack.com', 'conservative.ca',
    'sundaymass.store', 'customerservice@stan', 'privaterelay.appleid.com',
    'email.meetup.com', 'ben-evans.com', 'linkedin.com', 'e.linkedin.com',
    'linkedin.email', 'dsf.ca', 'dragonfly'
  ]),
  suspicious: Object.freeze([
    'financeinsiderpro.com', 'financebuzz', 'smartinvestmenttools',
    'investorplace', 'weissratings', 'americanprofitinsight.com'
  ])
});

/**
 * Main function to process inbox emails
 * This should be set to run every 15 minutes via trigger
 */
function processInbox()
{
  const startTime = Date.now();
  let spamCount = 0;
  let processedCount = 0;
  let errorCount = 0;

  try
  {
    validateConfig();

    const label = getOrCreateLabel(CONFIG.processedLabel);
    const searchQuery = buildSearchQuery();

    logInfo('Search query: ' + searchQuery);

    const threads = GmailApp.search(searchQuery, 0, CONFIG.maxEmailsPerRun);

    logInfo('Found ' + threads.length + ' threads to process');

    // Process each thread independently with error isolation
    for (let i = 0; i < threads.length; i++)
    {
      try
      {
        const thread = threads[i];
        const result = processThread(thread);

        spamCount += result.spamCount;
        processedCount += result.processedCount;

        // Mark thread as processed after successful processing
        thread.addLabel(label);
      }
      catch (threadError)
      {
        errorCount++;
        logError('Error processing thread: ' + threadError.toString());
        // Continue processing other threads
      }
    }

    const duration = Date.now() - startTime;
    logInfo('Completed in ' + duration + 'ms: Processed ' + processedCount +
            ' emails, marked ' + spamCount + ' as spam, ' + errorCount + ' errors');
  }
  catch (error)
  {
    logError('Critical error in processInbox: ' + error.toString());
    throw error; // Re-throw to ensure trigger failures are visible
  }
}

/**
 * Process a single thread and return statistics
 *
 * @param {GmailThread} thread - The Gmail thread to process
 * @return {Object} Object with spamCount and processedCount
 */
function processThread(thread)
{
  let spamCount = 0;
  let processedCount = 0;
  let threadMarkedAsSpam = false;

  const messages = thread.getMessages();

  // Process all messages in thread
  for (let i = 0; i < messages.length; i++)
  {
    try
    {
      const message = messages[i];

      // Skip if already processed or too large
      if (!shouldProcessMessage(message))
      {
        continue;
      }

      processedCount++;
      const spamScore = analyzeMessage(message);

      logDebug('Email: "' + sanitizeForLog(message.getSubject()) + '" - Score: ' + spamScore);

      // Only mark thread as spam once, even if multiple messages are spam
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
      // Continue processing other messages in thread
    }
  }

  return { spamCount: spamCount, processedCount: processedCount };
}

/**
 * Determine if a message should be processed
 *
 * @param {GmailMessage} message - The message to check
 * @return {boolean} True if message should be processed
 */
function shouldProcessMessage(message)
{
  try
  {
    // Check if message is too large to process safely
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
    return false;
  }
}

/**
 * Build search query to find unprocessed emails
 *
 * @return {string} Gmail search query string
 */
function buildSearchQuery()
{
  const date = new Date();
  date.setDate(date.getDate() - CONFIG.daysToCheck);
  const dateStr = Utilities.formatDate(date, Session.getScriptTimeZone(), 'yyyy/MM/dd');

  // Search inbox for recent emails that haven't been processed yet
  return 'in:inbox -label:' + CONFIG.processedLabel + ' after:' + dateStr;
}

/**
 * Analyze a message using pattern-based detection (not scoring!)
 *
 * Strategy: Detect behavioral patterns that spammers can't easily change
 * - Bulk email infrastructure (Amazon SES, SendGrid)
 * - Clickbait subject patterns
 * - Fear-mongering language
 * - Marketing sender format
 *
 * Returns: 0 (not spam) or 100 (spam) - binary decision
 *
 * @param {GmailMessage} message - The message to analyze
 * @return {number} 0 or 100
 */
function analyzeMessage(message)
{
  try
  {
    const subject = sanitizeInput(message.getSubject());
    const body = sanitizeInput(message.getPlainBody());
    const from = sanitizeInput(message.getFrom());
    const rawContent = message.getRawContent(); // Full email headers

    // WHITELIST CHECK: Skip spam detection for known legitimate domains
    const whitelist = getWhitelist();
    const fromLower = from.toLowerCase();
    for (let i = 0; i < whitelist.length; i++)
    {
      if (fromLower.includes(whitelist[i]))
      {
        logDebug('Whitelisted domain detected: ' + whitelist[i]);
        return 0; // Not spam - whitelisted
      }
    }

    // PATTERN DETECTION: Analyze spam signals
    const signals = {
      bulkEmailService: false,
      clickbaitCount: 0,
      fearMongering: false,
      marketingFormat: false
    };

    // SIGNAL 1: Bulk email service (Amazon SES, SendGrid, etc.)
    if (rawContent.toLowerCase().includes('amazonses.com') ||
        rawContent.toLowerCase().includes('x-ses-') ||
        rawContent.toLowerCase().includes('sendgrid.net'))
    {
      signals.bulkEmailService = true;
      logDebug('Bulk email service detected');
    }

    // SIGNAL 2: Clickbait/Sensationalism detection (category-based, not keyword lists!)
    // Each pattern catches a CATEGORY of spam tactics, not specific phrases
    // v6.0: Now checks BOTH subject AND from field, added new patterns

    const clickbaitPatterns = [
      // SENSATIONALIST ADJECTIVES: shocking, bizarre, stunning, etc. (broad match)
      // Catches: "shocking admission", "bizarre discovery", "stunning revelation", etc.
      /\b(shocking|stunning|bizarre|mysterious|secret|hidden|leaked|exposed|forbidden)\b/i,

      // v6.0: TERRIFYING/ALARMING adjectives (often in From field)
      // Catches: "A terrifying new warning", "alarming discovery", etc.
      /\b(terrifying|alarming|devastating|horrifying|frightening|chilling|disturbing)\b/i,

      // CURIOSITY GAP: (mystery word) + (visual/media word)
      // Catches: "strange picture", "secret photo", "hidden camera", etc.
      /(strange|secret|hidden|mysterious|shocking|bizarre|unusual|leaked).*(picture|photo|image|video|camera|footage|document)/i,

      // URGENCY + SENSATIONALISM: (urgent word) + (sensational concept)
      // Catches: "breaking news", "urgent warning", "alert exposed", etc.
      /(breaking|urgent|warning|alert|stop|exposed|banned).*(news|truth|secret|scandal|exposed|revealed)/i,

      // FINANCIAL FEAR-MONGERING: (market/money word) + (crisis word)
      // Catches: "market crash", "stock collapse", "economy shift", "bitcoin warning", etc.
      /(market|stock|economy|dollar|gold|bitcoin|investment|crypto).*(crash|collapse|shift|crisis|warning|alert|plunge|tank)/i,

      // "CAUGHT" PATTERN: Visual proof framing
      // Catches: "caught on camera", "caught doing", "caught red-handed", etc.
      /caught (on|doing|in|red-handed)/i,

      // TRANSFORMATION CLICKBAIT: (what/this) + (impact verb)
      // Catches: "this changes everything", "what stunned everyone", etc.
      /(what|this).*(changes everything|stunned everyone|shocked|amazed|surprised)/i,

      // v6.0: CELEBRITY/POLITICAL NAME-DROPPING for false credibility
      // Catches: "RFK Jr Issues Warning", "Trump Reveals", "Musk Exposes", etc.
      /\b(RFK|Trump|Biden|Musk|Elon|Kennedy|Obama|Fauci|Gates)\b.*(warning|says|reveals|exposes|issues|predicts|warns)/i,

      // v6.2: CELEBRITY MERCHANDISE/COLLECTIBLE SCAM
      // Catches: "Trump Coin", "Trump $2 Bill", "Biden Medal", "Trump's Legacy", etc.
      // L6 INSIGHT: Celebrity + product/legacy = collectible scam category
      /\b(Trump|Biden|Obama|Kennedy)\b.*(coin|bill|medal|card|stamp|legacy|commemorat|collect|mint|gold|silver)/i,

      // v6.0: DEMOGRAPHIC TARGETING (age-based fear)
      // Catches: "Seniors Most At Risk", "If you're over 60", "Retirees affected", etc.
      /\b(seniors?|elderly|retirees?|boomers?|over \d{2}|born before|age \d{2})\b.*(risk|warning|alert|danger|affected|target)/i,

      // v6.0: YEAR-BASED URGENCY (current year for fake timeliness)
      // Catches: "2025 Warning", "2026 Prediction", etc.
      /\b202[4-9]\b.*(warning|alert|prediction|forecast|crisis)/i,

      // v6.0: CONSPIRACY/HIDING pattern
      // Catches: "What else are they hiding", "What they don't want you to know", etc.
      /(what|who).*(hiding|don't want you|truth|they won't tell)/i,

      // v6.0: MILITARY/WAR SENSATIONALISM
      // Catches: "Declared war", "Bombed", "Attack", "Destroyed", etc.
      /\b(declared war|bombed|bombing|attack|attacked|destroyed|invasion)\b/i,

      // v6.0: STOCK PRICE HYPE
      // Catches: "Under $1 a share", "$5 stock", "penny stock", etc.
      /\$\d+(\.\d+)?\s*(a\s+)?share|\bpenny stock\b/i,

      // v6.0: WATCH/SEE WHAT HAPPENED (curiosity gap)
      // Catches: "Watch what happened", "See what happens when", etc.
      /\b(watch|see)\s+(what|this|the moment)/i,

      // STRUCTURAL SPAM INDICATORS
      /【.*】/,           // Japanese date brackets (spammer tactic)
      /\[.{3,}[?!]\]/,    // v6.0: Square brackets with question/exclamation [Like This?]
      /💼|📸|⏯️|🚨|⚠️|📰|💰/,  // Sensationalist emoji (business, camera, play, alert, money)
      /\?\?\?|!!!/,       // Multiple punctuation (urgency tactic)
      /\bWATCH\b.*\?$/i,  // "WATCH" + question mark (clickbait structure)

      // v6.0: CYRILLIC/UNICODE OBFUSCATION (spammers use lookalike characters)
      // Catches: "Еlоn" (Cyrillic Е, о), "Wаr" (Cyrillic а), etc.
      /[\u0400-\u04FF]/,  // Any Cyrillic character = spam evasion tactic

      // v6.1: GREEK CHARACTER OBFUSCATION (Β instead of B, etc.)
      // Catches: "Βanks" (Greek Β), "Αmazon" (Greek Α), etc.
      /[\u0370-\u03FF]/,  // Any Greek character = spam evasion tactic

      // v6.2: FULLWIDTH CHARACTER OBFUSCATION (＄ instead of $, etc.)
      // L6 INSIGHT: Fullwidth forms (U+FF00-FFEF) are NEVER legitimate in English
      // Catches: "＄2 Bill", "１００％ guaranteed", etc.
      /[\uFF00-\uFFEF]/,  // Any fullwidth character = spam evasion tactic

      // v6.0: JOBS/EMPLOYMENT FEAR
      // Catches: "jobs disappeared", "jobs that never existed", "layoffs"
      /\b(jobs?|employment).*(disappeared|vanished|never existed|fake|fraud|layoffs?)/i,

      // v6.1: BANK/BRANCH CLOSING FEAR
      // Catches: "Banks closing", "branch closures", "ATMs shutting down", etc.
      /\b(banks?|branch|branches|ATMs?).*(clos|shut|disappear|eliminat)/i,

      // v6.1: BUILDING/INSTITUTION EMOJI (banks, hospitals, etc.)
      /🏦|🏥|🏛️|🏢/,

      // v6.2: COLLECTIBLE/COMMEMORATIVE SCAM CATEGORY
      // L6 INSIGHT: This is a distinct spam category, not individual keywords
      // Catches: "Limited Edition", "Minted", "Commemorative", "Collector's Item"
      /\b(minted|commemorat|collector'?s?|limited edition|rare coin|gold.?plated|silver.?plated)\b/i
    ];

    // v6.0: Check BOTH subject AND from field for clickbait patterns
    const textToCheck = subject + ' ' + from;
    for (let i = 0; i < clickbaitPatterns.length; i++)
    {
      if (clickbaitPatterns[i].test(textToCheck))
      {
        signals.clickbaitCount++;
      }
    }

    // SIGNAL 3: Fear-mongering (category-based detection)
    // Broad categories that catch variations without hardcoded phrases
    // v6.0: Fixed case-insensitive urgency words, checks subject + from

    const fearPatterns = [
      // GOVERNMENT FEAR: IRS, NSA, FBI, government + any threat/revelation
      // Catches: "government warning", "NSA spied", "government admission", etc.
      /\b(IRS|NSA|FBI|CIA|government|federal)\b.*(warn|hiding|secret|spy|track|audit|investigation|admission|reveal|expose|confiscat)/i,

      // FINANCIAL FEAR: Banks, accounts + seizure/theft/loss threats
      // Catches: "banks seize", "bank account frozen", "savings stolen", etc.
      /\b(banks?|bank account|credit card|social security|identity|savings|cash|money)\b.*(seize|steal|stolen|hacked|freeze|frozen|close|closed|warning|alert|confiscat|take|taking|lost)/i,

      // HEALTH FEAR: Medical warnings, dangers
      // v6.0: Added more health terms (FDA, health crisis, at risk)
      /\b(blood thinner|medication|drug|vaccine|doctor|FDA|health crisis|at risk)\b.*(warning|danger|deadly|killing|risk|avoid|corrupt)/i,

      // v6.0: STANDALONE URGENCY WORDS (case-insensitive!)
      // Catches: "Warning", "WARNING", "Alert", etc.
      /\b(warning|alert|urgent|breaking|exposed|banned|stopped)\b/i,

      // "STOP USING" pattern
      /\bSTOP (using|taking|doing|buying)\b/i
    ];

    for (let i = 0; i < fearPatterns.length; i++)
    {
      if (fearPatterns[i].test(textToCheck))
      {
        signals.fearMongering = true;
        logDebug('Fear-mongering detected (pattern match)');
        break;
      }
    }

    // SIGNAL 4: Marketing sender format ("Name | Org" or "Topic, Company" or "Name at Org")
    // v6.0: Also detect spammy sender names and suspicious email patterns
    if (/["|,]\s*[A-Z]/.test(from) ||
        /\s+at\s+[A-Z]/i.test(from) ||
        /\|\s*/.test(from) ||
        /\b(investment|trading|wealth|profit|finance|insider|market)\s*(tools?|pro|tips?|alert)/i.test(from) ||  // v6.0: Spammy business names
        /grow@with\./i.test(from) ||  // v6.0: Suspicious email patterns
        /@[a-z]\.[a-z]+\.(com|net)/i.test(from))  // v6.0: Subdomain email pattern (e.g., @F.FinanceInsiderPro.com)
    {
      signals.marketingFormat = true;
      logDebug('Marketing sender format detected');
    }

    // DECISION LOGIC (v6.0 - Less conservative when bulk email + marketing present)
    // RULE 1: Bulk email + 2+ clickbait patterns = SPAM
    if (signals.bulkEmailService && signals.clickbaitCount >= 2)
    {
      logInfo('SPAM detected: Bulk email + clickbait (' + signals.clickbaitCount + ' patterns)');
      return 100;
    }

    // RULE 2: Bulk email + 2+ spam behaviors = SPAM
    let spamBehaviorCount = 0;
    if (signals.clickbaitCount >= 1) spamBehaviorCount++;  // v6.0: Changed from >= 2 to >= 1
    if (signals.fearMongering) spamBehaviorCount++;
    if (signals.marketingFormat) spamBehaviorCount++;

    if (signals.bulkEmailService && spamBehaviorCount >= 2)
    {
      logInfo('SPAM detected: Bulk email + ' + spamBehaviorCount + ' spam behaviors');
      return 100;
    }

    // v6.0 NEW RULE 3: Bulk email + marketing format + ANY warning signal = SPAM
    // Rationale: Legitimate bulk newsletters DON'T combine marketing format with fear tactics
    if (signals.bulkEmailService && signals.marketingFormat &&
        (signals.clickbaitCount >= 1 || signals.fearMongering))
    {
      logInfo('SPAM detected: Bulk email + marketing format + warning signal');
      return 100;
    }

    // RULE 4: Extreme clickbait even without bulk email = SPAM
    if (signals.clickbaitCount >= 3)
    {
      logInfo('SPAM detected: Extreme clickbait (' + signals.clickbaitCount + ' patterns)');
      return 100;
    }

    // Not spam
    logDebug('Not spam - signals: bulk=' + signals.bulkEmailService +
             ', clickbait=' + signals.clickbaitCount +
             ', fear=' + signals.fearMongering +
             ', marketing=' + signals.marketingFormat);
    return 0;
  }
  catch (error)
  {
    logError('Error analyzing message: ' + error.toString());
    return 0; // Default to not spam on error
  }
}

/**
 * Mark message as spam and move to spam folder
 *
 * @param {GmailMessage} message - The spam message
 * @param {GmailThread} thread - The thread containing the message
 */
function markAsSpam(message, thread)
{
  try
  {
    const messageId = message.getId();
    const subject = sanitizeForLog(message.getSubject());

    // Check if Gmail Advanced Service is available
    if (typeof Gmail === 'undefined' || !Gmail.Users || !Gmail.Users.Messages)
    {
      logError('Gmail Advanced Service not available! Enable it in Apps Script:');
      logError('  Services > + > Gmail API > Add');
      // Fallback: just move to spam using GmailApp
      thread.moveToSpam();
      logInfo('SPAM REPORTED (fallback): ' + subject);
      return;
    }

    // 1. SIGNAL: Report as spam to train Gmail's filters via the Gmail REST API.
    //    Uses the Advanced Service (not GmailApp) so both operations go through
    //    the same API surface, avoiding cross-API state inconsistency.
    logDebug('Reporting spam: ' + messageId);
    Gmail.Users.Messages.modify(
      { addLabelIds: ['SPAM'], removeLabelIds: ['INBOX'] },
      'me',
      messageId
    );
    logDebug('Spam report sent');

    // 2. Brief pause to let Gmail process the spam report before deletion.
    Utilities.sleep(500);

    // 3. THE VAPORIZER: Permanently deletes the message from the server.
    logDebug('Vaporizing: ' + messageId);
    Gmail.Users.Messages.remove('me', messageId);

    logInfo('SPAM REPORTED & VAPORIZED: ' + subject);
  }
  catch (error)
  {
    logError('Error marking as spam: ' + error.toString());
    logError('Message ID: ' + message.getId());
    logError('Subject: ' + sanitizeForLog(message.getSubject()));

    // Fallback: try basic spam move if vaporizer fails
    try
    {
      thread.moveToSpam();
      logInfo('Fallback: moved to spam folder (no delete)');
    }
    catch (fallbackError)
    {
      logError('Fallback also failed: ' + fallbackError.toString());
    }

    throw error; // Re-throw to ensure caller knows it failed
  }
}

/**
 * Get or create label for tracking processed emails
 *
 * @param {string} labelName - Name of the label
 * @return {GmailLabel} The label object
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

/**
 * Validate configuration values
 *
 * @throws {Error} If configuration is invalid
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

/**
 * Sanitize input to prevent potential issues
 *
 * @param {string} input - Input string to sanitize
 * @return {string} Sanitized string
 */
function sanitizeInput(input)
{
  if (!input)
  {
    return '';
  }

  // Convert to string and truncate if too long
  const str = String(input);
  const maxLength = 100000; // 100KB max

  return str.length > maxLength ? str.substring(0, maxLength) : str;
}

/**
 * Sanitize text for logging to prevent log injection
 *
 * @param {string} text - Text to sanitize
 * @return {string} Sanitized text
 */
function sanitizeForLog(text)
{
  if (!text)
  {
    return '';
  }

  // Truncate and remove newlines/special chars
  const sanitized = String(text).substring(0, 100).replace(/[\n\r]/g, ' ');
  return sanitized;
}

/**
 * Count matches of a regex pattern in text
 *
 * @param {string} text - Text to search
 * @param {RegExp} pattern - Pattern to match
 * @return {number} Number of matches
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
 * Count keyword matches and return weighted score
 *
 * @param {string} text - Text to search
 * @param {Array<string>} keywords - Array of keywords to match
 * @param {number} weight - Score weight per match
 * @return {number} Total score
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

/**
 * Log info message
 *
 * @param {string} message - Message to log
 */
function logInfo(message)
{
  Logger.log('[INFO] ' + message);
}

/**
 * Log debug message (only if debug enabled)
 *
 * @param {string} message - Message to log
 */
function logDebug(message)
{
  if (CONFIG.debug)
  {
    Logger.log('[DEBUG] ' + message);
  }
}

/**
 * Log error message
 *
 * @param {string} message - Message to log
 */
function logError(message)
{
  Logger.log('[ERROR] ' + message);
}

/**
 * Setup function - run this once to authorize the script
 */
function setup()
{
  try
  {
    logInfo('Setting up spam detector...');

    // Validate configuration
    validateConfig();

    // Create the processed label
    getOrCreateLabel(CONFIG.processedLabel);

    // Initialize Script Properties with default whitelist/blacklist
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
 * Initialize Script Properties with default whitelist and blacklist
 * Only runs if properties don't exist yet
 */
function initializeScriptProperties()
{
  const props = PropertiesService.getScriptProperties();

  // Initialize whitelist if not exists
  if (!props.getProperty('LEGITIMATE_DOMAINS'))
  {
    const defaultWhitelist = Array.from(DEFAULT_DOMAINS.legitimate);
    props.setProperty('LEGITIMATE_DOMAINS', JSON.stringify(defaultWhitelist));
    logInfo('Initialized whitelist with ' + defaultWhitelist.length + ' domains');
  }

  // Initialize blacklist if not exists
  if (!props.getProperty('SUSPICIOUS_DOMAINS'))
  {
    const defaultBlacklist = Array.from(DEFAULT_DOMAINS.suspicious);
    props.setProperty('SUSPICIOUS_DOMAINS', JSON.stringify(defaultBlacklist));
    logInfo('Initialized blacklist with ' + defaultBlacklist.length + ' domains');
  }
}

/**
 * Get current whitelist from Script Properties
 * @return {Array<string>} Array of whitelisted domains
 */
function getWhitelist()
{
  const props = PropertiesService.getScriptProperties();
  const whitelist = props.getProperty('LEGITIMATE_DOMAINS');
  return whitelist ? JSON.parse(whitelist) : [];
}

/**
 * Get current blacklist from Script Properties
 * @return {Array<string>} Array of blacklisted domains
 */
function getBlacklist()
{
  const props = PropertiesService.getScriptProperties();
  const blacklist = props.getProperty('SUSPICIOUS_DOMAINS');
  return blacklist ? JSON.parse(blacklist) : [];
}

/**
 * Add a domain to the whitelist
 * @param {string} domain - Domain to whitelist (e.g., 'example.com')
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
 * Add a domain to the blacklist
 * @param {string} domain - Domain to blacklist (e.g., 'spammer.com')
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
 * Remove a domain from the whitelist
 * @param {string} domain - Domain to remove
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
 * Remove a domain from the blacklist
 * @param {string} domain - Domain to remove
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
 * View current whitelist
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
 * View current blacklist
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
 * REFRESH WHITELIST: Adds any missing default domains to the whitelist
 * Run this if you set up before new legitimate domains were added
 */
function refreshWhitelist()
{
  const props = PropertiesService.getScriptProperties();
  const currentWhitelist = getWhitelist();
  const defaults = DEFAULT_DOMAINS.legitimate;
  let addedCount = 0;

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
 * DEBUG: Test why a specific email might be flagged
 * Searches for the email and shows all detection signals
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
    const subject = message.getSubject();
    const from = message.getFrom();
    const rawContent = message.getRawContent();

    logInfo('=== DEBUG: WHY FLAGGED? ===');
    logInfo('Subject: ' + subject);
    logInfo('From: ' + from);
    logInfo('');

    // Check whitelist
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

    // Check bulk email service
    const rawLower = rawContent.toLowerCase();
    if (rawLower.includes('amazonses.com') || rawLower.includes('x-ses-'))
    {
      logInfo('⚠ Bulk email: Amazon SES detected');
    }
    if (rawLower.includes('sendgrid.net'))
    {
      logInfo('⚠ Bulk email: SendGrid detected');
    }

    // Check marketing format
    if (/["|,]\s*[A-Z]/.test(from) || /\|\s*/.test(from))
    {
      logInfo('⚠ Marketing format detected in From field');
    }

    logInfo('');
    logInfo('Final score: ' + analyzeMessage(message));
    logInfo('=== END DEBUG ===');
  }
  catch (error)
  {
    logError('Debug failed: ' + error.toString());
  }
}

