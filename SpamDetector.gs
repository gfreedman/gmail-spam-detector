/**
 * Gmail Spam Detector - Google Apps Script
 *
 * This script detects spam emails based on patterns observed in common spam messages
 * and automatically marks them as spam and moves them to the SPAM folder.
 *
 * Setup Instructions:
 * 1. Open Google Apps Script (script.google.com)
 * 2. Create a new project
 * 3. Copy this entire script into Code.gs
 * 4. Run 'setup()' function once to authorize the script
 * 5. Set up a time-based trigger:
 *    - Click on the clock icon (Triggers)
 *    - Add Trigger
 *    - Choose function: processInbox
 *    - Choose event source: Time-driven
 *    - Choose type of time based trigger: Minutes timer
 *    - Choose minute interval: Every 15 minutes
 *
 * @author Anti-Spam Dataset
 * @version 6.1 - Greek Character Detection
 *
 * v6.1 CHANGES: Fixed Greek character obfuscation detection
 * - FIXED: Added Greek character range detection (Β instead of B, etc.)
 * - ADDED: Bank/branch closing pattern for financial fear spam
 * - ADDED: Building emoji detection (🏦 etc.)
 * - RESULT: Catches "Major Βanks Continue Closing Locations 🏦" spam
 *
 * v6.0 CHANGES: Fixed critical blindspots that let "RFK Jr Issues 2025 Warning" through
 * - FIXED: Case-insensitive standalone warning words (Warning, Alert, Urgent)
 * - ADDED: Square brackets detection [like this?] (not just Japanese 【】)
 * - ADDED: From field sensationalism check ("terrifying", "alarming" in sender name)
 * - ADDED: Demographic targeting detection (seniors, elderly, age-based fear)
 * - ADDED: Celebrity/political name-dropping (RFK, Trump, Musk + warning/reveals)
 * - ADDED: Year-based urgency (2025/2026 Warning)
 * - ADDED: NEW RULE - Bulk email + marketing format + ANY single warning = SPAM
 * - RESULT: Catches distributed low-grade signals that evaded v5.1
 *
 * v5.1 CHANGES: Broadened patterns to catch subtler spam tactics
 * - ADDED: Standalone sensationalist adjectives (shocking, stunning, bizarre, etc.)
 * - BROADENED: Government fear now catches "admission/reveal/expose" (not just spy/hiding)
 * - BROADENED: Financial fear now catches "banks" + "seize/confiscate" (not just "bank account")
 * - RESULT: Catches "Government's Shocking Admission: Banks Could Seize Your Cash"
 *
 * v5.0 CHANGES: Complete rewrite to eliminate keyword array anti-pattern
 * - REMOVED: Hardcoded clickbait phrase arrays (was whack-a-mole)
 * - REMOVED: Hardcoded fear keyword lists (reactive, not proactive)
 * - ADDED: Category-based regex patterns that catch CLASSES of spam tactics
 *   * Curiosity gap: (mystery word) + (visual word) = catches ALL variations
 *   * Financial fear: (market word) + (crisis word) = catches ALL variations
 *   * Government fear: (agency) + (threat) = catches ALL variations
 *   * Urgency + sensationalism patterns
 *   * Structural spam indicators (emoji, punctuation, formatting)
 * - RESULT: Proactive detection without reactive keyword additions
 *
 * v4.0 CHANGES: Moved from complex scoring to simple pattern detection
 * - Detects bulk email services (Amazon SES, SendGrid)
 * - Detects clickbait/fear-mongering patterns
 * - Requires multiple signals (not just one)
 * - Returns binary decision: 0 or 100 (not spam or spam)
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
  maxEmailSizeBytes: 5 * 1024 * 1024, // 5MB

  // Timeout for individual email processing (milliseconds)
  emailProcessingTimeout: 5000
});

// Spam detection scoring weights - centralized for easy tuning
// Architecture: Tier 1 (structural) > Tier 2 (behavioral) > Tier 3 (content)
const SCORING_WEIGHTS = Object.freeze({
  // TIER 1: Structural indicators (very high confidence - 40-50 points)
  MALFORMED_HEADERS: 50,           // Header corruption/bleeding
  DISPLAY_NAME_MISMATCH: 40,       // Display name doesn't match email domain
  MULTIPLE_SENDERS: 35,            // Multiple sender names in From field
  SUSPICIOUS_FROM_PATTERN: 30,     // Unusual From field structure

  // TIER 2: Behavioral indicators (high confidence - 15-25 points)
  SUSPICIOUS_DOMAIN: 25,           // Increased from 15
  UNICODE_OBFUSCATION: 20,         // Increased from 15
  AFFILIATE_DISCLAIMER: 15,        // Increased from 12
  UNSUBSCRIBE_LANGUAGE: 12,        // Increased from 8
  NOREPLY_SENDER: 8,               // Increased from 5

  // TIER 3: Content indicators (medium confidence - 5-12 points)
  ALL_CAPS_SUBJECT: 12,
  SENSATIONALIST_KEYWORD: 10,
  HEALTH_SCAM: 10,
  MANY_LINKS_HIGH: 10,
  DATE_URGENCY: 8,
  EXCESSIVE_EXCLAMATION_SUBJECT: 8,
  FINANCIAL_SCAM: 8,
  CLICK_TRACKING: 8,
  FEAR_MONGERING: 7,
  MULTIPLE_CTAS: 7,
  TECH_HYPE: 6,
  MANY_LINKS_MEDIUM: 5,
  EXCLAMATION_PER_COUNT: 2,
  MAX_EXCLAMATION_SCORE: 15
});

// Compile regexes once for performance
const REGEX_CACHE = Object.freeze({
  dateUrgency: /january|february|march|april|may|june|july|august|september|october|november|december.*\d{1,2}.*202[0-9]/i,
  exclamationMarks: /!/g,
  linkTags: /<a\s+(?:[^>]*?\s+)?href/gi,
  ctaPatterns: /learn more|apply now|click here|get started|claim now/gi,
  cyrillic: /[а-яА-Я]/,
  greek: /[\u0370-\u03FF]/,
  phoneticExt: /[\u1D00-\u1DBF]/,
  latinExtAdd: /[\u1E00-\u1EFF]/,
  latinExtC: /[\u2C60-\u2C7F]/,
  latinExtD: /[\uA720-\uA7FF]/,
  alphaPres: /[\uFB00-\uFB4F]/,
  mathAlpha: /[\uD835]/
});

// Keyword arrays - centralized and frozen
const KEYWORDS = Object.freeze({
  sensationalist: Object.freeze([
    'breaking news', 'urgent', 'warning', 'caught on camera',
    'just exposed', 'shocking', 'stunned everyone', 'alert',
    'do not ignore', 'this changes everything', 'secret'
  ]),
  // Note: suspiciousDomains and legitimateDomains are now stored in Script Properties
  // Use addToWhitelist() / addToBlacklist() functions to manage them
  // Kept here as defaults for initial setup only
  suspiciousDomains_DEFAULT: Object.freeze([
    'financeinsiderpro.com', 'financebuzz', 'smartinvestmenttools',
    'investorplace', 'weissratings', 'americanprofitinsight.com'
  ]),
  legitimateDomains_DEFAULT: Object.freeze([
    'sardine.ai', 'meetup.com', 'substack.com', 'conservative.ca',
    'sundaymass.store', 'customerservice@stan', 'privaterelay.appleid.com',
    'email.meetup.com', 'ben-evans.com', 'linkedin.com', 'dsf.ca',
    'dragonfly'
  ]),
  financialScam: Object.freeze([
    'investment opportunity', 'cash back', 'bonus instantly',
    'approval decision', 'wealth transfer', 'smart money',
    'government infrastructure spending', 'stock tips',
    'make money', 'earn cash', 'financial freedom'
  ]),
  fearMongering: Object.freeze([
    'jobs disappeared', 'massive layoffs', 'market crash',
    'wealth confiscation', 'government hiding', 'exposed',
    'economic collapse', 'crisis'
  ]),
  healthScam: Object.freeze([
    'cure', 'erases', 'brain health', 'neuropathy',
    'miracle', 'breakthrough', 'doctors hate'
  ]),
  techHype: Object.freeze([
    'tesla', 'spacex', 'self-driving', 'ai takeover',
    'cybertruck', 'elon'
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

  // Process only unread messages to avoid reprocessing
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
      /[💼📸⏯️🚨⚠️📰💰]/,  // Sensationalist emoji (business, camera, play, alert, money)
      /\?\?\?|!!!/,       // Multiple punctuation (urgency tactic)
      /\bWATCH\b.*\?$/i,  // "WATCH" + question mark (clickbait structure)

      // v6.0: CYRILLIC/UNICODE OBFUSCATION (spammers use lookalike characters)
      // Catches: "Еlоn" (Cyrillic Е, о), "Wаr" (Cyrillic а), etc.
      /[\u0400-\u04FF]/,  // Any Cyrillic character = spam evasion tactic

      // v6.1: GREEK CHARACTER OBFUSCATION (Β instead of B, etc.)
      // Catches: "Βanks" (Greek Β), "Αmazon" (Greek Α), etc.
      /[\u0370-\u03FF]/,  // Any Greek character = spam evasion tactic

      // v6.0: JOBS/EMPLOYMENT FEAR
      // Catches: "jobs disappeared", "jobs that never existed", "layoffs"
      /\b(jobs?|employment).*(disappeared|vanished|never existed|fake|fraud|layoffs?)/i,

      // v6.1: BANK/BRANCH CLOSING FEAR
      // Catches: "Banks closing", "branch closures", "ATMs shutting down", etc.
      /\b(banks?|branch|branches|ATMs?).*(clos|shut|disappear|eliminat)/i,

      // v6.1: BUILDING/INSTITUTION EMOJI (banks, hospitals, etc.)
      /[🏦🏥🏛️🏢]/
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
 * Analyze sender for TIER 1 structural/malformation indicators
 * These are very high confidence spam signals that are hard to fake
 *
 * @param {string} from - The sender email/display name
 * @param {string} subject - The email subject (to detect header bleeding)
 * @return {Object} Object with score and reasons array
 */
function analyzeStructuralIndicators(from, subject)
{
  if (!from || from.length === 0)
  {
    return { score: 0, reasons: [] };
  }

  let score = 0;
  const reasons = [];

  // TIER 1.1: Malformed headers - "Subject:" bleeding into From field
  // This is a 100% reliable indicator found in all test spam
  if (from.toLowerCase().includes('subject:'))
  {
    score += SCORING_WEIGHTS.MALFORMED_HEADERS;
    reasons.push('Malformed headers (Subject: in From field) (+' + SCORING_WEIGHTS.MALFORMED_HEADERS + ')');
  }

  // TIER 1.2: Multiple senders in From field (using || separator)
  if (from.includes('||'))
  {
    score += SCORING_WEIGHTS.MULTIPLE_SENDERS;
    reasons.push('Multiple sender names in From field (+' + SCORING_WEIGHTS.MULTIPLE_SENDERS + ')');
  }

  // TIER 1.3: Display name mismatch - extract email vs display name
  // Pattern: "Display Name email@domain.com" or "Display Name <email@domain.com>"
  const emailMatch = from.match(/[\w.-]+@[\w.-]+\.[a-z]{2,}/i);
  if (emailMatch)
  {
    const emailDomain = emailMatch[0].split('@')[1];
    const displayPart = from.substring(0, from.indexOf(emailMatch[0])).trim();

    // Check if display name is completely different from domain
    if (displayPart.length > 3 && emailDomain)
    {
      const domainWords = emailDomain.replace(/\./g, ' ').toLowerCase();
      const displayWords = displayPart.replace(/[^a-z0-9\s]/gi, ' ').toLowerCase();

      // If display name has no words in common with domain, it's suspicious
      const displayWordArray = displayWords.split(/\s+/).filter(w => w.length > 2);
      const domainWordArray = domainWords.split(/\s+/).filter(w => w.length > 2);

      let hasCommonWord = false;
      for (let i = 0; i < displayWordArray.length; i++)
      {
        for (let j = 0; j < domainWordArray.length; j++)
        {
          if (displayWordArray[i] === domainWordArray[j])
          {
            hasCommonWord = true;
            break;
          }
        }
        if (hasCommonWord) break;
      }

      if (!hasCommonWord && displayWordArray.length > 0)
      {
        score += SCORING_WEIGHTS.DISPLAY_NAME_MISMATCH;
        reasons.push('Display name does not match email domain (+' + SCORING_WEIGHTS.DISPLAY_NAME_MISMATCH + ')');
      }
    }
  }

  // TIER 1.4: Suspicious From field patterns
  // Multiple domains in From field, concatenated text, missing spaces
  if (from.match(/\.com[A-Z]/i) || from.match(/\.com[a-z]{3,}/) || from.includes('grow@with'))
  {
    score += SCORING_WEIGHTS.SUSPICIOUS_FROM_PATTERN;
    reasons.push('Suspicious From field formatting (+' + SCORING_WEIGHTS.SUSPICIOUS_FROM_PATTERN + ')');
  }

  return { score: score, reasons: reasons };
}

/**
 * Analyze subject line for spam indicators
 *
 * @param {string} subject - The email subject line
 * @return {number} Spam score contribution
 */
function analyzeSubject(subject)
{
  if (!subject || subject.length === 0)
  {
    return 0;
  }

  let score = 0;
  const subjectLower = subject.toLowerCase();

  // Sensationalist keywords
  score += countKeywordMatches(subjectLower, KEYWORDS.sensationalist,
                                SCORING_WEIGHTS.SENSATIONALIST_KEYWORD);

  // Fake urgency with dates
  if (REGEX_CACHE.dateUrgency.test(subject))
  {
    score += SCORING_WEIGHTS.DATE_URGENCY;
  }

  // All caps (excluding short subjects which might be legitimate)
  if (subject.length > 10 && subject === subject.toUpperCase())
  {
    score += SCORING_WEIGHTS.ALL_CAPS_SUBJECT;
  }

  // Excessive exclamation marks
  const exclamationCount = countMatches(subject, REGEX_CACHE.exclamationMarks);
  if (exclamationCount >= 2)
  {
    score += SCORING_WEIGHTS.EXCESSIVE_EXCLAMATION_SUBJECT;
  }

  return score;
}

/**
 * Analyze sender email for suspicious patterns
 *
 * @param {string} from - The sender email address
 * @return {number} Spam score contribution
 */
function analyzeSender(from)
{
  if (!from || from.length === 0)
  {
    return 0;
  }

  let score = 0;
  const fromLower = from.toLowerCase();

  // Common spam sender domains/patterns
  // Load from Script Properties (allows runtime updates without code changes)
  const blacklist = getBlacklist();
  score += countKeywordMatches(fromLower, blacklist,
                                SCORING_WEIGHTS.SUSPICIOUS_DOMAIN);

  // Generic marketing patterns
  if (fromLower.includes('noreply') || fromLower.includes('no-reply'))
  {
    score += SCORING_WEIGHTS.NOREPLY_SENDER;
  }

  return score;
}

/**
 * Analyze email body for spam patterns
 *
 * @param {string} body - Plain text email body
 * @param {string} htmlBody - HTML email body
 * @return {number} Spam score contribution
 */
function analyzeBody(body, htmlBody)
{
  if (!body || body.length === 0)
  {
    return 0;
  }

  let score = 0;
  const bodyLower = body.toLowerCase();

  // Financial scam keywords
  score += countKeywordMatches(bodyLower, KEYWORDS.financialScam,
                                SCORING_WEIGHTS.FINANCIAL_SCAM);

  // Fear-mongering keywords
  score += countKeywordMatches(bodyLower, KEYWORDS.fearMongering,
                                SCORING_WEIGHTS.FEAR_MONGERING);

  // Health scam indicators
  score += countKeywordMatches(bodyLower, KEYWORDS.healthScam,
                                SCORING_WEIGHTS.HEALTH_SCAM);

  // Tech hype keywords
  score += countKeywordMatches(bodyLower, KEYWORDS.techHype,
                                SCORING_WEIGHTS.TECH_HYPE);

  // Unsubscribe language (common in spam)
  if (bodyLower.includes('unsubscribe') && bodyLower.includes('opt out'))
  {
    score += SCORING_WEIGHTS.UNSUBSCRIBE_LANGUAGE;
  }

  // Affiliate disclaimer language
  if (bodyLower.includes('this is an advertisement') ||
      bodyLower.includes('we may receive compensation'))
  {
    score += SCORING_WEIGHTS.AFFILIATE_DISCLAIMER;
  }

  // Multiple exclamation marks
  const exclamationCount = countMatches(body, REGEX_CACHE.exclamationMarks);
  if (exclamationCount >= 3)
  {
    score += Math.min(exclamationCount * SCORING_WEIGHTS.EXCLAMATION_PER_COUNT,
                      SCORING_WEIGHTS.MAX_EXCLAMATION_SCORE);
  }

  return score;
}

/**
 * Analyze links for suspicious patterns
 *
 * @param {string} htmlBody - HTML email body
 * @return {number} Spam score contribution
 */
function analyzeLinks(htmlBody)
{
  if (!htmlBody || htmlBody.length === 0)
  {
    return 0;
  }

  let score = 0;

  // Count number of links safely
  const linkCount = countMatches(htmlBody, REGEX_CACHE.linkTags);

  // Many links is suspicious
  if (linkCount > 10)
  {
    score += SCORING_WEIGHTS.MANY_LINKS_HIGH;
  }
  else if (linkCount > 5)
  {
    score += SCORING_WEIGHTS.MANY_LINKS_MEDIUM;
  }

  // Check for click tracking links
  if (htmlBody.toLowerCase().includes('click here') && linkCount > 0)
  {
    score += SCORING_WEIGHTS.CLICK_TRACKING;
  }

  // Multiple CTAs
  const ctaCount = countMatches(htmlBody, REGEX_CACHE.ctaPatterns);
  if (ctaCount >= 2)
  {
    score += SCORING_WEIGHTS.MULTIPLE_CTAS;
  }

  return score;
}

/**
 * Detect Unicode character obfuscation
 *
 * @param {string} text - Text to analyze
 * @return {number} Spam score contribution
 */
function analyzeUnicodeObfuscation(text)
{
  if (!text || text.length === 0)
  {
    return 0;
  }

  let score = 0;

  // Check for various Unicode obfuscation patterns
  const obfuscationPatterns = [
    REGEX_CACHE.cyrillic,
    REGEX_CACHE.greek,
    REGEX_CACHE.phoneticExt,
    REGEX_CACHE.latinExtAdd,
    REGEX_CACHE.latinExtC,
    REGEX_CACHE.latinExtD,
    REGEX_CACHE.alphaPres
  ];

  for (let i = 0; i < obfuscationPatterns.length; i++)
  {
    if (obfuscationPatterns[i].test(text))
    {
      score += SCORING_WEIGHTS.UNICODE_OBFUSCATION;
      break; // Only count once even if multiple patterns match
    }
  }

  // Check for mathematical alphanumeric symbols (bold, italic variants)
  if (REGEX_CACHE.mathAlpha.test(text))
  {
    score += SCORING_WEIGHTS.UNICODE_OBFUSCATION;
  }

  return score;
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
    // Move to spam
    thread.moveToSpam();

    // Also mark as read to keep inbox clean
    thread.markRead();

    logInfo('Marked as spam: ' + sanitizeForLog(message.getSubject()));
  }
  catch (error)
  {
    logError('Error marking as spam: ' + error.toString());
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
    const defaultWhitelist = Array.from(KEYWORDS.legitimateDomains_DEFAULT);
    props.setProperty('LEGITIMATE_DOMAINS', JSON.stringify(defaultWhitelist));
    logInfo('Initialized whitelist with ' + defaultWhitelist.length + ' domains');
  }

  // Initialize blacklist if not exists
  if (!props.getProperty('SUSPICIOUS_DOMAINS'))
  {
    const defaultBlacklist = Array.from(KEYWORDS.suspiciousDomains_DEFAULT);
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
 * Test function to analyze a specific email by subject search
 *
 * @param {string} testSubject - Subject line to search for (optional)
 */
function testSpamDetection(testSubject)
{
  try
  {
    const subject = testSubject || 'URGENT: Government Checks monthly';
    const threads = GmailApp.search('subject:"' + subject + '"', 0, 1);

    if (threads.length === 0)
    {
      logInfo('No email found with subject: ' + subject);
      logInfo('Try searching for a different subject or check your inbox.');
      return;
    }

    const message = threads[0].getMessages()[0];
    const from = message.getFrom();
    const subj = message.getSubject();
    const body = message.getPlainBody().substring(0, 500);

    // Test structural detection directly
    logInfo('=== Spam Detection Test Results ===');
    logInfo('Subject: ' + sanitizeForLog(subj));
    logInfo('From: ' + from);
    logInfo('Date: ' + message.getDate());
    logInfo('--- Testing Structural Detection ---');

    const structuralResult = analyzeStructuralIndicators(from, subj);
    logInfo('Structural Score: ' + structuralResult.score);
    if (structuralResult.reasons.length > 0)
    {
      structuralResult.reasons.forEach(function(reason) {
        logInfo('  - ' + reason);
      });
    }
    else
    {
      logInfo('  - No structural indicators detected');
    }

    // Check if "Subject:" is in from field
    logInfo('--- Debug Info ---');
    logInfo('Does From contain "subject:": ' + from.toLowerCase().includes('subject:'));
    logInfo('Does From contain "||": ' + from.includes('||'));

    const score = analyzeMessage(message);
    logInfo('--- Final Results ---');
    logInfo('Total Spam Score: ' + score + ' / 100');
    logInfo('Threshold: ' + CONFIG.spamThreshold);
    logInfo('Would be marked as spam: ' + (score >= CONFIG.spamThreshold ? 'YES' : 'NO'));
    logInfo('===================================');
  }
  catch (error)
  {
    logError('Test failed: ' + error.toString());
    throw error;
  }
}

/**
 * Utility function to test the spam detector on the most recent email
 */
function testOnRecentEmail()
{
  try
  {
    const threads = GmailApp.search('in:inbox', 0, 1);

    if (threads.length === 0)
    {
      logInfo('No emails found in inbox');
      return;
    }

    const message = threads[0].getMessages()[0];
    testSpamDetection(message.getSubject());
  }
  catch (error)
  {
    logError('Test on recent email failed: ' + error.toString());
    throw error;
  }
}
