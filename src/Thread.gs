/**
 * Thread.gs — Per-thread and per-message processing, and the inbox search query.
 *
 * processThread() is the bridge between a run (Inbox.gs) and a verdict
 * (Verdict.gs): it walks the messages, calls analyzeMessage(), and hands the
 * spam ones to Disposition.gs.
 *
 * isBulkEmail() sits here rather than in Signals.gs for historical reasons —
 * it is a detection helper, called only by Signal 1a.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

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
        threadUnevaluated = 'size';
        continue;
      }

      processedCount++;
      const verdict = analyzeMessage(message);

      // 'size' is permanent and must not be retried forever; 'error' may be
      // transient. Never let an 'error' downgrade a 'size' already recorded.
      if (verdict.unevaluated && threadUnevaluated !== 'size')
      {
        threadUnevaluated = verdict.unevaluated;
      }

      logDebug('Email: "' + sanitizeForLog(message.getSubject()) + '" - Spam: ' + verdict.isSpam);
      if (!verdict.isSpam) observeShadow(message, verdict);   // log-only; cannot change the outcome

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
           verdict.signals.callbackPhishing || verdict.signals.calendarLure)
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
  // un-archives it to look) will not be re-detected on every run.
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

/**
 * Log-only observer (v6.91.0): records, never decides. For mail judged NOT spam it
 * writes ONE logInfo line ("SHADOW ...") when the mail looks like the finance-ad family:
 *   themes=N        >= 3 of SHADOW_THEME_PATTERNS fire
 *   postal=...      a footer address in SHADOW_POSTAL_NEEDLES
 *   unsolicited     bulk + 2 weak points + no relationship with the sender's domain
 *                   (nothing sent to it, no mail from it older than 2 days)
 * so a few weeks of the Executions log show what a theme rule or an engagement rule
 * would have done to REAL mail before either is allowed to act. It reads the same
 * message the verdict already read, writes nothing but a log line (and a cached
 * history answer in Script Properties), and swallows its own errors: it cannot change
 * a verdict, a label or a delete. The history lookup is the only API cost: at most
 * SHADOW_HISTORY_BUDGET searches' worth of new domains per execution, each cached
 * 30 days per domain.
 */
const SHADOW_HISTORY_BUDGET = 3;
let shadowHistoryLookups = 0;

function senderHasHistory(domain)
{
  const props = PropertiesService.getScriptProperties();
  const key   = 'SHADOW_HIST_' + domain;
  const now   = Date.now();
  const cached = props.getProperty(key);
  if (cached)
  {
    const parts = cached.split(':');
    if (now - Number(parts[1]) < 30 * 24 * 3600 * 1000) return parts[0] === 'Y';
  }
  if (shadowHistoryLookups >= SHADOW_HISTORY_BUDGET) return null;   // unknown this run
  shadowHistoryLookups++;
  const known = GmailApp.search('in:sent to:' + domain, 0, 1).length > 0 ||
                GmailApp.search('from:' + domain + ' older_than:2d -in:spam -in:trash', 0, 1).length > 0;
  props.setProperty(key, (known ? 'Y' : 'N') + ':' + now);
  return known;
}

function observeShadow(message, verdict)
{
  try
  {
    const signals = verdict && verdict.signals;
    if (!signals) return;                                     // whitelisted or unevaluated
    const tags = [];
    const subject = message.getSubject() || '';
    const body    = (message.getPlainBody() || '').substring(0, LIMITS.maxRawScanChars);
    // normalizeAdText() plus what it misses: combining marks, variation selectors,
    // the grapheme joiner, the Hangul filler and tag characters, each of which broke
    // "executive order" in the reformed-spammer review.
    // NFD first: normalizeAdText()'s NFKC FUSES "r" + U+0301 into one letter, which a
    // strip afterwards cannot undo (found by fault-injecting this very test).
    const text = normalizeAdText(subject + ' ' + body).normalize('NFD')
      .replace(/[\u0300-\u036f\u3164\ufe00-\ufe0f]|\udb40[\udc00-\udc7f]/g, '')
      .replace(/ +/g, ' ');

    let themes = 0;
    const names = Object.keys(SHADOW_THEME_PATTERNS);
    for (let i = 0; i < names.length; i++)
    {
      if (SHADOW_THEME_PATTERNS[names[i]].test(text)) themes++;
    }
    if (themes >= 3) tags.push('themes=' + themes);

    const flat = ' ' + text.replace(/[^a-z0-9 ]/g, ' ').replace(/ +/g, ' ') + ' ';
    for (let i = 0; i < SHADOW_POSTAL_NEEDLES.length; i++)
    {
      if (flat.indexOf(' ' + SHADOW_POSTAL_NEEDLES[i] + ' ') !== -1) { tags.push('postal=' + SHADOW_POSTAL_NEEDLES[i].split(' ').slice(-1)[0]); break; }
    }

    const weak = (signals.clickbaitCount > 0 ? 1 : 0) + (signals.fearMongering ? 1 : 0) +
                 (signals.marketingFormat ? 1 : 0) + (signals.suspiciousFromName ? 1 : 0) +
                 (signals.headlineFromName ? 1 : 0);
    const addr = extractEmailAddress(message.getFrom() || '');
    const domain = addr.substring(addr.lastIndexOf('@') + 1).toLowerCase();
    if (signals.bulkEmailService && weak >= 2 && domain.indexOf('.') > 0 &&
        senderHasHistory(domain) === false)
    {
      tags.push('unsolicited');
    }

    if (tags.length > 0)
    {
      logInfo('SHADOW ' + tags.join(' ') + ' from=' + sanitizeForLog(domain) +
              ' subject=' + sanitizeForLog(subject));
    }
  }
  catch (shadowError)
  {
    logDebug('observeShadow skipped: ' + shadowError.toString());
  }
}
