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
        // quarantineAsPhishing(). Rule 9 quarantines too; every other rule deletes
        // permanently, Rules 13 and 14 included since v6.100.0 (all behind the Drive-archive gate).
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
 * History lookups per execution, shared by every sender-history question Rules 13 and 14 ask
 * (senderHasHistory, senderHasNamedDomainHistory). An exhausted budget makes the gate answer
 * "unknown": the mail is not convicted and is retried next run.
 */
// 6, was 3: since v6.103.0 a Rule 13/14 candidate whose address is new spends a SECOND lookup
// (senderHasNamedDomainHistory), so 3 judged one new sender per run (review of PR #32).
const HISTORY_LOOKUP_BUDGET = 6;
let historyLookups = 0;

/**
 * The labels this script itself puts on mail it judged suspicious (v6.103.0). Mail carrying one
 * is NOT history: the recheck holds READ Rule 13/14 matches under SuspectedSpam, so counting it
 * let one held mill message vouch for every later rotating address under the same name
 * (review of PR #32 reproduced it with the Trend Watchers Lab fixtures).
 * @return {Array<string>}
 */
function historyExcludedLabels()
{
  return [CONFIG.phishingLabel, CONFIG.reviewLabel, CONFIG.purgeLabel, 'SpamMissed'];
}

/** The same list as Gmail query terms: " -label:A -label:B ...". */
function historyLabelExclusions()
{
  return historyExcludedLabels().map(function(l) { return ' -label:' + l; }).join('');
}

/**
 * The Script Properties key that caches one history answer. A DOMAIN keys on itself; a full
 * ADDRESS (Rule 14 asks per address) keys on a short FNV-1a hash, because the local part is
 * attacker-chosen: a mill rotating "<name>.<brand>@esp" would otherwise write a ~75-byte key per
 * new address into a 500 KB store and eventually make every Script Properties write throw.
 * The "SHADOW_HIST_" prefix is historical (the removed v6.91 observer introduced it); kept so
 * the gate's cached answers survive v6.106.0. Only the hashed ADDRESS form is in use now:
 * the plain DOMAIN form was the observer's, and purgeShadowLeftovers() deletes those.
 */
function historyCacheKey(who)
{
  if (who.indexOf('@') === -1) return 'SHADOW_HIST_' + who;
  let h = 0x811c9dc5;
  for (let i = 0; i < who.length; i++) { h ^= who.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
  return 'SHADOW_HIST_A' + h.toString(16);
}

function senderHasHistory(domain)   // `domain` may also be a full address: Gmail's to:/from: take either
{
  const props = PropertiesService.getScriptProperties();
  const key   = historyCacheKey(domain);
  const now   = Date.now();
  const cached = props.getProperty(key);
  if (cached)
  {
    const parts = cached.split(':');
    // An ADDRESS answer (Rule 14's gate) expires in 3 days, a domain answer in 30: a cached "no
    // history" must not outlive the user starting to read that sender while it guards a delete.
    const ttlDays = domain.indexOf('@') !== -1 ? 3 : 30;
    if (now - Number(parts[1]) < ttlDays * 24 * 3600 * 1000) return parts[0] === 'Y';
  }
  if (historyLookups >= HISTORY_LOOKUP_BUDGET) return null;   // unknown this run
  historyLookups++;
  // v6.99.0: the received-mail half now needs `is:read` and excludes the quarantine label.
  // Rule 14 relies on this answer, and without those two terms the mill's OWN earlier mail
  // (left unread in the inbox, or held under the Phishing label) would make the mill a
  // "known sender" after its first miss and switch the rule off for it.
  const known = GmailApp.search('in:sent to:' + domain, 0, 1).length > 0 ||
                GmailApp.search('from:' + domain + ' older_than:2d is:read' + historyLabelExclusions() +
                                ' -in:spam -in:trash', 0, 1).length > 0;
  props.setProperty(key, (known ? 'Y' : 'N') + ':' + now);
  return known;
}

