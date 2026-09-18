/**
 * Cleanup.gs — Label plumbing and the sweep for mail this detector condemned.
 *
 * destroySpam() is the safety net for markAsSpam()'s immediate delete failing;
 * it is scoped by CONFIG.purgeLabel so it can never touch Gmail's own spam.
 *
 * hasCorroboratingSignal() lives here and is load-bearing: it is the gate on
 * deleteMessagePermanently() for Spam-folder mail, where ONE signal is enough
 * because Gmail has already judged the message.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

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
 * Does this thread already carry the named label?
 *
 * Used as a one-shot retry counter for messages that could not be evaluated:
 * the review label's presence means "we already tried once". A label is used
 * rather than a Script Property because it is per-thread, survives executions,
 * needs no cleanup, and is visible to the user in Gmail.
 *
 * Fails CLOSED (returns true) when the labels cannot be read. A false here
 * grants another retry, and if label reads are broken that could loop every
 * run; claiming "already retried" ends the loop instead.
 *
 * @param {GmailThread} thread
 * @param {string} labelName
 * @return {boolean}
 */
function threadHasLabel(thread, labelName)
{
  try
  {
    const labels = thread.getLabels() || [];
    for (let i = 0; i < labels.length; i++)
    {
      if (labels[i].getName() === labelName) return true;
    }
    return false;
  }
  catch (e)
  {
    logError('Could not read thread labels, assuming already retried: ' +
             e.toString());
    return true;
  }
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
