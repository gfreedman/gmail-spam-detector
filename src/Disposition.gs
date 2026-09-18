/**
 * Disposition.gs — What happens to a message once it is judged spam.
 *
 * The irreversible path. disposeDetectedMessage() routes on the rule name:
 * DESTRUCTIVE_RULES are permanently deleted, everything else is quarantined.
 * That allowlist is deliberately an allowlist, so a NEW rule defaults to the
 * recoverable branch.
 *
 * Nothing here deletes without an archive: accumulateLogEntry() must report a
 * successful Drive write first.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

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
