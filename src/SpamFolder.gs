/**
 * SpamFolder.gs — Gmail's OWN spam verdicts: re-judging them, and publishing the folder.
 *
 * This is mail Gmail intercepted before the inbox, so our rules never saw it.
 * reviewGmailSpam() deletes only what an independent signal corroborates, then
 * ages the rest out after CONFIG.gmailSpamGraceDays. writeSpamFolderSnapshot()
 * publishes the folder to a Sheet tab, because the Gmail API hides SPAM from
 * search and this script is the only thing that can see it.
 *
 * Distinct from Cleanup.gs, which sweeps mail THIS detector condemned.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

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
            recordSpamFolderVerdict(message, null, 'KEEP_WHITELISTED');
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
            recordSpamFolderVerdict(message, signals, 'AWAITING_GRACE');
            markReviewed(thread);
            waiting++;
            continue;
          }

          const logType = makeVerdict(signals)
            ? 'GMAIL_SPAM_CONFIRMED'
            : 'GMAIL_SPAM_CORROBORATED';

          recordSpamFolderVerdict(message, signals, 'DELETE_' + logType);

          if (accumulateLogEntry(message, signals, logType) !== true)
          {
            recordSpamFolderVerdict(message, signals, 'BLOCKED_NO_ARCHIVE');
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
 * Record what reviewGmailSpam() decided about one Spam-folder message.
 *
 * Called from the Phase 1 loop, which has already paid for collectSignals().
 * Stashing the answer costs nothing; recomputing it inside the snapshot would
 * cost a second getRawContent() per message.
 *
 * @param {GmailMessage} message
 * @param {Object|null} signals - From collectSignals(); null means whitelisted.
 * @param {string} verdict
 */
function recordSpamFolderVerdict(message, signals, verdict)
{
  try
  {
    _spamFolderVerdicts[message.getId()] = {
      verdict: verdict,
      signals: describeSignals(signals)
    };
  }
  catch (e)
  {
    // An annotation on a diagnostic tab is never worth failing a deletion
    // decision over.
    logError('Could not record spam-folder verdict (non-fatal): ' + e.toString());
  }
}

/**
 * Render the signals that fired as a short human-readable list.
 *
 * @param {Object|null} signals
 * @return {string}
 */
function describeSignals(signals)
{
  if (!signals) return 'whitelisted (not evaluated)';

  const fired = [];
  if (signals.blacklistedSender)          fired.push('blacklisted');
  if (signals.clickbaitCount > 0)         fired.push('clickbait x' + signals.clickbaitCount);
  if (signals.fearMongering)              fired.push('fear');
  if (signals.marketingFormat)            fired.push('marketing-format');
  if (signals.suspiciousFromName)         fired.push('from-name');
  if (signals.emptySubjectWithAttachment) fired.push('empty-subject+attachment');
  if (signals.serviceImpersonation)       fired.push('service-impersonation');
  if (signals.brandMismatchedCta)         fired.push('brand-cta');
  if (signals.freeMailRandomLocal)        fired.push('freemail-random');
  if (signals.callbackPhishing)           fired.push('callback-phishing');

  // Parenthesised and last, deliberately. Bulk routing corroborates nothing on
  // its own — hasCorroboratingSignal() excludes it because virtually every
  // newsletter the user actually wants is bulk-routed — so it must not read as
  // a reason the message is going to be deleted.
  if (signals.bulkEmailService)           fired.push('(bulk)');
  if (signals._degraded)                  fired.push('[DEGRADED: a signal threw]');

  return fired.length > 0 ? fired.join(', ') : 'none';
}

/**
 * Publish the current contents of Gmail's Spam folder to the "Spam Folder" tab.
 *
 * WHY THIS EXISTS. The Spam folder is the one place this detector acts that
 * nothing outside Apps Script can see. The Sheet records what the detector DID
 * — deleted, quarantined — so a message sitting in Spam awaiting its grace
 * period appears nowhere at all, and the only honest answer to "what will the
 * script do with that message?" was to open Gmail by hand. Worse, API clients
 * (the Gmail REST connector included) exclude SPAM from search by default, so
 * the folder is not reachable from outside even with a token. This script is
 * the only thing that can already see it, so it is the thing that must publish
 * it.
 *
 * A GAUGE, NOT A LOG — the same shape as the Health tab. The tab is cleared and
 * rewritten on every maintenance cycle because it answers "what is in the
 * folder right now", and an append-only version would grow one duplicate block
 * per cycle for mail that has not changed. History of what was actually deleted
 * already lives in the Raw Log, which is where a permanent record belongs.
 *
 * COST: two GmailApp.search() calls and one batched getMessagesForThreads().
 * Everything read per message — getFrom, getSubject, getDate, getId — comes
 * with thread metadata. Nothing here calls getRawContent(), and nothing here
 * calls collectSignals(): verdicts come from _spamFolderVerdicts, which Phase 1
 * populated for free. The "reviewed?" column is derived from a second search
 * rather than thread.getLabels() for the same reason — one bounded query beats
 * N per-thread label fetches.
 *
 * Never throws. A diagnostic tab must not be able to break the run it reports on.
 */
function writeSpamFolderSnapshot()
{
  // Bounded for the same reason REVIEW_LIMIT is: a folder with thousands of
  // threads must not turn a diagnostic into a quota incident. The tab says so
  // explicitly when it truncates, so a partial view can never be mistaken for
  // an empty folder.
  const SNAPSHOT_LIMIT = 100;

  try
  {
    const sheetId = PropertiesService.getScriptProperties()
                      .getProperty('SPAM_LOG_SHEET_ID');
    if (!sheetId) return;   // no spreadsheet configured

    const threads = GmailApp.search('in:spam', 0, SNAPSHOT_LIMIT);

    // Threads Gmail has flagged that this detector has NOT yet judged. Used to
    // fill the Reviewed column without a per-thread label fetch.
    const unreviewed = {};
    try
    {
      const pending = GmailApp.search(
        'in:spam -label:' + CONFIG.processedLabel, 0, SNAPSHOT_LIMIT);
      for (let p = 0; p < pending.length; p++)
      {
        unreviewed[pending[p].getId()] = true;
      }
    }
    catch (e)
    {
      // Degrade to "unknown" rather than losing the whole snapshot.
      logError('Could not determine reviewed set (non-fatal): ' + e.toString());
    }

    const header = [
      'SnapshotAt', 'ReceivedAt', 'AgeDays', 'DeleteDueAt', 'Verdict',
      'SignalsFired', 'FromAddress', 'FromName', 'Subject',
      'Whitelisted', 'Reviewed', 'MessageId', 'ThreadId'
    ];

    const now     = new Date();
    const nowIso  = now.toISOString();
    const rows    = [];
    const graceMs = CONFIG.gmailSpamGraceDays * 24 * 60 * 60 * 1000;

    const messagesByThread = threads.length > 0
      ? GmailApp.getMessagesForThreads(threads)
      : [];

    for (let i = 0; i < threads.length; i++)
    {
      try
      {
        const messages = messagesByThread[i];
        if (!messages || messages.length === 0) continue;

        const message  = messages[0];
        const thread   = threads[i];
        const from     = message.getFrom() || '';
        const received = message.getDate();
        const ageMs    = now.getTime() - received.getTime();
        const ageDays  = Math.floor(ageMs / (24 * 60 * 60 * 1000));
        const whitelisted = isWhitelistedSender(message);
        const reviewed    = !unreviewed[thread.getId()];
        const recorded    = _spamFolderVerdicts[message.getId()];

        // Verdict, in priority order:
        //   1. What Phase 1 actually decided this run, when it looked at this
        //      message. Always the most accurate answer.
        //   2. Whitelisted — never deleted by any phase, at any age.
        //   3. Past the grace period — phase 2 takes it on the next cycle
        //      regardless of signals.
        //   4. Judged on an earlier run and left: waiting out the grace period.
        //   5. Not yet judged.
        let verdict, signalText;
        if (recorded)
        {
          verdict    = recorded.verdict;
          signalText = recorded.signals;
        }
        else
        {
          signalText = 'not evaluated this run';
          verdict = whitelisted        ? 'KEEP_WHITELISTED'
                  : ageMs >= graceMs   ? 'DELETE_AGED'
                  : reviewed           ? 'AWAITING_GRACE'
                  : 'PENDING_REVIEW';
        }

        // Blank rather than a date for mail that is never deleted — a due date
        // on a whitelisted keep would be actively misleading.
        const dueAt = whitelisted
          ? ''
          : new Date(received.getTime() + graceMs).toISOString();

        rows.push([
          nowIso,
          received.toISOString(),
          ageDays,
          dueAt,
          verdict,
          escapeSheetCell(signalText),
          escapeSheetCell(extractEmailAddress(from)),
          escapeSheetCell(from.replace(/<[^>]*>/g, '').trim()),
          escapeSheetCell(message.getSubject() || '(no subject)'),
          whitelisted ? 'YES' : 'no',
          reviewed    ? 'YES' : 'no',
          message.getId(),
          thread.getId()
        ]);
      }
      catch (rowError)
      {
        logError('Spam snapshot row failed (skipped): ' + rowError.toString());
      }
    }

    const ss = SpreadsheetApp.openById(sheetId);
    let sheet = ss.getSheetByName('Spam Folder');
    if (!sheet)
    {
      sheet = ss.insertSheet('Spam Folder');
      sheet.setFrozenRows(1);
    }

    // Cleared before every write. Without this a shrinking folder would leave
    // the previous run's surplus rows behind, and stale rows on a tab whose
    // whole purpose is "right now" are worse than no tab.
    sheet.clearContents();

    // Header and data written together, for the reason writeHealthRow()
    // documents: a tab created under an older schema must self-heal rather than
    // silently keep unlabelled columns.
    const values = [header].concat(rows);
    sheet.getRange(1, 1, values.length, header.length).setValues(values);

    if (threads.length >= SNAPSHOT_LIMIT)
    {
      sheet.getRange(values.length + 1, 1).setValue(
        'TRUNCATED at ' + SNAPSHOT_LIMIT + ' threads — the folder holds more.');
    }

    logInfo('Spam folder snapshot: ' + rows.length + ' thread(s) published');
  }
  catch (e)
  {
    logError('writeSpamFolderSnapshot failed (non-fatal): ' + e.toString());
  }
}
