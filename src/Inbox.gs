/**
 * Inbox.gs — Run entry points: the scheduled pass and the manual bulk pass.
 *
 * processInbox() is what the 10-minute trigger calls — it holds the script lock,
 * the per-run counters, and the audit/heartbeat calls in its finally block.
 * cleanseInbox() is the manual, higher-volume variant run from the editor.
 *
 * Neither decides anything about a message; they drive Thread.gs.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

// =============================================================================
// Core Processing Pipeline
// =============================================================================

/**
 * Main entry point — scan inbox and process unprocessed emails.
 *
 * Should be configured as a time-driven trigger running every 10 minutes.
 * Processes up to CONFIG.maxEmailsPerRun emails per invocation, with
 * per-thread error isolation so one bad email doesn't abort the entire run.
 *
 * Housekeeping (destroySpam, recheckRecentSpamChecked, checkFalseNegatives)
 * runs via runPeriodicMaintenance() on a 5-minute cadence, not every invocation.
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

  // Reset audit state for this run. Inside the lock and after the skip check,
  // so a skipped invocation cannot clear a running one's tally.
  _destroyedMessageIds = [];
  _loggedMessageIds    = [];
  _unresolvedAgedSpam  = 0;
  _spamFolderVerdicts  = {};

  // Declared out here, not in the try, because `finally` reads them to emit the
  // heartbeat even when the run throws.
  let spamCount      = 0;
  let processedCount = 0;
  let errorCount     = 0;
  let auditFindings  = 0;
  let runError       = null;

  try
  {
    // Validate config before doing any work. If something is misconfigured we
    // want a clear error immediately rather than silent misbehavior later on
    // ("fail fast" — crash early with a useful message instead of limping along).
    validateConfig();

    // Single search call — the only API call on the fast path when inbox is clean.
    const threads = GmailApp.search(buildSearchQuery(), 0, CONFIG.maxEmailsPerRun);

    if (threads.length > 0)
    {
      logInfo('Found ' + threads.length + ' threads to process');
      const startTime = Date.now();

      // Deferred label lookup — skipped entirely on empty-inbox runs.
      const label = getOrCreateLabel(CONFIG.processedLabel);

      // Batch-fetch all thread messages in one API call instead of N
      // separate thread.getMessages() calls — the dominant cost when
      // processing multiple threads per run.
      const allMessages = GmailApp.getMessagesForThreads(threads);

      for (let i = 0; i < threads.length; i++)
      {
        try
        {
          const thread = threads[i];
          const result = processThread(thread, allMessages[i]);

          spamCount      += result.spamCount;
          processedCount += result.processedCount;

          // Gate on DESTRUCTION, not on spamCount. addLabel() throws
          // "Not found" on a thread markAsSpam() permanently deleted, which is
          // why this skip exists — but a Rule 7 quarantine also sets
          // spamCount > 0 while leaving the thread alive. Skipping the label
          // there left the thread unprocessed, so it was re-detected on every
          // subsequent run: an unbounded re-quarantine loop that
          // appended a PHISHING_DETECTED row and a Drive EML every cycle
          // (~1440/day) and, via _quarantinedMessageIds, suppressed the spam
          // sweep indefinitely.
          if (!result.destroyed)
          {
            // An unevaluated message is flagged for review either way, so it is
            // never silently indistinguishable from mail that passed every
            // rule. What differs is whether it is ALSO marked processed —
            // SpamChecked is what removes it from the search query for good.
            if (result.unevaluated)
            {
              const subject = sanitizeForLog(thread.getFirstMessageSubject());

              // Read the label BEFORE adding it: this is the retry counter.
              const alreadyRetried = threadHasLabel(thread, CONFIG.reviewLabel);

              try { thread.addLabel(getOrCreateLabel(CONFIG.reviewLabel)); }
              catch (e) { logError('Could not flag unevaluated thread: ' + e.toString()); }

              // 'size' is a permanent property of the message: it will be too
              // large on every future run, so re-fetching it forever costs
              // quota and changes nothing. Mark it processed.
              //
              // 'error' may be transient — a timeout, a quota blip, one
              // malformed part. Leaving it unmarked means the next run tries
              // again, which is the point: a message that threw was never
              // judged, and stamping it processed is a permanent exemption
              // obtainable by making getRawContent() fail.
              //
              // Bounded to ONE retry by the review label above, so genuinely
              // undecodable mail cannot become an unbounded re-fetch loop —
              // the failure mode that cost 11,500 reads/day in v6.50.1.
              if (result.unevaluated === 'error' && !alreadyRetried)
              {
                logInfo('NOT marking processed, will retry next run: ' + subject);
                continue;
              }

              logInfo('FLAGGED (unevaluated: ' + result.unevaluated +
                      (result.unevaluated === 'error' ? ', retry exhausted' : '') +
                      '): ' + subject);
            }
            thread.addLabel(label);
          }
        }
        catch (threadError)
        {
          errorCount++;
          logError('Error processing thread: ' + threadError.toString());
        }
      }

      const duration = Date.now() - startTime;
      logInfo('Completed in ' + duration + 'ms: Processed ' + processedCount +
              ' emails, marked ' + spamCount + ' as spam, ' + errorCount + ' errors');
    }

    // Flush log entries from email processing (no-op when nothing was detected).
    flushSpamLog();

    // Maintenance runs at most every 5 minutes regardless of per-run
    // email activity — avoids burning quota on housekeeping every invocation.
    // May queue additional log entries (false negatives, rechecked spam).
    runPeriodicMaintenance();

    // Second flush picks up any entries queued by maintenance.
    flushSpamLog();

    // Check that what the run believes it did matches what it recorded.
    // After both flushes, so _loggedMessageIds is complete.
    auditFindings = auditRunIntegrity();
  }
  catch (error)
  {
    // Recorded for the heartbeat in `finally`, so a failed run still reports.
    runError = error.toString();

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
    // The heartbeat MUST be in `finally`, not at the end of the try.
    //
    // Placed in the try (v6.58.0) it only fired when the run succeeded, so a
    // run that threw reported nothing at all — indistinguishable from a trigger
    // that never fired. That is precisely the blind spot the heartbeat exists
    // to close, reintroduced one level down: the failure mode a health signal
    // most needs to report is the one that skips the health signal.
    //
    // `return` inside the catch (the Gmail-quota branch) also jumps straight
    // here, so that path reports too.
    //
    // Runs before releaseLock() so the write happens while this execution still
    // holds the lock, and cannot interleave with the next trigger's row.
    logRunHeartbeat({ processed: processedCount, spam: spamCount,
                      errors: errorCount, auditFindings: auditFindings,
                      runError: runError });

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
  const SUSPECT_LABEL = CONFIG.reviewLabel;

  let deletedCount  = 0;
  let phishingCount = 0;
  let suspectCount  = 0;
  let cleanCount    = 0;
  let errorCount    = 0;

  try
  {
    const checkedLabel = getOrCreateLabel(CONFIG.processedLabel);
    const suspectLabel = getOrCreateLabel(SUSPECT_LABEL);
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
          let threadHandled  = false;

          for (let m = 0; m < messages.length; m++)
          {
            const message = messages[m];

            // Single call to the real pipeline. This function used to re-implement
            // the whitelist check, bulk detection and blacklist check by hand and
            // then call analyzeMessage() two lines later anyway — duplicating even
            // the expensive getRawContent().
            //
            // That duplication was not just waste, it was a live security hole.
            // The hand-rolled copy matched with `fromLower.includes(entry)` against
            // the FULL From string, display name included, so:
            //   "billing@linkedin.com" <evil@evil.ru>    -> whitelisted, skipped
            //   "financebuzz roundup" <legit@company.com> -> blacklisted -> DELETED
            // v6.42.0 fixed both bugs in collectSignals() and this copy was missed,
            // so the delete path here kept the old behaviour for three releases.
            // Deleting the duplicate is the fix; sharing one code path is what stops
            // it recurring.
            const verdict = analyzeMessage(message);
            if (verdict.signals === null) continue;  // whitelisted
            if (!verdict.isSpam) continue;

            const firedRule = getRuleFromSignals(verdict.signals).rule;

            // Rule 1 (bulk + known spam mill) is definitive, so cleanse mode acts
            // on it. Rule 7 routes through the same disposition logic as the live
            // pipeline so a brand-mismatched CTA is quarantined here too, rather
            // than silently downgraded to a SuspectedSpam label.
            if (firedRule === 'Rule 1' || firedRule === 'Rule 7')
            {
              // Archive BEFORE disposing — getRawContent() is unavailable after a
              // batchDelete. cleanse mode previously deleted with no Drive EML and
              // no Sheets row at all, so a misjudged message left no trace.
              const archived = accumulateLogEntry(message, verdict.signals,
                (firedRule === 'Rule 7' || firedRule === 'Rule 9')
                  ? 'PHISHING_DETECTED' : 'SPAM_DETECTED');

              if (disposeDetectedMessage(message, thread, verdict.signals, archived))
              {
                deletedCount++;
                threadDeleted = true;
              }
              else
              {
                phishingCount++;
                threadHandled = true;   // quarantined: archived + Phishing label
              }
              break; // this message is handled; stop scanning the thread
            }

            // Rules 2-6: pattern-based — label for human review, never delete
            threadSuspect = true;
          }

          // Deleted or quarantined: disposition already applied the labels it
          // needs, and addLabel() throws on a destroyed thread.
          if (threadDeleted || threadHandled) continue;

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
            phishingCount + ' quarantined (Phishing label), ' +
            suspectCount + ' flagged (review SuspectedSpam label), ' +
            cleanCount + ' clean, ' + errorCount + ' errors');

    // Flush the archive buffer before the sweep. accumulateLogEntry() only
    // buffers; without this the Drive EMLs and Sheets rows for everything
    // deleted above are discarded.
    flushSpamLog();

    destroySpam();
  }
  catch (error)
  {
    logError('Critical error in cleanseInbox: ' + error.toString());
    throw error;
  }
}
