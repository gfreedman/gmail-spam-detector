
/**
 * One-time setup for spam intelligence logging.
 *
 * Creates:
 *   - "Spam Intelligence/" folder at My Drive root
 *   - "Detected/" and "False Negatives/" subfolders inside it
 *   - "Spam Intelligence Log" spreadsheet with a "Raw Log" tab and column headers
 *   - "SpamMissed" Gmail label for flagging false negatives
 *
 * Saves the folder ID and spreadsheet ID to Script Properties so
 * flushSpamLog() can find them on every subsequent run. Run once manually
 * from the Apps Script editor after deploying this feature — the time-based
 * trigger will not prompt for the new OAuth scopes until this is called.
 *
 * @throws {Error} If Drive or Sheets creation fails.
 */
function setupLogging()
{
  try
  {
    logInfo('Setting up spam intelligence logging...');

    const props = PropertiesService.getScriptProperties();

    // ── Drive folder ─────────────────────────────────────────────────────────
    let rootFolder;
    const existingFolderId = props.getProperty('SPAM_LOG_FOLDER_ID');
    if (existingFolderId)
    {
      try { rootFolder = DriveApp.getFolderById(existingFolderId); }
      catch (e) { rootFolder = null; }
    }

    if (!rootFolder)
    {
      rootFolder = DriveApp.createFolder('Spam Intelligence');
      props.setProperty('SPAM_LOG_FOLDER_ID', rootFolder.getId());
      logInfo('Created "Spam Intelligence" folder in My Drive');
    }
    else
    {
      logInfo('Using existing "Spam Intelligence" folder');
    }

    getOrCreateLogSubfolder(rootFolder, ['Detected']);
    getOrCreateLogSubfolder(rootFolder, ['False Negatives']);

    // ── Spreadsheet ──────────────────────────────────────────────────────────
    let spreadsheet;
    const existingSheetId = props.getProperty('SPAM_LOG_SHEET_ID');
    if (existingSheetId)
    {
      try { spreadsheet = SpreadsheetApp.openById(existingSheetId); }
      catch (e) { spreadsheet = null; }
    }

    if (!spreadsheet)
    {
      spreadsheet = SpreadsheetApp.create('Spam Intelligence Log');
      props.setProperty('SPAM_LOG_SHEET_ID', spreadsheet.getId());

      const sheet = spreadsheet.getActiveSheet();
      sheet.setName('Raw Log');
      sheet.appendRow([
        'Detected At', 'Log Type', 'Gmail Message ID', 'Gmail Thread ID',
        'EML Drive URL', 'Subject', 'From Display Name', 'From Address',
        'Sending Domain', 'Reply-To', 'Rule Triggered', 'Rule Description',
        'Clickbait Count', 'Signals Detected', 'Bulk Email Service',
        'Has Attachment', 'List-Unsubscribe Present', 'False Negative Notes', 'Notes'
      ]);
      sheet.setFrozenRows(1);
      logInfo('Created "Spam Intelligence Log" spreadsheet');
    }
    else
    {
      logInfo('Using existing "Spam Intelligence Log" spreadsheet');
    }

    // ── SpamMissed label ─────────────────────────────────────────────────────
    getOrCreateLabel(SPAM_MISSED_LABEL);

    logInfo('Setup complete!');
    logInfo('Spreadsheet: ' + SpreadsheetApp.openById(props.getProperty('SPAM_LOG_SHEET_ID')).getUrl());
    logInfo('Drive folder: https://drive.google.com/drive/folders/' + rootFolder.getId());
    logInfo('Apply the "SpamMissed" label in Gmail to any spam the script misses.');
  }
  catch (error)
  {
    logError('setupLogging failed: ' + error.toString());
    throw error;
  }
}

/**
 * Run housekeeping tasks at most once every 5 minutes.
 *
 * Most invocations find no new emails, so running checkFalseNegatives(),
 * recheckRecentSpamChecked() and destroySpam() every time would spend quota
 * re-examining mail that has not changed. This guard bounds that, and gates
 * the expensive recheck separately (see below).
 *
 * The interval was sized when the trigger ran every minute. The live trigger
 * now runs every 10 minutes, so this guard rarely binds — it is kept because
 * the trigger interval is a setting in the Apps Script UI, not a property of
 * this code, and it can change back without anything here noticing.
 *
 * Uses Script Properties to persist the last-run timestamp across executions.
 */
function runPeriodicMaintenance()
{
  // 5 minutes, down from 15. Chosen against Gmail's read quota rather than by
  // feel: recheckRecentSpamChecked() runs analyzeMessage() on up to 20 recent
  // inbox threads, and each non-whitelisted message costs a getRawContent()
  // fetch. At ~7 inbox threads that is ~7 reads per cycle:
  //     every  1 min -> ~10 000 reads/day  (about half the consumer daily quota)
  //     every  5 min ->  ~2 000 reads/day  (comfortable)
  //     every 10 min ->  ~1 000 reads/day  (the live trigger interval)
  // Quota exhaustion stops detection altogether — the opposite of catching
  // spam fast — so the ceiling matters more than the cadence.
  //
  // Speed where it actually matters does not depend on this number:
  //   - NEW mail is scanned by processInbox()'s main loop on every run.
  //   - A fix deploy re-checks recent mail IMMEDIATELY via the
  //     SCRIPT_VERSION change check below, not on this timer.
  // This interval only governs routine re-checks between deploys.
  const MAINTENANCE_INTERVAL_MS = 5 * 60 * 1000;
  const RECHECK_INTERVAL_MS     = 30 * 60 * 1000;
  const props  = PropertiesService.getScriptProperties();
  const lastTs = parseInt(props.getProperty('LAST_MAINTENANCE_TS') || '0', 10);

  // Force an immediate cycle when a new version has been deployed.
  //
  // A fix deploy exists precisely to catch something the previous code missed,
  // so making it wait up to 15 minutes to re-evaluate defeats the point.
  // Before v6.40.0, recheckRecentSpamChecked() ran on EVERY invocation, so a
  // deploy re-caught its target on the very next run.
  // v6.40.0 moved maintenance behind the 15-minute gate for performance and
  // silently made post-deploy recatch up to 15x slower — a regression in the
  // v6.36.0 guarantee that a fix deploy cleans up after itself unattended.
  //
  // Comparing SCRIPT_VERSION against the last value seen restores that
  // guarantee without giving up the performance win: the forced run happens
  // once per deploy, not once per minute. It also covers deploys made outside
  // CI (a manual clasp push, or an edit in the Apps Script editor), which a
  // CI-side "run this function after deploying" step would miss.
  const seenVersion    = props.getProperty('LAST_SEEN_VERSION');
  const versionChanged = seenVersion !== SCRIPT_VERSION;

  if (!versionChanged && Date.now() - lastTs < MAINTENANCE_INTERVAL_MS) return;

  if (versionChanged)
  {
    logInfo('New version deployed (' + (seenVersion || 'none') + ' -> ' +
            SCRIPT_VERSION + ') — forcing immediate maintenance cycle');
    // Recorded BEFORE running the cycle, deliberately. If one of the
    // maintenance functions throws, the next trigger must fall back
    // to the normal maintenance gate rather than force a fresh cycle every
    // minute and burn Gmail API quota.
    props.setProperty('LAST_SEEN_VERSION', SCRIPT_VERSION);
  }

  logInfo('Running periodic maintenance');

  // Cheap, and genuinely time-sensitive: one search each.
  checkFalseNegatives();
  destroySpam();

  // Re-judge Gmail's own spam verdicts and delete only what we agree about.
  // Runs after destroySpam() so our own failed deletes are retried first and
  // do not show up here as unreviewed.
  // versionChanged forces a full re-review, so a detection improvement is
  // applied to spam the previous logic already looked at and dismissed.
  reviewGmailSpam(versionChanged);

  // Publish the folder AFTER the review, so the tab reflects the deletions this
  // run just made rather than the state that preceded them. Costs two searches
  // and no getRawContent(); see the function header.
  writeSpamFolderSnapshot();

  // Expensive, and NOT time-sensitive. recheckRecentSpamChecked() re-evaluates
  // recent mail against the CURRENT patterns, so between deploys it keeps
  // computing the same answer at ~2 reads per message. Its real trigger is a
  // pattern change, which means a deploy.
  //
  // Run it when the version changed (immediately after a fix lands, which is
  // the case that matters), or on a slow timer so that a domain added at
  // runtime via addToBlacklist() — which changes behaviour without a deploy —
  // is still picked up within the hour.
  const lastRecheck = parseInt(props.getProperty('LAST_RECHECK_TS') || '0', 10);
  if (versionChanged || Date.now() - lastRecheck >= RECHECK_INTERVAL_MS)
  {
    recheckRecentSpamChecked();
    props.setProperty('LAST_RECHECK_TS', String(Date.now()));
  }

  props.setProperty('LAST_MAINTENANCE_TS', String(Date.now()));
}

/**
 * Scan for emails labeled "SpamMissed" by the user, log them, then delete them.
 *
 * The user labels an escaped spam email "SpamMissed" in Gmail. On the next run,
 * this function finds it, accumulates a log entry (Log Type = FALSE_NEGATIVE),
 * removes the label, then calls markAsSpam() to report and permanently delete
 * the email — identical path to auto-detected spam.
 *
 * collectSignals() is run on each false negative so the Sheets row captures WHY
 * the script missed it. The user fills in "False Negative Notes" manually later.
 */
function checkFalseNegatives()
{
  try
  {
    const threads = GmailApp.search('label:' + SPAM_MISSED_LABEL, 0, CONFIG.maxEmailsPerRun);
    if (threads.length === 0) return;

    logInfo('Found ' + threads.length + ' false negative(s) to log');

    const label = GmailApp.getUserLabelByName(SPAM_MISSED_LABEL);

    // Batch-fetch messages for all false-negative threads in one API call.
    const allMessages = GmailApp.getMessagesForThreads(threads);

    for (let i = 0; i < threads.length; i++)
    {
      try
      {
        const thread    = threads[i];
        const messages  = allMessages[i];
        if (!messages || messages.length === 0) continue;
        const message   = messages[0];

        // WHITELIST GUARD, checked before anything destructive.
        //
        // This path deletes on an explicit human instruction, and that argument
        // holds for one deliberate click. It does not hold for a mis-click on a
        // multi-select: applying SpamMissed to forty threads is two keystrokes
        // in Gmail, and until now every one of them was permanently deleted
        // with no whitelist check at all.
        //
        // A whitelisted sender is the user's own standing instruction that this
        // mail is wanted. Two instructions conflict, so the safe resolution is
        // the non-destructive one: refuse, say why, and let the user resolve it
        // deliberately — either by deleting in Gmail (one click, recoverable
        // via Trash) or by removing the domain from the whitelist.
        // Checked across EVERY message in the thread, not just messages[0].
        // markAsSpam()'s fallback when the Advanced Gmail Service is missing is
        // thread.moveToSpam(), which moves the whole thread — so a whitelisted
        // sibling in a reply chain would be dragged along. getFrom() is free
        // metadata, so scanning the thread costs nothing.
        const whitelistedInThread = messages.some(function(m) {
          return isWhitelistedSender(m);
        });

        if (whitelistedInThread)
        {
          accumulateLogEntry(message, null, 'SPAM_MISSED_REFUSED_WHITELISTED',
                             { skipArchive: true });
          swapSpamMissedForReview(thread, label,
            'REFUSED: SpamMissed on a WHITELISTED sender: ' +
            sanitizeForLog(message.getSubject()) +
            '. Remove the domain from the whitelist first, or delete it in Gmail ' +
            'directly.');
          continue;
        }

        let signals = null;
        try { signals = collectSignals(message); }
        catch (e) { /* non-fatal — log entry still captured without signals */ }

        // Accumulate BEFORE deletion — getRawContent() is unavailable after batchDelete
        const archived = accumulateLogEntry(message, signals, 'FALSE_NEGATIVE');

        // The archive invariant applies here too: an explicit instruction to
        // delete is not an instruction to delete the only copy.
        //
        // Checked BEFORE the label is removed. Previously the label came off
        // first, so this branch dropped the message silently and the comment
        // claiming it "will retry next run" was false — nothing carried the
        // label any more, so nothing ever retried.
        if (!archived)
        {
          // Swapped, not kept. Keeping the label looked like a free retry, but
          // accumulateLogEntry() above buffers its Sheets row BEFORE this check,
          // so every retry wrote a duplicate row and paid two getRawContent()
          // fetches: measured at 288 rows and 576 reads per day per stuck
          // message, with no convergence. An unreachable Drive is a persistent
          // configuration fault, not a transient one, so retrying forever is
          // strictly worse than stopping and saying so.
          swapSpamMissedForReview(thread, label,
            'REFUSED: cannot archive, so not deleting: ' +
            sanitizeForLog(message.getSubject()) +
            '. Run setupLogging(), then re-apply SpamMissed.');
          continue;
        }

        // Remove label before markAsSpam() — deleted threads can't have labels removed
        if (label) thread.removeLabel(label);

        // Deliberately markAsSpam(), NOT disposeDetectedMessage(): the user
        // asked for destruction and this is not a whitelisted sender.
        markAsSpam(message, thread);

        logInfo('FALSE NEGATIVE LOGGED AND DESTROYED: ' + sanitizeForLog(message.getSubject()));
      }
      catch (threadError)
      {
        logError('Error processing false negative: ' + threadError.toString());
      }
    }
  }
  catch (error)
  {
    logError('checkFalseNegatives failed: ' + error.toString());
  }
}

/**
 * Re-evaluate recently SpamChecked inbox emails against the current patterns.
 *
 * Problem this solves: when a false negative is detected and patterns are
 * improved, emails that were already stamped SpamChecked (processed before the
 * fix deployed) are permanently excluded from the normal scan. They sit in the
 * inbox until the user notices and manually labels them SpamMissed.
 *
 * This function closes that gap automatically. It runs on a new deploy via
 * runPeriodicMaintenance(), re-checking inbox emails carrying SpamChecked from
 * the last RECHECK_DAYS days. Any that now score as spam under updated patterns
 * are logged as FALSE_NEGATIVE, archived out of the inbox, and HELD under
 * CONFIG.reviewLabel.
 *
 * This path does NOT delete, and deliberately does not get the same treatment
 * as a manually labelled SpamMissed email. The difference is consent: a
 * SpamMissed label is the user asking for destruction, whereas this is the
 * script overruling a decision the user already made, using a pattern deployed
 * moments ago. See holdForReview() for the full reasoning.
 *
 * Performance: capped at RECHECK_LIMIT emails per run. Messages are batch-fetched
 * via getMessagesForThreads() (one API call for all threads). analyzeMessage()
 * averages ~2ms per email in GAS, so 20 emails adds ~40ms — negligible vs. budget.
 */
function recheckRecentSpamChecked()
{
  const RECHECK_DAYS  = 2;
  const RECHECK_LIMIT = 20;

  try
  {
    const query   = 'in:inbox label:' + CONFIG.processedLabel +
                    ' -label:' + CONFIG.phishingLabel +
                    ' newer_than:' + RECHECK_DAYS + 'd';
    const threads = GmailApp.search(query, 0, RECHECK_LIMIT);
    if (threads.length === 0) return;

    logDebug('Rechecking ' + threads.length + ' recent SpamChecked inbox email(s)');

    // Batch-fetch messages for all recheck threads in one API call.
    const allMessages = GmailApp.getMessagesForThreads(threads);
    let recaughtCount = 0;

    for (let i = 0; i < threads.length; i++)
    {
      try
      {
        const thread   = threads[i];
        const messages = allMessages[i];
        if (!messages || messages.length === 0) continue;
        const message  = messages[0];

        const verdict = analyzeMessage(message);
        if (!verdict.isSpam) continue;

        logInfo('Auto-recaught false negative: ' + sanitizeForLog(message.getSubject()));

        // Archive the evidence, then HOLD — never delete on this path.
        //
        // Until v6.48.0 this called disposeDetectedMessage(), so a newly
        // deployed pattern permanently deleted up to 20 messages the user had
        // already read and kept, within a minute of the deploy, with nothing
        // between the new regex and the loss but a 22-file ham corpus. It was
        // the highest-blast-radius consequence of a bad pattern in the system
        // and the one most likely to be exercised, because a pattern is added
        // precisely when it is new and unproven.
        accumulateLogEntry(message, verdict.signals, 'FALSE_NEGATIVE');
        holdForReview(message, thread, 'recheck after pattern change');
        recaughtCount++;
      }
      catch (threadError)
      {
        logError('recheckRecentSpamChecked thread error: ' + threadError.toString());
      }
    }

    if (recaughtCount > 0)
    {
      logInfo('Recheck: held ' + recaughtCount + ' newly-matching email(s) from the last ' +
              RECHECK_DAYS + ' days for review under the "' + CONFIG.reviewLabel +
              '" label — none were deleted');
    }
  }
  catch (error)
  {
    logError('recheckRecentSpamChecked failed: ' + error.toString());
  }
}
