/**
 * Flush.gs — Buffered log flush, and the rule-name cascade.
 *
 * getRuleFromSignals() is here for historical reasons and is easy to miss: it is
 * a SECOND implementation of makeVerdict()'s nine rules, returning the rule NAME
 * rather than a boolean — and it is what disposeDetectedMessage() reads to
 * decide whether a message is destroyed or quarantined.
 *
 * Rule order is the contract between the two. An exhaustive 5,120-combination
 * test in tests/test_disposition.js now enforces it; before that it was a
 * comment.
 *
 * flushSpamLog() drains the buffered Sheets rows at end of run.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

/**
 * Write all pending log entries to Drive (EML files) and Sheets (rows).
 *
 * Called once at the end of processInbox(), after all deletions are complete.
 * Batches all Sheets rows into a single setValues() call. Drive writes are
 * sequential (one file per entry) since Drive has no batch creation API.
 *
 * Non-blocking: errors are caught and logged; spam detection is unaffected.
 * The finally block always clears _pendingLogEntries to prevent memory growth.
 *
 * @return {void} Errors are logged, never thrown: a failed flush must not
 *   abort the run, and the Drive copies were already written synchronously by
 *   accumulateLogEntry().
 */
function flushSpamLog()
{
  if (_pendingLogEntries.length === 0) return;

  try
  {
    const props        = PropertiesService.getScriptProperties();
    const rootFolderId = props.getProperty('SPAM_LOG_FOLDER_ID');
    const sheetId      = props.getProperty('SPAM_LOG_SHEET_ID');

    if (!rootFolderId || !sheetId)
    {
      logInfo('Spam logging not configured — run setupLogging() to enable it');
      return;
    }

    let rootFolder;
    try { rootFolder = DriveApp.getFolderById(rootFolderId); }
    catch (e)
    {
      logError('Spam log Drive folder not found: ' + e.toString());
      return;
    }

    let sheet;
    try
    {
      const ss = SpreadsheetApp.openById(sheetId);
      sheet = ss.getSheetByName('Raw Log');
      if (!sheet) throw new Error('"Raw Log" tab not found in spreadsheet');
    }
    catch (e)
    {
      logError('Spam log spreadsheet unavailable: ' + e.toString());
      return;
    }

    const detectedFolder = getOrCreateLogSubfolder(rootFolder, ['Detected']);
    let   fnFolder       = null; // Created on demand — only when a false negative is present

    const rows = [];

    for (let i = 0; i < _pendingLogEntries.length; i++)
    {
      const entry = _pendingLogEntries[i];

      // The EML was already written by archiveRawEml() BEFORE disposal, so
      // this loop only builds the Sheets row.
      const driveUrl = entry.driveUrl || '';

      // Columns F-H and J carry attacker-controlled text; see escapeSheetCell().
      // driveUrl is constructed by this code, not the attacker, and must stay a
      // live =HYPERLINK formula.
      rows.push([
        entry.detectedAt,
        entry.logType,
        entry.messageId,
        entry.threadId,
        driveUrl,
        escapeSheetCell(entry.subject),
        escapeSheetCell(entry.fromDisplayName),
        escapeSheetCell(entry.fromAddress),
        entry.sendingDomain,
        entry.replyTo,
        entry.ruleInfo.rule,
        entry.ruleInfo.description,
        entry.clickbaitCount,
        entry.signalsCsv,
        entry.bulkEmailService,
        entry.hasAttachment,
        entry.listUnsubscribePresent,
        '', // False Negative Notes (filled in manually by user)
        ''  // Notes (general free-form)
      ]);
    }

    // Single Sheets write for all rows — more efficient than one appendRow() per entry
    if (rows.length > 0)
    {
      sheet.getRange(sheet.getLastRow() + 1, 1, rows.length, rows[0].length).setValues(rows);
      logInfo('Logged ' + rows.length + ' spam intelligence ' +
              (rows.length === 1 ? 'entry' : 'entries'));
    }
  }
  catch (error)
  {
    logError('flushSpamLog failed: ' + error.toString());
  }
  finally
  {
    _pendingLogEntries = []; // Always clear — prevents memory growth between runs
  }
}

/**
 * Get or create a chain of nested subfolders under a Drive parent folder.
 *
 * Given rootFolder and ['Detected'], returns the "Detected" subfolder,
 * creating it if missing. Supports deeper paths too: ['a', 'b', 'c'].
 *
 * @param {DriveFolder}   rootFolder   - Starting parent folder.
 * @param {Array<string>} pathSegments - Folder names to traverse/create in order.
 * @return {DriveFolder} The deepest folder at the end of the path.
 */
function getOrCreateLogSubfolder(rootFolder, pathSegments)
{
  let current = rootFolder;
  for (let i = 0; i < pathSegments.length; i++)
  {
    const name     = pathSegments[i];
    const existing = current.getFoldersByName(name);
    current        = existing.hasNext() ? existing.next() : current.createFolder(name);
  }
  return current;
}

/**
 * Derive which detection rule fired from a signals object.
 *
 * Mirrors the rule cascade in makeVerdict() exactly — must be kept in sync
 * if makeVerdict() rules change. Returns rule 'NONE' for false negatives or
 * any signals object where no rule matched.
 *
 * @param {Object|null} signals - Signal object from collectSignals(), or null.
 * @return {{rule: string, description: string}}
 */
function getRuleFromSignals(signals)
{
  if (!signals)
  {
    // NOT "false negative". null means no signals were collected at all, and
    // every live caller that passes null is a DELIBERATE disposition, not a
    // miss: GMAIL_SPAM_EXPIRED (aged out on Gmail's verdict) and
    // SPAM_MISSED_REFUSED_WHITELISTED (a refusal). Labelling those "false
    // negative" in the Sheet asserted the detector had failed on mail it had
    // judged correctly on purpose — which is exactly how a whitelisted
    // LinkedIn keep came to be filed as a detection failure. An actual false
    // negative carries real signals, because it is re-scored before logging.
    return { rule: 'NONE', description: 'Not rule-based — see log type' };
  }

  if (signals.bulkEmailService && signals.blacklistedSender)
  {
    return { rule: 'Rule 1', description: 'Bulk email + blacklisted sender' };
  }

  if (signals.bulkEmailService && signals.clickbaitCount >= 2)
  {
    return { rule: 'Rule 2', description: 'Bulk email + clickbait (' + signals.clickbaitCount + ' patterns)' };
  }

  let spamBehaviorCount = 0;
  if (signals.clickbaitCount >= 1)       spamBehaviorCount++;
  if (signals.fearMongering)             spamBehaviorCount++;
  if (signals.marketingFormat)           spamBehaviorCount++;
  if (signals.suspiciousFromName)        spamBehaviorCount++;

  if (signals.bulkEmailService && spamBehaviorCount >= 2)
  {
    return { rule: 'Rule 3', description: 'Bulk email + ' + spamBehaviorCount + ' spam behaviors' };
  }

  if (signals.clickbaitCount >= 3)
  {
    return { rule: 'Rule 4', description: 'Extreme clickbait (' + signals.clickbaitCount + ' patterns)' };
  }

  if (signals.emptySubjectWithAttachment)
  {
    return { rule: 'Rule 5', description: 'Empty subject with attachment (payload delivery scam)' };
  }

  if (signals.serviceImpersonation)
  {
    return { rule: 'Rule 6', description: 'Service impersonation phishing (cloud service subject from non-service sender)' };
  }

  // Must stay in the SAME position as in makeVerdict(). Rule order is the
  // contract — a branch in the wrong slot reports the wrong rule for any
  // message that trips two signals.
  if (signals.brandMismatchedCta)
  {
    return { rule: 'Rule 7', description: 'Brand-mismatched CTA phishing (link text names a document brand the destination does not control)' };
  }

  if (signals.freeMailRandomLocal && spamBehaviorCount >= 2)
  {
    return { rule: 'Rule 8', description: 'Free-mail machine-generated sender + ' + spamBehaviorCount + ' spam behaviors' };
  }

  if (signals.callbackPhishing)
  {
    return { rule: 'Rule 9', description: 'Callback phishing (free-mail sender invoicing as a brand it does not control, payload is a phone number)' };
  }

  return { rule: 'NONE', description: 'No rule triggered' };
}

/**
 * Format a signals object as a comma-separated list of active signal names.
 * Used for the "Signals Detected" column in the Sheets log.
 *
 * @param {Object|null} signals - Signal object from collectSignals(), or null.
 * @return {string} CSV string, e.g. "BULK,BLACKLISTED,CLICKBAIT(3),FEAR", or "".
 */
function buildSignalsCsv(signals)
{
  if (!signals) return '';

  const parts = [];
  if (signals.bulkEmailService)           parts.push('BULK');
  if (signals.blacklistedSender)          parts.push('BLACKLISTED');
  if (signals.clickbaitCount > 0)         parts.push('CLICKBAIT(' + signals.clickbaitCount + ')');
  if (signals.fearMongering)              parts.push('FEAR');
  if (signals.marketingFormat)            parts.push('MARKETING');
  if (signals.suspiciousFromName)         parts.push('SUSPICIOUS_FROM');
  if (signals.emptySubjectWithAttachment) parts.push('EMPTY_SUBJECT_ATTACHMENT');
  if (signals.serviceImpersonation)       parts.push('SERVICE_IMPERSONATION');
  if (signals.brandMismatchedCta)         parts.push('BRAND_MISMATCH_CTA');
  if (signals.freeMailRandomLocal)        parts.push('FREEMAIL_RANDOM_LOCAL');
  if (signals.callbackPhishing)           parts.push('CALLBACK_PHISHING');
  // Surfaced in the Sheet so a degraded verdict is visible in the log, not
  // just in an execution transcript nobody reads.
  if (signals._degraded)                  parts.push('DEGRADED');

  return parts.join(',');
}
