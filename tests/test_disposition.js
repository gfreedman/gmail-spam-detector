/**
 * Disposition tests — the only automated coverage of the code that
 * IRREVERSIBLY destroys mail.
 *
 * SpamDetector.gs is loaded into a `vm` context with GmailApp / Gmail /
 * PropertiesService / LockService / Utilities / Session stubbed, and every
 * side-effecting call is recorded. Assertions are made on that call log.
 *
 * This exists because two consecutive releases (v6.43.0, v6.44.0) were spent
 * fixing disposition bugs that no test could see: the Python harness cannot
 * exercise Apps Script runtime functions, so quarantine-vs-delete routing had
 * zero coverage. Both the 2026-09-16 incident (a quarantined message
 * permanently deleted) and the re-quarantine loop that followed it are
 * regression-tested below.
 *
 * Run: node tests/test_disposition.js
 */
'use strict';
const fs = require('fs');
const vm = require('vm');
const path = require('path');

const GS_PATH = path.join(__dirname, '..', 'SpamDetector.gs');

let failures = 0;
let passed = 0;
function check(desc, cond, detail) {
  if (cond) { passed++; console.log('  ✅ ' + desc); }
  else { failures++; console.log('  ❌ ' + desc + (detail ? ' — ' + detail : '')); }
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/**
 * Build a vm context with stubbed Apps Script services.
 * `opts.threads` is a list of fake threads returned by GmailApp.search().
 */
function makeCtx(opts) {
  opts = opts || {};
  const calls = [];
  const props = Object.assign({}, opts.props || {});

  const labelObj = name => ({ __label: name, getName: () => name });

  const ctx = {
    console,
    calls,
    props,
    Logger: { log() {} },
    Utilities: {
      sleep() {},
      formatDate: () => '2026/09/15',
      base64Encode: s => 'b64',
      // Required by archiveRawEml(). Without it the archive throws, reports
      // failure, and the archive invariant refuses every delete — which makes
      // unrelated tests fail for the right reason in a confusing way.
      newBlob: (content, type, name) => ({ content, type, name })
    },
    Session: { getScriptTimeZone: () => 'UTC' },
    LockService: {
      getScriptLock: () => ({ tryLock: () => true, releaseLock() {} })
    },
    PropertiesService: {
      getScriptProperties: () => ({
        getProperty: k => (k in props ? props[k] : null),
        setProperty: (k, v) => { props[k] = String(v); },
        deleteProperty: k => { delete props[k]; }
      })
    },
    GmailApp: {
      search: (q) => {
        calls.push({ op: 'search', q });
        if (opts.searchResults && q in opts.searchResults) return opts.searchResults[q];
        return opts.threads || [];
      },
      getMessagesForThreads: ts => ts.map(t => t.__messages),
      getUserLabelByName: n => labelObj(n),
      createLabel: n => labelObj(n)
    },
    Gmail: {
      Users: {
        Labels: {
          list() { return { labels: [{ id: 'Label_PURGE', name: 'SpamDetectorPurge' },
                                     { id: 'Label_PHISH', name: 'Phishing' }] }; },
          create(body) { return { id: 'Label_NEW_' + body.name, name: body.name }; }
        },
        Messages: {
          modify(body, user, id) {
            calls.push({ op: 'modify', id,
                         add: body.addLabelIds || [], rm: body.removeLabelIds || [] });
          },
          batchDelete(body) { calls.push({ op: 'batchDelete', ids: body.ids.slice() }); },
          list(user, params) {
            calls.push({ op: 'list', labelIds: (params.labelIds || []).slice(),
                         q: params.q || null });
            // Honour the label intersection the caller asked for: only messages
            // the harness says carry every requested label come back.
            const want = params.labelIds || [];
            const folder = opts.spamFolder || {};
            const ids = Object.keys(folder).filter(id =>
              want.every(l => l === 'SPAM' || folder[id].indexOf(l) !== -1));
            return { messages: ids.map(id => ({ id })) };
          }
        }
      }
    },
    DriveApp: {
      getFolderById: () => ({
        createFile: () => ({ getUrl: () => 'https://drive/x', getId: () => 'f1' }),
        getFoldersByName: () => ({ hasNext: () => false }),
        createFolder() { return this; }
      })
    }
  };
  vm.createContext(ctx);
  new vm.Script(fs.readFileSync(GS_PATH, 'utf8')).runInContext(ctx);
  return ctx;
}

/** A fake message whose HTML carries a brand-mismatched CTA (fires Rule 7). */
function phishMessage(id) {
  const html = '<p><a href="https://cptlbpolicy.com/">VIEW IN DOCUSIGN&#x2192;</a></p>';
  return {
    __id: id,
    getId: () => id,
    getSubject: () => 'Capital B | Bitcoin Policy Brief',
    getFrom: () => 'Capital B <info@cptlbnews.press>',
    getPlainBody: () => 'Capital B policy brief',
    getBody: () => html,
    getRawContent: () => 'X-SES-Outgoing: 1\r\nPrecedence: bulk\r\n\r\n' + html,
    getAttachments: () => [],
    getDate: () => new Date('2026-09-16T15:25:41Z'),
    // accumulateLogEntry() reads all three; omitting them made it throw, report
    // no archive, and the archive invariant then refused every delete.
    getThread: () => ({ getId: () => 't-' + id }),
    getReplyTo: () => '',
    getHeader: () => ''
  };
}

/** A fake message that trips Rule 1 (bulk + blacklisted) and must be deleted. */
function blacklistMessage(id) {
  return {
    __id: id,
    getId: () => id,
    getSubject: () => 'Doctor: 92 million Americans on deadly drug',
    getFrom: () => 'FinRiseX <team@your.finrisex.com>',
    getPlainBody: () => 'body',
    getBody: () => '<p>body</p>',
    getRawContent: () => 'X-SES-Outgoing: 1\r\n\r\nbody',
    getAttachments: () => [],
    getDate: () => new Date('2026-09-16T15:25:41Z'),
    getThread: () => ({ getId: () => 't-' + id }),
    getReplyTo: () => '',
    getHeader: () => ''
  };
}

function fakeThread(messages, sink) {
  const labels = [];
  const ops = [];
  // `sink` is optionally makeCtx's `calls`, so label operations and Gmail API
  // operations land in ONE ordered log. Without it the invariant at
  // SpamDetector.gs "remove the label before deleting — a deleted thread
  // cannot be relabelled" is unprovable, because the two op kinds lived in
  // separate arrays and any findIndex comparison between them was meaningless.
  const record = o => { ops.push(o); if (sink) sink.push(o); };
  return {
    __messages: messages,
    __labels: labels,
    __ops: ops,
    getId: () => 't1',
    getFirstMessageSubject: () => messages[0].getSubject(),
    getMessages: () => messages,
    // Ops are recorded on the thread itself (__ops), not in makeCtx's `calls`,
    // which is out of scope here. removeLabel used to record nothing at all,
    // which made any assertion of the form
    //   findIndex(removeLabel) < findIndex(batchDelete)
    // pass vacuously at -1 < 0.
    addLabel(l) { record({ op: 'addLabel', label: l.__label }); labels.push(l.__label); },
    removeLabel(l) {
      record({ op: 'removeLabel', label: l.__label });
      const i = labels.indexOf(l.__label); if (i >= 0) labels.splice(i, 1);
    },
    moveToSpam() { labels.push('__MOVED_TO_SPAM__'); },
    moveToArchive() { labels.push('__ARCHIVED__'); }
  };
}

// ---------------------------------------------------------------------------
console.log('\n=== Rule 7 (brand-mismatched CTA) must quarantine, never destroy ===');
{
  const ctx = makeCtx();
  const msg = phishMessage('mPHISH');
  const thread = fakeThread([msg]);
  const destroyed = ctx.disposeDetectedMessage(msg, thread,
    ctx.collectSignals(msg), true);

  const deletes = ctx.calls.filter(c => c.op === 'batchDelete');
  const spamAdds = ctx.calls.filter(c => c.op === 'modify' && c.add.indexOf('SPAM') !== -1);
  const inboxRemovals = ctx.calls.filter(c => c.op === 'modify' && c.rm.indexOf('INBOX') !== -1);

  check('issues ZERO batchDelete calls', deletes.length === 0,
        JSON.stringify(deletes));
  check('never adds the SPAM label', spamAdds.length === 0,
        JSON.stringify(spamAdds));
  check('archives the message (removes INBOX)', inboxRemovals.length === 1);
  check('applies the Phishing label', thread.__labels.indexOf('Phishing') !== -1,
        JSON.stringify(thread.__labels));
  check('applies the SpamChecked label so it is not re-detected',
        thread.__labels.indexOf('SpamChecked') !== -1, JSON.stringify(thread.__labels));
  check('reports the thread as NOT destroyed', destroyed === false);
}

console.log('\n=== Rules 1-6 must still permanently delete ===');
{
  const ctx = makeCtx();
  const msg = blacklistMessage('mSPAM');
  const thread = fakeThread([msg]);
  const signals = ctx.collectSignals(msg);
  const rule = ctx.getRuleFromSignals(signals).rule;
  // archived=true simulates archiveRawEml() having stored the raw message.
  const destroyed = ctx.disposeDetectedMessage(msg, thread, signals, true);

  const deletes = ctx.calls.filter(c => c.op === 'batchDelete');
  check('identified as a destructive rule (got ' + rule + ')',
        ['Rule 1','Rule 2','Rule 3','Rule 4','Rule 5','Rule 6'].indexOf(rule) !== -1);
  check('issues exactly one batchDelete', deletes.length === 1);
  check('deletes exactly one message id',
        deletes.length === 1 && deletes[0].ids.length === 1 && deletes[0].ids[0] === 'mSPAM');
  check('reports the thread as destroyed', destroyed === true);
}

console.log('\n=== No Drive archive means NO permanent delete ===');
{
  // The invariant that did not exist before v6.47.0. Four comments in
  // SpamDetector.gs asserted "archived before deleting" while the Drive write
  // actually happened AFTER the batchDelete, so an interruption in between lost
  // the only copy. A destructive rule with no archive must now downgrade to a
  // hold, not delete.
  const ctx = makeCtx();
  const msg = blacklistMessage('mNOARCH');
  const thread = fakeThread([msg]);
  const signals = ctx.collectSignals(msg);
  check('rule is destructive (got ' + ctx.getRuleFromSignals(signals).rule + ')',
        ctx.getRuleFromSignals(signals).rule === 'Rule 1');

  const destroyed = ctx.disposeDetectedMessage(msg, thread, signals, false);
  check('unarchived destructive verdict issues NO batchDelete',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 0,
        JSON.stringify(ctx.calls));
  check('unarchived destructive verdict reports NOT destroyed', destroyed === false);
  check('thread is flagged SuspectedSpam for review',
        thread.__labels.indexOf('SuspectedSpam') !== -1, JSON.stringify(thread.__labels));
  check('it is NOT mislabelled as Phishing (a spam rule fired, not Rule 7)',
        thread.__labels.indexOf('Phishing') === -1);

  // omitted argument must behave the same as false — fail safe on a bad call
  const ctx2 = makeCtx();
  const msg2 = blacklistMessage('mUNDEF');
  ctx2.disposeDetectedMessage(msg2, fakeThread([msg2]), ctx2.collectSignals(msg2));
  check('omitting the archived argument also refuses to delete',
        ctx2.calls.filter(c => c.op === 'batchDelete').length === 0);
}

console.log('\n=== Unidentified disposition must fail SAFE (quarantine, not delete) ===');
{
  const ctx = makeCtx();
  const msg = phishMessage('mNULL');
  const thread = fakeThread([msg]);
  const destroyed = ctx.disposeDetectedMessage(msg, thread, null); // rule = NONE
  check('null signals do not trigger batchDelete',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 0);
  check('null signals report NOT destroyed', destroyed === false);
}

console.log('\n=== Quarantine is terminal: repeated runs detect it exactly once ===');
{
  // A two-message thread: the phish plus a sibling that keeps INBOX, which is
  // the reply-chain lure shape. This is the M1 regression test.
  const phish = phishMessage('mPHISH');
  const sibling = blacklistMessage('mSIB');
  sibling.getFrom = () => 'Colleague <colleague@example.org>';
  sibling.getSubject = () => 'Re: quarterly numbers';
  sibling.getRawContent = () => 'Received: from mail.example.org\r\n\r\nhi';
  sibling.getBody = () => '<p>hi</p>';

  const thread = fakeThread([phish, sibling]);
  const ctx = makeCtx({ threads: [thread] });

  let detections = 0;
  const origDispose = ctx.disposeDetectedMessage;
  ctx.disposeDetectedMessage = function (m, t, s) { detections++; return origDispose(m, t, s); };

  // Simulate three consecutive 1-minute trigger cycles. GmailApp.search() is
  // stubbed to honour the -label: exclusions the real query carries.
  for (let run = 1; run <= 3; run++) {
    ctx.GmailApp.search = function () {
      const q = ctx.buildSearchQuery();
      const excluded = ['SpamChecked', 'Phishing'].some(function (name) {
        return q.indexOf('-label:' + name) !== -1 && thread.__labels.indexOf(name) !== -1;
      });
      return excluded ? [] : [thread];
    };
    ctx.processInbox();
  }

  check('detected exactly once across 3 runs (got ' + detections + ')', detections === 1);
  check('thread carries Phishing', thread.__labels.indexOf('Phishing') !== -1);
  check('thread carries SpamChecked', thread.__labels.indexOf('SpamChecked') !== -1);
  check('no batchDelete over 3 runs',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 0);
}

console.log('\n=== markAsSpam tags its own verdicts before deleting ===');
{
  const ctx = makeCtx();
  const msg = blacklistMessage('mSPAM');
  ctx.markAsSpam(msg, fakeThread([msg]));
  const mod = ctx.calls.find(c => c.op === 'modify');
  check('purge label applied alongside SPAM',
        !!mod && mod.add.indexOf('Label_PURGE') !== -1 && mod.add.indexOf('SPAM') !== -1,
        JSON.stringify(mod));
  check('tag and spam-report happen in ONE modify call',
        ctx.calls.filter(c => c.op === 'modify').length === 1);
  check('tag is applied BEFORE the delete',
        ctx.calls.findIndex(c => c.op === 'modify') <
        ctx.calls.findIndex(c => c.op === 'batchDelete'));
}

console.log('\n=== Gmail spam phase 1: corroborated verdicts delete immediately ===');
{
  // The reported sender. No inbox rule fires on a direct-send free-mail
  // address and gmail.com cannot be blacklisted — but Gmail already flagged
  // it, and a machine-generated local part corroborates that. Deleted now, not
  // in seven days.
  const raju = blacklistMessage('mRAJU');
  raju.getFrom = () => 'raju <raju47326yu@gmail.com>';
  raju.getSubject = () => 'Hello friend';
  raju.getRawContent = () => 'Received: from mail-x\r\n\r\nhi';
  raju.getBody = () => '<p>hi</p>';
  const tRaju = fakeThread([raju]);

  const ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
  let queries = [];
  ctx.GmailApp.search = (q) => {
    queries.push(q);
    return q.indexOf('older_than') === -1 ? [tRaju] : [];
  };
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.reviewGmailSpam();

  const deleted = ctx.calls.filter(c => c.op === 'batchDelete')
                           .reduce((a, c) => a.concat(c.ids), []);
  check('raju47326yu@gmail.com is deleted immediately', deleted.indexOf('mRAJU') !== -1,
        'deleted=' + JSON.stringify(deleted));
  check('phase 1 query is NOT age-gated (corroboration acts now)',
        queries.some(q => q.indexOf('in:spam') !== -1 && q.indexOf('older_than') === -1),
        JSON.stringify(queries));
  check('phase 2 query IS age-gated',
        queries.some(q => q.indexOf('older_than:') !== -1), JSON.stringify(queries));
}

console.log('\n=== a real person on free mail is NOT deleted by corroboration ===');
{
  // The whole risk of Signal 8 is deleting mail from a person. These must fall
  // through to the grace period, not to immediate deletion.
  for (const [id, from, desc] of [
    ['mJANE', 'Jane Doe <jane.doe@gmail.com>',   'ordinary name'],
    ['mJOHN', 'John <john1985@gmail.com>',       'name + birth year'],
    ['mMIKE', 'Mike <mike_92@yahoo.com>',        'name + short digits'],
    ['mKENT', 'Clark <clark.kent1938@gmail.com>', 'dotted name + year']
  ]) {
    const m = blacklistMessage(id);
    m.getFrom = () => from;
    m.getSubject = () => 'Following up on our chat';
    m.getRawContent = () => 'Received: from mail-x\r\n\r\nhi';
    m.getBody = () => '<p>hi</p>';
    const thread = fakeThread([m]);
    const ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
    ctx.GmailApp.search = (q) => (q.indexOf('older_than') === -1 ? [thread] : []);
    ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
    ctx.reviewGmailSpam();

    check('NOT deleted on corroboration: ' + desc,
          ctx.calls.filter(c => c.op === 'batchDelete').length === 0,
          JSON.stringify(ctx.calls.filter(c => c.op === 'batchDelete')));
    check('marked reviewed so it is judged once: ' + desc,
          thread.__labels.indexOf('SpamChecked') !== -1, JSON.stringify(thread.__labels));
  }
}

console.log('\n=== phase 2: aged mail deletes on Gmail\'s word, whitelist spared ===');
{
  const aged = blacklistMessage('mAGED');
  aged.getFrom = () => 'Someone <hello@unknown-sender.com>';
  aged.getRawContent = () => 'Received: from mail-x\r\n\r\nhi';
  aged.getBody = () => '<p>hi</p>';
  const wl = blacklistMessage('mWLAGED');
  wl.getFrom = () => 'LinkedIn <jobalerts-noreply@linkedin.com>';
  wl.getRawContent = () => 'Received: from mail.linkedin.com\r\n\r\nhi';
  wl.getBody = () => '<p>hi</p>';

  const ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
  ctx.GmailApp.search = (q) => (q.indexOf('older_than') !== -1
    ? [fakeThread([aged]), fakeThread([wl])] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.reviewGmailSpam();

  const deleted = ctx.calls.filter(c => c.op === 'batchDelete')
                           .reduce((a, c) => a.concat(c.ids), []);
  check('aged uncorroborated mail IS deleted', deleted.indexOf('mAGED') !== -1,
        'deleted=' + JSON.stringify(deleted));
  check('aged WHITELISTED mail is NOT deleted', deleted.indexOf('mWLAGED') === -1,
        'deleted=' + JSON.stringify(deleted));
  check('grace period comes from CONFIG and is a positive integer',
        Number.isInteger(vm.runInContext('CONFIG.gmailSpamGraceDays', ctx)) &&
        vm.runInContext('CONFIG.gmailSpamGraceDays', ctx) > 0);
}

console.log('\n=== the whitelist holds across all header forms ===');
{
  for (const [id, from, desc] of [
    ['mWL1', 'LinkedIn <jobalerts-noreply@linkedin.com>',     'angle form'],
    ['mWL2', 'notifications@linkedin.com (LinkedIn)',         'RFC2822 comment form'],
    ['mWL3', '"' + 'A'.repeat(600) + '" <news@substack.com>', '600-char display name'],
    ['mWL4', 'news@substack.com',                             'bare address']
  ]) {
    const m = blacklistMessage(id);
    m.getFrom = () => from;
    m.getRawContent = () => 'Received: from mail.example\r\n\r\nhi';
    m.getBody = () => '<p>hi</p>';
    const thread = fakeThread([m]);
    const ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
    ctx.GmailApp.search = () => [thread];   // both phases see it
    ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
    ctx.reviewGmailSpam();
    check('whitelisted NEVER deleted, either phase: ' + desc,
          ctx.calls.filter(c => c.op === 'batchDelete').length === 0,
          JSON.stringify(ctx.calls.filter(c => c.op === 'batchDelete')));
  }
}

console.log('\n=== every non-deleting branch marks the thread reviewed ===');
{
  // (a) archive unavailable
  const na = blacklistMessage('mMARK2');
  na.getFrom = () => 'raju <raju47326yu@gmail.com>';
  na.getRawContent = () => 'Received: from x\r\n\r\nhi';
  na.getBody = () => '<p>hi</p>';
  const tNa = fakeThread([na]);
  let ctx = makeCtx();   // no folder id
  ctx.GmailApp.search = (q) => (q.indexOf('older_than') === -1 ? [tNa] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.reviewGmailSpam();
  check('unarchivable is NOT deleted',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 0);
  check('unarchivable is still marked reviewed',
        tNa.__labels.indexOf('SpamChecked') !== -1, JSON.stringify(tNa.__labels));

  // (b) collectSignals throws
  const boom = blacklistMessage('mMARK3');
  boom.getRawContent = () => { throw new Error('malformed MIME'); };
  const tBoom = fakeThread([boom]);
  ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
  ctx.GmailApp.search = (q) => (q.indexOf('older_than') === -1 ? [tBoom] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.reviewGmailSpam();
  check('a throwing message is NOT deleted',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 0);
  check('a throwing message is still marked reviewed',
        tBoom.__labels.indexOf('SpamChecked') !== -1, JSON.stringify(tBoom.__labels));

  // (c) Advanced Service missing -> fallback must not count as deleted
  const fb = blacklistMessage('mMARK4');
  fb.getFrom = () => 'raju <raju47326yu@gmail.com>';
  fb.getRawContent = () => 'Received: from x\r\n\r\nhi';
  fb.getBody = () => '<p>hi</p>';
  const tFb = fakeThread([fb]);
  ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
  ctx.GmailApp.search = (q) => (q.indexOf('older_than') === -1 ? [tFb] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.Gmail = undefined;
  ctx.reviewGmailSpam();
  check('no Advanced Service means no delete, no crash',
        !ctx.calls.some(c => c.op === 'batchDelete'));
  check('undeletable message is marked reviewed',
        tFb.__labels.indexOf('SpamChecked') !== -1, JSON.stringify(tFb.__labels));
}

console.log('\n=== logging: every reviewed message produces a row ===');
{
  const raju = blacklistMessage('mLOG1');
  raju.getFrom = () => 'raju <raju47326yu@gmail.com>';
  raju.getRawContent = () => 'Received: from x\r\n\r\nhi';
  raju.getBody = () => '<p>hi</p>';
  const linked = blacklistMessage('mLOG2');
  linked.getFrom = () => 'LinkedIn <jobalerts-noreply@linkedin.com>';
  linked.getRawContent = () => 'Received: from mail.linkedin.com\r\n\r\nhi';
  linked.getBody = () => '<p>hi</p>';

  const ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
  ctx.GmailApp.search = (q) => (q.indexOf('older_than') === -1
    ? [fakeThread([raju]), fakeThread([linked])] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);

  const rows = [];
  const orig = ctx.accumulateLogEntry;
  ctx.accumulateLogEntry = function (m, sig, type, opts) {
    rows.push({ id: m.getId(), type, skipArchive: !!(opts && opts.skipArchive) });
    return orig(m, sig, type, opts);
  };
  ctx.reviewGmailSpam();

  check('both messages logged', rows.length === 2, JSON.stringify(rows));
  const del  = rows.find(r => r.id === 'mLOG1');
  const kept = rows.find(r => r.id === 'mLOG2');
  check('corroborated deletion logs CORROBORATED or CONFIRMED',
        !!del && (del.type === 'GMAIL_SPAM_CORROBORATED' ||
                  del.type === 'GMAIL_SPAM_CONFIRMED'), JSON.stringify(del));
  check('deleted message IS archived to Drive',
        !!del && del.skipArchive === false);
  check('kept message logs KEPT_WHITELISTED',
        !!kept && kept.type === 'GMAIL_SPAM_KEPT_WHITELISTED', JSON.stringify(kept));
  check('kept message is NOT copied to Drive',
        !!kept && kept.skipArchive === true);
  check('FREEMAIL_RANDOM_LOCAL appears in the signals CSV',
        vm.runInContext("buildSignalsCsv({freeMailRandomLocal:true})", ctx)
          .indexOf('FREEMAIL_RANDOM_LOCAL') !== -1);
}

console.log('\n=== checkFalseNegatives: SpamMissed cannot destroy whitelisted mail ===');
{
  // This path deletes on explicit human instruction, which is sound for one
  // deliberate click and unsound for a mis-click on a multi-select. Applying
  // SpamMissed to forty threads is two keystrokes in Gmail.
  const linked = blacklistMessage('mSM_WL');
  linked.getFrom = () => 'LinkedIn <jobalerts-noreply@linkedin.com>';
  linked.getSubject = () => 'Brex is hiring a Director of Product';
  linked.getRawContent = () => 'Received: from mail.linkedin.com\r\n\r\nhi';
  linked.getBody = () => '<p>hi</p>';
  const tLinked = fakeThread([linked]);
  tLinked.__labels.push('SpamMissed');

  const ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
  ctx.GmailApp.search = (q) =>
    (q.indexOf('SpamMissed') !== -1 ? [tLinked] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);

  const rows = [];
  const orig = ctx.accumulateLogEntry;
  ctx.accumulateLogEntry = function (m, sig, type, opts) {
    rows.push({ id: m.getId(), type, skipArchive: !!(opts && opts.skipArchive) });
    return orig(m, sig, type, opts);
  };

  ctx.checkFalseNegatives();

  check('whitelisted SpamMissed message is NOT deleted',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 0,
        JSON.stringify(ctx.calls.filter(c => c.op === 'batchDelete')));
  check('whitelisted message is not moved to SPAM either',
        !ctx.calls.some(c => c.op === 'modify' && (c.add || []).indexOf('SPAM') !== -1));
  check('the refusal is logged to the Sheet',
        rows.some(r => r.type === 'SPAM_MISSED_REFUSED_WHITELISTED'),
        'rows=' + JSON.stringify(rows));
  const refusal = rows.find(r => r.type === 'SPAM_MISSED_REFUSED_WHITELISTED');
  check('refusal is NOT archived to Drive (nothing destroyed)',
        !!refusal && refusal.skipArchive === true, JSON.stringify(rows));
  check('SpamMissed is REMOVED so the refusal does not repeat every cycle',
        tLinked.__ops.some(o => o.op === 'removeLabel' && o.label === 'SpamMissed'),
        JSON.stringify(tLinked.__ops));
  check('and the review label is ADDED so the user can see the refusal',
        tLinked.__labels.indexOf('SuspectedSpam') !== -1,
        JSON.stringify(tLinked.__labels));
}

console.log('\n=== checkFalseNegatives: a NON-whitelisted SpamMissed IS deleted ===');
{
  // The feature must still work — the user asked for this one to go.
  const junk = blacklistMessage('mSM_OK');   // team@your.finrisex.com
  const tJunk = fakeThread([junk]);
  tJunk.__labels.push('SpamMissed');

  const ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
  // Shared sink: label ops interleave with Gmail ops in ctx.calls, so the
  // ordering invariant below is actually provable.
  const tJunkS = fakeThread([junk], ctx.calls);
  tJunkS.__labels.push('SpamMissed');
  ctx.GmailApp.search = (q) => (q.indexOf('SpamMissed') !== -1 ? [tJunkS] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.checkFalseNegatives();

  const deleted = ctx.calls.filter(c => c.op === 'batchDelete')
                           .reduce((a, c) => a.concat(c.ids), []);
  check('non-whitelisted SpamMissed message IS deleted', deleted.indexOf('mSM_OK') !== -1,
        'deleted=' + JSON.stringify(deleted));

  const rmIdx  = ctx.calls.findIndex(c => c.op === 'removeLabel' && c.label === 'SpamMissed');
  const delIdx = ctx.calls.findIndex(c => c.op === 'batchDelete');
  check('SpamMissed label was actually removed', rmIdx !== -1, JSON.stringify(ctx.calls));
  check('and removed BEFORE the delete (a deleted thread cannot be relabelled)',
        rmIdx !== -1 && delIdx !== -1 && rmIdx < delIdx,
        'removeLabel@' + rmIdx + ' batchDelete@' + delIdx);
}

console.log('\n=== checkFalseNegatives: unarchivable is refused, once, visibly ===');
{
  // Previously the label was removed BEFORE the archive check, so this branch
  // dropped the message silently and the comment promising a retry was false.
  const junk = blacklistMessage('mSM_NOARCH');
  const tJunk = fakeThread([junk]);
  tJunk.__labels.push('SpamMissed');

  const ctx = makeCtx();   // no SPAM_LOG_FOLDER_ID -> archive fails
  ctx.GmailApp.search = (q) => (q.indexOf('SpamMissed') !== -1 ? [tJunk] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.checkFalseNegatives();

  check('unarchivable message is NOT deleted',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 0);
  check('SpamMissed is swapped for the review label, not kept',
        tJunk.__ops.some(o => o.op === 'removeLabel' && o.label === 'SpamMissed') &&
        tJunk.__labels.indexOf('SuspectedSpam') !== -1,
        JSON.stringify(tJunk.__ops) + ' labels=' + JSON.stringify(tJunk.__labels));

  // The reason it must not be kept: accumulateLogEntry() buffers its Sheets row
  // BEFORE the archive check, so a retained label meant a duplicate row and two
  // getRawContent() fetches every cycle — measured at 288 rows/day.
  const before = ctx.calls.filter(c => c.op === 'batchDelete').length;
  ctx.GmailApp.search = () => [];   // label swapped, so the search no longer matches
  ctx.checkFalseNegatives();
  check('a second cycle does no further work', 
        ctx.calls.filter(c => c.op === 'batchDelete').length === before);
}

console.log('\n=== checkFalseNegatives: edge cases the review asked for ===');
{
  // (a) whitelisted message is NOT messages[0]. markAsSpam()'s no-Advanced-
  // Service fallback is thread.moveToSpam(), which moves the whole thread, so
  // a whitelisted sibling must veto the delete.
  const junk = blacklistMessage('mSIB_JUNK');
  const wl = blacklistMessage('mSIB_WL');
  wl.getFrom = () => 'LinkedIn <jobalerts-noreply@linkedin.com>';
  wl.getRawContent = () => 'Received: from mail.linkedin.com\r\n\r\nhi';
  wl.getBody = () => '<p>hi</p>';
  const tSib = fakeThread([junk, wl]);
  tSib.__labels.push('SpamMissed');

  let ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
  ctx.GmailApp.search = (q) => (q.indexOf('SpamMissed') !== -1 ? [tSib] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.checkFalseNegatives();
  check('a whitelisted SIBLING vetoes the delete',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 0,
        JSON.stringify(ctx.calls.filter(c => c.op === 'batchDelete')));

  // (b) getFrom() throws -> isWhitelistedSender fails safe to true -> refused
  const bad = blacklistMessage('mSM_BADFROM');
  bad.getFrom = () => { throw new Error('malformed From header'); };
  const tBad = fakeThread([bad]);
  tBad.__labels.push('SpamMissed');
  ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
  ctx.GmailApp.search = (q) => (q.indexOf('SpamMissed') !== -1 ? [tBad] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.checkFalseNegatives();
  check('an unreadable From is refused, not deleted',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 0,
        JSON.stringify(ctx.calls.filter(c => c.op === 'batchDelete')));

  // (c) whitelisted AND unarchivable -> the whitelist guard must win, and the
  // outcome must still be visible rather than silent.
  const both = blacklistMessage('mSM_BOTH');
  both.getFrom = () => 'LinkedIn <jobalerts-noreply@linkedin.com>';
  both.getRawContent = () => 'Received: from mail.linkedin.com\r\n\r\nhi';
  both.getBody = () => '<p>hi</p>';
  const tBoth = fakeThread([both]);
  tBoth.__labels.push('SpamMissed');
  ctx = makeCtx();   // no SPAM_LOG_FOLDER_ID either
  ctx.GmailApp.search = (q) => (q.indexOf('SpamMissed') !== -1 ? [tBoth] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.checkFalseNegatives();
  check('whitelisted AND unarchivable: not deleted',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 0);
  check('whitelisted AND unarchivable: outcome still visible',
        tBoth.__labels.indexOf('SuspectedSpam') !== -1,
        JSON.stringify(tBoth.__labels));
}

console.log('\n=== the recheck path HOLDS, it never deletes ===');
{
  // Mail the user already read and kept, which a newly deployed pattern now
  // scores as spam. Until v6.48.0 this permanently deleted up to 20 such
  // messages within a minute of every deploy.
  const ctx = makeCtx();
  const msg = blacklistMessage('mRECHECK');
  const thread = fakeThread([msg]);

  const held = ctx.holdForReview(msg, thread, 'recheck after pattern change');

  check('reports success', held === true);
  check('issues NO batchDelete',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 0,
        JSON.stringify(ctx.calls));
  check('never adds the SPAM label',
        ctx.calls.filter(c => c.op === 'modify' && c.add.indexOf('SPAM') !== -1).length === 0);
  check('archives out of the inbox',
        ctx.calls.some(c => c.op === 'modify' && c.rm.indexOf('INBOX') !== -1));
  check('labels SuspectedSpam for review',
        thread.__labels.indexOf('SuspectedSpam') !== -1, JSON.stringify(thread.__labels));
  check('labels SpamChecked so it is not re-held every cycle',
        thread.__labels.indexOf('SpamChecked') !== -1, JSON.stringify(thread.__labels));
  check('not mislabelled Phishing (no Rule 7 involved)',
        thread.__labels.indexOf('Phishing') === -1);
}

console.log('\n=== destroySpam() sweeps ONLY what this detector condemned ===');
{
  // mOURS carries the purge tag (we judged and archived it); mGMAIL does not
  // (Gmail's classifier filed it and we never evaluated it).
  const ctx = makeCtx({ spamFolder: { mOURS: ['Label_PURGE'], mGMAIL: [] } });
  ctx.destroySpam();

  const listed = ctx.calls.filter(c => c.op === 'list');
  const deleted = ctx.calls.filter(c => c.op === 'batchDelete')
                           .reduce((a, c) => a.concat(c.ids), []);
  check('sweep scoped by label intersection, not a q: filter',
        listed.length > 0 &&
        listed[0].labelIds.indexOf('SPAM') !== -1 &&
        listed[0].labelIds.indexOf('Label_PURGE') !== -1 &&
        listed[0].q === null,
        JSON.stringify(listed[0]));
  check('our own verdict IS deleted', deleted.indexOf('mOURS') !== -1,
        'deleted=' + JSON.stringify(deleted));
  check('Gmail-classified spam is NOT deleted', deleted.indexOf('mGMAIL') === -1,
        'deleted=' + JSON.stringify(deleted));
}

console.log('\n=== destroySpam() never deletes a message quarantined this run ===');
{
  const ctx = makeCtx({ spamFolder: { mQUAR: ['Label_PURGE'], mOTHER: ['Label_PURGE'] } });
  const msg = phishMessage('mQUAR');
  ctx.disposeDetectedMessage(msg, fakeThread([msg]), ctx.collectSignals(msg));
  ctx.destroySpam();

  const deleted = ctx.calls.filter(c => c.op === 'batchDelete')
                           .reduce((a, c) => a.concat(c.ids), []);
  check('quarantined id excluded from the sweep', deleted.indexOf('mQUAR') === -1,
        'deleted=' + JSON.stringify(deleted));
  check('the sweep still runs for other condemned spam',
        deleted.indexOf('mOTHER') !== -1, 'deleted=' + JSON.stringify(deleted));
}

console.log('\n=== the sweep refuses to run if it cannot identify our verdicts ===');
{
  const ctx = makeCtx({ spamFolder: { mGMAIL: [] } });
  // Label resolution fails entirely — the safe answer is to sweep nothing
  // rather than fall back to deleting the whole folder.
  ctx.Gmail.Users.Labels.list = () => { throw new Error('API down'); };
  ctx.Gmail.Users.Labels.create = () => { throw new Error('API down'); };
  ctx.destroySpam();
  check('no batchDelete when the purge label cannot be resolved',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 0);
}

console.log('\n' + '='.repeat(70));
console.log(failures === 0
  ? '✅ DISPOSITION TESTS PASSED (' + passed + ' assertions)'
  : '❌ DISPOSITION TESTS FAILED: ' + failures + ' of ' + (passed + failures));
process.exit(failures === 0 ? 0 : 1);
