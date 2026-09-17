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

function fakeThread(messages) {
  const labels = [];
  return {
    __messages: messages,
    __labels: labels,
    getId: () => 't1',
    getFirstMessageSubject: () => messages[0].getSubject(),
    getMessages: () => messages,
    addLabel(l) { labels.push(l.__label); },
    removeLabel(l) { const i = labels.indexOf(l.__label); if (i >= 0) labels.splice(i, 1); },
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

console.log('\n=== Gmail spam: the AGE GATE is the protection ===');
{
  // The gate must be in the query itself, so young mail is never even fetched.
  // Deleting on Gmail's word alone with only a 16-entry whitelist as a guard
  // destroys first-contact mail, 2FA from small services, invoices on cheap
  // relays — none of which is whitelisted and all of which Gmail misfiles.
  const msg = blacklistMessage('mAGED');
  const ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
  let seenQuery = null;
  ctx.GmailApp.search = (q) => { seenQuery = q; return q.indexOf('in:spam') !== -1 ? [fakeThread([msg])] : []; };
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.reviewGmailSpam();

  check('query age-gates with older_than',
        !!seenQuery && /older_than:\d+d/.test(seenQuery), String(seenQuery));
  // Asserted against a concrete integer, not against the same expression the
  // code uses — comparing to CONFIG.x would have passed even when CONFIG.x was
  // undefined and the query read "older_than:undefinedd", which is exactly the
  // bug this suite caught.
  const grace = vm.runInContext('CONFIG.gmailSpamGraceDays', ctx);
  check('grace period is a positive integer', Number.isInteger(grace) && grace > 0,
        'got ' + JSON.stringify(grace));
  check('query embeds the configured grace period',
        !!seenQuery && seenQuery.indexOf('older_than:' + grace + 'd') !== -1,
        String(seenQuery));
  check('query excludes our own purge label',
        !!seenQuery && seenQuery.indexOf('-label:SpamDetectorPurge') !== -1);
  check('query excludes already-reviewed threads',
        !!seenQuery && seenQuery.indexOf('-label:SpamChecked') !== -1);
  check('an aged non-whitelisted message IS deleted',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 1,
        JSON.stringify(ctx.calls.filter(c => c.op === 'batchDelete')));
}

console.log('\n=== the whitelist holds, including the forms that used to miss ===');
{
  // Both of these failed the whitelist check before today, which was harmless
  // while the consequence was "stays in Spam" and data loss the moment any
  // path deleted on a failed match.
  const forms = [
    ['mWL1', 'LinkedIn <jobalerts-noreply@linkedin.com>',        'angle form'],
    ['mWL2', 'notifications@linkedin.com (LinkedIn)',            'RFC2822 comment form'],
    ['mWL3', '"' + 'A'.repeat(600) + '" <news@substack.com>',    '600-char display name'],
    ['mWL4', 'news@substack.com',                                'bare address']
  ];

  for (const [id, from, desc] of forms) {
    const m = blacklistMessage(id);
    m.getFrom = () => from;
    m.getRawContent = () => 'Received: from mail.example\r\n\r\nhi';
    m.getBody = () => '<p>hi</p>';
    const thread = fakeThread([m]);
    const ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
    ctx.GmailApp.search = (q) => (q.indexOf('in:spam') !== -1 ? [thread] : []);
    ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
    ctx.reviewGmailSpam();

    check('whitelisted sender NOT deleted: ' + desc,
          ctx.calls.filter(c => c.op === 'batchDelete').length === 0,
          JSON.stringify(ctx.calls.filter(c => c.op === 'batchDelete')));
    check('whitelisted message not modified at all: ' + desc,
          !ctx.calls.some(c => c.op === 'modify' && c.id === id));
  }
}

console.log('\n=== every non-deleting branch marks the thread reviewed ===');
{
  // A decision made and not recorded is recomputed forever. This project has
  // shipped that bug twice; these assertions are why it should not happen a
  // third time.

  // (a) whitelisted keep
  const wl = blacklistMessage('mMARK1');
  wl.getFrom = () => 'LinkedIn <jobalerts-noreply@linkedin.com>';
  wl.getRawContent = () => 'Received: from mail.linkedin.com\r\n\r\nhi';
  wl.getBody = () => '<p>hi</p>';
  const tWl = fakeThread([wl]);
  let ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
  ctx.GmailApp.search = (q) => (q.indexOf('in:spam') !== -1 ? [tWl] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.reviewGmailSpam();
  check('kept thread is marked reviewed', tWl.__labels.indexOf('SpamChecked') !== -1,
        JSON.stringify(tWl.__labels));

  // (b) archive unavailable -> must not delete, must still mark
  const na = blacklistMessage('mMARK2');
  const tNa = fakeThread([na]);
  ctx = makeCtx();   // no SPAM_LOG_FOLDER_ID
  ctx.GmailApp.search = (q) => (q.indexOf('in:spam') !== -1 ? [tNa] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.reviewGmailSpam();
  check('unarchivable message is NOT deleted',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 0);
  check('unarchivable message is still marked reviewed (no re-fetch loop)',
        tNa.__labels.indexOf('SpamChecked') !== -1, JSON.stringify(tNa.__labels));

  // (c) collectSignals throws -> must not delete, must still mark
  const boom = blacklistMessage('mMARK3');
  boom.getRawContent = () => { throw new Error('malformed MIME'); };
  const tBoom = fakeThread([boom]);
  ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
  ctx.GmailApp.search = (q) => (q.indexOf('in:spam') !== -1 ? [tBoom] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.reviewGmailSpam();
  check('a throwing message is NOT deleted',
        ctx.calls.filter(c => c.op === 'batchDelete').length === 0,
        JSON.stringify(ctx.calls));
  check('a throwing message is still marked reviewed',
        tBoom.__labels.indexOf('SpamChecked') !== -1, JSON.stringify(tBoom.__labels));

  // (d) Gmail Advanced Service missing -> fallback must NOT count as a delete
  const fb = blacklistMessage('mMARK4');
  const tFb = fakeThread([fb]);
  ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
  ctx.GmailApp.search = (q) => (q.indexOf('in:spam') !== -1 ? [tFb] : []);
  ctx.GmailApp.getMessagesForThreads = ts => ts.map(t => t.__messages);
  ctx.Gmail = undefined;   // Advanced Service unavailable
  ctx.reviewGmailSpam();
  check('no Advanced Service means no delete, and no crash',
        !ctx.calls.some(c => c.op === 'batchDelete'));
  check('undeletable message is marked reviewed (no re-archive every cycle)',
        tFb.__labels.indexOf('SpamChecked') !== -1, JSON.stringify(tFb.__labels));
}

console.log('\n=== logging: every reviewed message produces a row ===');
{
  const spammy = blacklistMessage('mLOG1');
  const linked = blacklistMessage('mLOG2');
  linked.getFrom = () => 'LinkedIn <jobalerts-noreply@linkedin.com>';
  linked.getRawContent = () => 'Received: from mail.linkedin.com\r\n\r\nhi';
  linked.getBody = () => '<p>hi</p>';

  const ctx = makeCtx({ props: { SPAM_LOG_FOLDER_ID: 'folder123' } });
  ctx.GmailApp.search = (q) => (q.indexOf('in:spam') !== -1
    ? [fakeThread([spammy]), fakeThread([linked])] : []);
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
  // finrisex.com is blacklisted AND the fixture is SES-routed, so Rule 1 fires
  // and this is a genuine agreement rather than a deferral.
  check('rule-confirmed deletion logs CONFIRMED',
        !!del && del.type === 'GMAIL_SPAM_CONFIRMED', JSON.stringify(del));
  check('deleted message IS archived (it is being destroyed)',
        !!del && del.skipArchive === false);
  check('kept message logs KEPT_WHITELISTED',
        !!kept && kept.type === 'GMAIL_SPAM_KEPT_WHITELISTED', JSON.stringify(kept));
  check('kept message is NOT copied to Drive (survives; privacy)',
        !!kept && kept.skipArchive === true);
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
