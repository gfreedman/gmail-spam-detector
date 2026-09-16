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
      base64Encode: s => 'b64'
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
      search: () => opts.threads || [],
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
    getDate: () => new Date('2026-09-16T15:25:41Z')
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
    getDate: () => new Date('2026-09-16T15:25:41Z')
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
    ctx.collectSignals(msg));

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
  const destroyed = ctx.disposeDetectedMessage(msg, thread, signals);

  const deletes = ctx.calls.filter(c => c.op === 'batchDelete');
  check('identified as a destructive rule (got ' + rule + ')',
        ['Rule 1','Rule 2','Rule 3','Rule 4','Rule 5','Rule 6'].indexOf(rule) !== -1);
  check('issues exactly one batchDelete', deletes.length === 1);
  check('deletes exactly one message id',
        deletes.length === 1 && deletes[0].ids.length === 1 && deletes[0].ids[0] === 'mSPAM');
  check('reports the thread as destroyed', destroyed === true);
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
