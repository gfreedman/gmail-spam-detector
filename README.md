# Gmail Spam Detector - Pattern-Based Detection

**[📖 Documentation](https://gfreedman.github.io/gmail-spam-detector/)** &nbsp;·&nbsp; Google Apps Script &nbsp;·&nbsp; MIT license

A Google Apps Script that catches spam Gmail misses using behavioral pattern detection instead of keyword matching or domain blacklists.

## 🎯 The Problem

Gmail's spam filter lets certain types of spam through, particularly:
- Financial fear-mongering emails
- Clickbait "breaking news" scams
- Investment opportunity spam
- Health scare campaigns

All sent via bulk email services like Amazon SES, SendGrid, and Mailchimp — often hiding in Gmail's **Updates** or **Promotions** tabs where they're never seen.

## ✨ The Solution

**Pattern-based detection** that identifies spam by behavioral patterns spammers can't easily change:

1. **Bulk email infrastructure** (Amazon SES, SendGrid, Mailchimp)
2. **Clickbait subject patterns** ("Caught on Camera", "WARNING:", etc.)
3. **Fear-mongering language** (IRS, NSA, government warnings)
4. **Marketing sender format** ("Name | Organization")
5. **Blacklisted sender domains** (known spam mills)
6. **From-name anomalies** (bullet separators, excessive length)
7. **Unicode obfuscation** (Cyrillic/Greek/fullwidth lookalikes)
8. **Service impersonation** (a cloud-share subject from a non-service sender)
9. **Link-graph anomalies** (a CTA naming a brand its destination doesn't own)
10. **Machine-generated free-mail addresses** (throwaway accounts like `raju47326yu@gmail.com`)

**Detection Logic — 9 rules, first match wins:**
- Bulk email + blacklisted sender = SPAM
- Bulk email + 2+ clickbait patterns = SPAM
- Bulk email + 2+ spam behaviors = SPAM
- Extreme clickbait (3+ patterns) = SPAM
- Empty subject + attachment = SPAM
- Cloud-service subject from a non-service sender = PHISHING
- CTA names a document brand its destination doesn't control = PHISHING (quarantined, not deleted)
- Free-mail sender with a machine-generated address + 2 spam behaviours = SPAM
- Free-mail sender invoicing as a brand it doesn't control, with a phone number to call = PHISHING (quarantined, not deleted)

**Why this works:** Spammers need these patterns to make money. If they remove them, their business model breaks.

## 📊 Results

- ✅ **100% detection** on 54/54 spam + 5/5 scam (.eml files)
- ✅ **0% false positives** on 22/22 legitimate emails
- ✅ **Nothing is deleted without a Drive archive** — unarchivable mail is held, not destroyed
- ✅ **Every run audits itself** — `auditRunIntegrity()` writes an `AUDIT_*` row to the Sheet if a deleted message has no log row, or if aged non-whitelisted spam was left in the folder. Costs no API calls; silent when healthy.
- ✅ **No domain whack-a-mole** (catches new spam domains automatically)
- ✅ **Signal collection and verdict logic kept separate** (`collectSignals()` gathers facts, `makeVerdict()` judges)

## 🚀 Quick Start

### 1. Install

1. Go to [script.google.com](https://script.google.com)
2. Click **New Project**
3. Copy the entire contents of `SpamDetector.gs` into the editor
4. Rename to "Gmail Spam Detector"
5. Click **Save**

### 2. Authorize

1. Select `setup` from the function dropdown
2. Click **Run**
3. Authorize the script when prompted
4. Check the execution log - should see "Setup complete!"

### 3. Set Up Trigger

1. Click **Triggers** (clock icon in left sidebar)
2. Click **Add Trigger**
3. Configure:
   - Function: `processInbox`
   - Event source: **Time-driven**
   - Type: **Minutes timer**
   - Interval: **Every 1 minute**
4. Click **Save**

### 4. Enable Gmail API (for auto-delete)

1. In Apps Script, click **Services** (+ icon in left sidebar)
2. Search for **Gmail API**
3. Click **Add**

### 5. Set Up Spam Intelligence Logging

Run once from the Apps Script editor to create the Drive folder, Sheets log, and SpamMissed label:

1. Select `setupLogging` from the function dropdown
2. Click **Run**
3. Authorize the new Drive and Sheets permissions when prompted
4. Check the execution log - should see "Setup complete!"

This creates a **Spam Intelligence** folder in My Drive containing a flat EML archive and a Google Sheets log. Every spam detection is automatically recorded going forward.

### 6. Done!

The script now runs every minute, automatically detecting spam, reporting it to Gmail, and permanently deleting it.

## 🔥 What Happens To Detected Mail

Disposition depends on which rule fired, and the difference matters.

**Rules 1–6 — permanently deleted:**
1. **Archive first** — the raw message is written to Drive (`Spam Intelligence/Detected/`) *before* anything is destroyed. A message that can't be archived is held for review instead of deleted.
2. **Report as spam** — trains Gmail's own filters
3. **Delete forever** — `batchDelete` bypasses Trash, so the Drive copy is the only copy

**Rule 7 — quarantined, never deleted:**
Archived out of the inbox and labelled `Phishing`, kept in All Mail indefinitely. Rule 7 reads the link graph rather than sender reputation, and a legitimate sender can reproduce that pattern by accident, so permanent deletion is the wrong default.

**Mail Gmail filed as spam is deleted only after a grace period.** Gmail intercepts that mail before your inbox, so the detector's rules never judged it — and Gmail's own false-positive classes (first contact from a new correspondent, 2FA from a small service, an invoice on a cheap relay) are exactly what no whitelist can enumerate in advance. So `reviewGmailSpam()` lets it age `CONFIG.gmailSpamGraceDays` (default **7**) first, which is your recovery window: the folder is visible, searchable, and one "Not spam" click from undoing Gmail's mistake. After that Gmail's verdict stands and the message is archived, logged and deleted. Whitelisted senders are never deleted at any age, and nothing is ever moved back to your inbox.

Mail already reviewed is normally skipped, so the folder is not re-fetched every cycle. But "reviewed" is a fact about *the logic that did the reviewing*, not about the message — so a `SCRIPT_VERSION` change re-reviews the whole folder once, and an improved rule gets applied to spam the previous logic dismissed. (It did not, before v6.54.0: six messages sat through two releases meant to remove them.) `reviewSpamFolderNow()` runs the same pass on demand from the editor.

### Labels you'll see

| Label | Meaning | Action needed |
|---|---|---|
| `SpamChecked` | Evaluated; don't re-process | None — bookkeeping |
| `Phishing` | Rule 7 quarantine, archived not deleted | Review occasionally |
| `SuspectedSpam` | Flagged but **not** deleted — cleanse mode, a message too large to evaluate, one that couldn't be archived, or mail a newly deployed pattern re-flagged after you'd already kept it | Review; this is the "we weren't sure" pile |
| `SpamDetectorPurge` | Internal marker so the sweep only touches our own verdicts | None — machinery |
| `SpamMissed` | **You** apply this to spam that got through; it's logged and deleted on the next run — **unless the sender is whitelisted or the Drive archive is unreachable**, in which case it's refused and moved to `SuspectedSpam` | Apply it manually |

*Requires Gmail API to be enabled (see Quick Start step 4).*

## 📋 Spam Intelligence Logging

Every detected spam is automatically logged to:

- **Google Drive** — full `.eml` file saved flat in `Spam Intelligence/Detected/`
- **Google Sheets** — one row per event in `Spam Intelligence Log` with 19 columns: timestamp, rule triggered, signals, subject, sender, sending domain, Reply-To, clickbait count, bulk service flag, attachment flag, List-Unsubscribe flag, and a link to the Drive EML

### Log False Negatives (Spam the Script Missed)

1. Find a spam email that reached your inbox
2. Apply the Gmail label **`SpamMissed`** to it
3. On the next script run, the email is logged to `Spam Intelligence/False Negatives/` and permanently deleted

The Sheets row shows `Log Type = FALSE_NEGATIVE` and `Rule Triggered = NONE`. Fill in the **False Negative Notes** column to record why it was missed.

**Full design:** [docs/SPAM_LOGGING_PLAN.md](docs/SPAM_LOGGING_PLAN.md) — Drive/Sheets schema, 19-column log layout, OAuth scopes, false negative workflow, and architecture decisions.

## 📖 How It Works

### Detection Signals

**1. Bulk Email Service (Technical Signal)**
- Detects Amazon SES, SendGrid, and Mailchimp in email headers
- Most spam uses these for cheap bulk sending
- Legitimate senders often use their own SMTP

**2. Clickbait Patterns (Content Signal)**
```javascript
Caught on Camera
WARNING: | EXPOSED: | ALERT:
"This changes everything" | "Stunned everyone"
【Date brackets】
Sensationalist emoji 💼📸⏯️
Multiple punctuation ??? !!!
```

**3. Fear-Mongering Keywords (Content Signal)**
```
WARNING, EXPOSED, STOP Using, IRS, NSA,
Bank Account, Government Hiding, Blood Thinner
```

**4. Marketing Sender Format (Technical Signal)**
```
"Name | Organization" <email@domain.com>
"Topic, Company Name" <email@domain.com>
"Name at Org" <email@domain.com>
```

**5. Blacklisted Sender Domains (Technical Signal)**
- Known spam mill domains (e.g. financeinsiderpro.com, investorplace)
- Matched against the From field

**6. From-Name Anomalies (Technical Signal)**
- Display names with bullet separators (e.g. "Finance • Daily Tips")
- Excessively long display names (> 50 characters)

**7. Service Impersonation (Technical Signal)**
- A cloud document-sharing subject ("Document shared with you") from a sender
  that is not the service's own domain
- Real services only ever notify from their own infrastructure

**8. Brand-Mismatched CTA (Link-Graph Signal)**
- A call-to-action whose text names a document brand (DocuSign, Adobe Sign,
  SharePoint, OneDrive…) while its `href` points somewhere that brand does not
  control
- The only signal that inspects links rather than sender-side wording, which is
  how it reaches phishing with clean prose and valid DKIM
- **Abstains** when the destination is a click-tracker, a CNAMEd tracker
  (`click.`, `links.`, `go.`) or the sender's own domain — a wrapped link is
  *unverifiable*, not malicious
- Requires a CTA verb and a normalized label ≤ 80 chars, so a genuine DocuSign
  email's "About DocuSign" footer prose cannot trigger it. Measured on the
  alphanumeric-only form, so padding with zero-width characters can't evade it
- **Quarantines rather than deletes** — archived out of the inbox and labelled
  `Phishing`, never moved to Spam and never deleted, so it stays in All Mail

### Decision Rules

**Conservative approach - requires multiple signals:**

```javascript
// RULE 1: Bulk email + known spam domain → definitive spam
if (bulkEmail && blacklistedSender) { return SPAM; }

// RULE 2: Bulk email + 2+ clickbait patterns → spam
if (bulkEmail && clickbaitCount >= 2) { return SPAM; }

// RULE 3: Bulk email + 2+ independent spam behaviors → spam
// (behaviors = any of: clickbait, fear, marketing format, suspicious From name)
if (bulkEmail && spamBehaviorCount >= 2) { return SPAM; }

// RULE 4: Extreme clickbait alone (3+) → spam (catches direct-send spam)
if (clickbaitCount >= 3) { return SPAM; }

// RULE 5: Empty subject + attachment → payload delivery scam
if (emptySubject && hasAttachment) { return SPAM; }

// RULE 6: Cloud service subject from a non-service sender → phishing
// (no bulk gate: delivered via compromised legitimate accounts)
if (serviceImpersonation) { return SPAM; }

// Cleanup boundary: destroySpam() sweeps ONLY messages this detector
// condemned (tagged by markAsSpam() before it deletes). Mail Gmail's own
// classifier filed is left alone and purged by Gmail at 30 days, so Gmail's
// false positives stay recoverable. purgeAllSpamNow() empties the folder
// manually if you want it cleared sooner.

// RULE 7: CTA names a document brand the destination does not control → phishing
// (no bulk gate, same reasoning; trackers and aligned hosts already exempted)
// NOTE: Rule 7 QUARANTINES — archived + labelled "Phishing", never moved to
// Spam and never deleted, because it is the one rule with an irreducible
// false-positive class. Rules 1-6 delete permanently.
if (brandMismatchedCta) { return SPAM; }

return NOT_SPAM;
```

## ⚙️ Configuration

### Whitelist Legitimate Senders

If a legitimate email gets flagged (rare), add to whitelist:

```javascript
addToWhitelist('example.com');
```

Run this function in Apps Script and the domain is permanently whitelisted. No code changes needed!

### View Whitelist

```javascript
viewWhitelist();
```

Check execution log to see all whitelisted domains.

### Remove from Whitelist

```javascript
removeFromWhitelist('example.com');
```

## 🔍 Monitoring

### View Activity

1. In Apps Script, click **Executions** (left sidebar)
2. See logs for each run

**Example logs:**
```
[INFO] Found 3 threads to process
[DEBUG] Bulk email service detected
[DEBUG] Marketing sender format detected
[INFO] SPAM DETECTED: Bulk email + 2 spam behaviors
[INFO] SPAM REPORTED TO GOOGLE: WARNING: NSA Spied on Millions
[INFO] SPAM DESTROYED: WARNING: NSA Spied on Millions
[INFO] Completed in 1250ms: Processed 3 emails, marked 1 as spam
```

### Check for False Positives

Check the `Phishing` label for quarantined phishing, your Spam folder for anything Gmail misfiled (the detector no longer empties it), and the Drive archive (Spam Intelligence/Detected) to recover anything the detector deleted:
1. Look for emails with "SpamChecked" label
2. If legitimate, add sender to whitelist
3. Move back to Inbox

## 🛠️ Troubleshooting

### Debug Why an Email Was Flagged

```javascript
debugWhyFlagged('from:linkedin');  // Search term
```

Shows whitelist status, bulk email detection, and all signals for the email.

### Script Not Running
- Check **Triggers** tab - verify 1-minute trigger exists
- Check **Executions** tab for errors
- Manually run `processInbox` to test

### Legitimate Email Marked as Spam
```javascript
addToWhitelist('domain.com');
```

### Spam Getting Through
1. Check execution log - what signals were detected?
2. The script scans all Gmail category tabs (Primary, Updates, Promotions, Social, Forums) — spam can't hide in tabs
3. If spam doesn't use a known bulk service (Amazon SES, SendGrid, Mailchimp), may not be caught
4. Open an issue with the .eml file

## 📁 Files

```
/
├── SpamDetector.gs              # Main script (auto-deployed)
├── appsscript.json              # Apps Script manifest (scopes, runtime)
├── .claspignore                 # Controls which files clasp uploads
├── README.md
├── CHANGELOG.md                 # Release history (was the .gs header comment)
├── LICENSE
├── docs/
│   ├── index.html               # Published GitHub Pages site
│   ├── BACKLOG.md               # Deferred work, with why-it-can-wait rationale
│   └── EXPORTING_EMAILS.md      # How to export .eml files from Gmail
├── scripts/
│   ├── patch_version.js         # Stamps @version + SCRIPT_VERSION at deploy
│   └── validate.py              # Repo consistency checks (runs in CI)
├── tests/
│   ├── test_spam_detector.py    # Detection corpus + edge cases (Python)
│   ├── test_disposition.js      # Quarantine-vs-delete routing (Node)
│   ├── test_link_graph.js       # URL parsing + Signal 7 (Node)
│   ├── test_patch_version.js    # Version patch + claspignore (Node)
│   ├── spam_examples/           # Real spam .eml files (54)
│   ├── scam_examples/           # Scam .eml files (5)
│   └── ham_examples/            # Legitimate .eml files (22)
└── .github/workflows/           # CI/CD pipeline
```

Docs: [Changelog](CHANGELOG.md) · [Backlog](docs/BACKLOG.md) · [Exporting emails](docs/EXPORTING_EMAILS.md) · [Spam logging design](docs/SPAM_LOGGING_PLAN.md)

## 🔐 Privacy & Security

- ✅ Runs entirely in your Google account
- ✅ No data sent to external servers
- ✅ Only accesses your Gmail (with your authorization)
- ✅ Open source - review all code
- ✅ Revoke access anytime at [Google Account Permissions](https://myaccount.google.com/permissions)

## 🧪 Testing with Real Emails

**Important:** `.eml` files only — PDFs create text extraction artifacts that cause 100% false positives.

Four ways to get emails out of Gmail:

| Method | Effort | Bulk? | Best for |
|--------|--------|-------|----------|
| Gmail web UI — ⋮ → "Download message" | Low | No | 1–20 emails |
| Google Takeout | Medium | Yes | 100+ emails |
| Gmail API + Python script | High | Yes | Automation |
| Thunderbird "Save As" | Low | No | Quick one-offs |

See **[docs/EXPORTING_EMAILS.md](docs/EXPORTING_EMAILS.md)** for step-by-step instructions on all four methods.

## 🎓 Why Pattern-Based Detection?

### What We Learned (The Hard Way)

**❌ Domain Blacklists** - Whack-a-mole game, spammers just register new domains

**❌ Keyword Matching** - Spammers easily evade ("inv3stment" vs "investment")

**❌ Complex Scoring** - Overfits to test data, creates anti-patterns

**✅ Behavioral Patterns** - Detects immutable characteristics of spam business model

### L6 Engineering Perspective

> "Spammers can change domains and wording, but they can't change their fundamental business model. Bulk email + clickbait = revenue. Detect that pattern." - L6 review

## 🚧 Limitations

- **Gmail API Quotas**: Limited daily operations
- **~1-minute delay**: Near real-time (trigger interval)
- **Pattern-based**: Won't catch 100% of all spam types
- **No ML**: Can't learn new patterns automatically

## 📈 Future Enhancements

- Detect new clickbait evolution
- Machine learning (when dataset > 1000 examples)
- Multi-platform support (Outlook, Yahoo)

## 🤝 Contributing

Found a spam pattern we're missing? Open an issue with:
- The `.eml` file (not PDF!)
- Why it's spam
- What signals it has

## 👩‍💻 Developer Setup

### Auto-Deploy Pipeline

This repo has CI/CD that auto-deploys to Google Apps Script on every push to `main`.

**Pipeline: test → deploy → validate → tag**
1. **Test** — six gates, all of which must pass:
   - JS syntax lint (Node `vm.Script`)
   - `tests/test_spam_detector.py` — spam/scam/ham corpus + edge cases
   - `tests/test_disposition.js` — quarantine-vs-delete routing, the only coverage of the code that irreversibly deletes mail
   - `tests/test_link_graph.js` — URL host parsing and Signal 7, against the shipped JS
   - `tests/test_patch_version.js` — the deploy-time version patch and `.claspignore` coverage
   - `scripts/validate.py` — version-marker agreement and README stat freshness
2. **Deploy** — Runs `clasp push` to Apps Script (only if tests pass). Writes failure summary on error.
3. **Validate** — Reads the deployed script back via the Apps Script REST API and confirms the expected `@version` tag is live. Warns but does not block on API errors.
4. **Tag** — Auto-creates a git tag when the commit message contains a version (`v6.18.0`, etc.)

**Setup for your own fork:**

1. Install clasp and login:
   ```bash
   npm install -g @google/clasp
   clasp login
   ```

2. Copy `.clasp.json.example` to `.clasp.json` and add your script ID:
   ```json
   {"scriptId": "YOUR_SCRIPT_ID_HERE", "rootDir": "."}
   ```

3. Enable Apps Script API at https://script.google.com/home/usersettings

4. Add GitHub secrets:
   - `SCRIPT_ID` - Your Apps Script project ID (from the URL)
   - `CLASP_TOKEN` - Contents of `~/.clasprc.json` after `clasp login`

**Manual deploy:**
```bash
clasp push
```

## 📝 License

MIT License - See `LICENSE` file

## 🙏 Acknowledgments

Built through iterative L6 engineering reviews focusing on:
- First principles thinking
- Avoiding anti-patterns
- Maintainable, clean code
- Real data validation (not PDFs!)

---

**Ready to kill spam?** Deploy `SpamDetector.gs` and let pattern detection do its work! 🚀
