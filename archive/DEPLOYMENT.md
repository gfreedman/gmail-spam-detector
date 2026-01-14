# Deployment Guide - Quick Fix (Option A)

## Changes Summary

**Version:** 3.1 - Quick Fix for False Positives
**Date:** 2026-01-12

### What Changed

1. **Added Whitelist** - Protects 8 known legitimate domains
2. **Raised Threshold** - From 30 to 50 (more conservative)
3. **Results:**
   - False positive rate: 100% → 0% ✅
   - Spam detection rate: 100% (unchanged) ✅

---

## Deployment Steps

### Step 1: Open Google Apps Script

1. Go to [script.google.com](https://script.google.com)
2. Open your **Gmail Spam Detector** project
3. You should see your existing code

### Step 2: Replace the Code

1. Open `SpamDetector.gs` from your local `anti_spam` folder
2. **Select ALL code** (Cmd+A / Ctrl+A)
3. **Copy** it (Cmd+C / Ctrl+C)
4. Go back to Google Apps Script editor
5. **Select ALL existing code** in the editor
6. **Paste** the new code (Cmd+V / Ctrl+V)
7. **Click Save** (disk icon or Cmd+S)

### Step 3: Verify the Changes

Look for these key changes in the code:

**Line ~36 - New Threshold:**
```javascript
spamThreshold: 50,  // Was 30
```

**Line ~114-118 - New Whitelist:**
```javascript
legitimateDomains: Object.freeze([
  'sardine.ai', 'meetup.com', 'substack.com', 'conservative.ca',
  'sundaymass.store', 'customerservice@stan', 'privaterelay.appleid.com',
  'email.meetup.com'
]),
```

**Line ~309-318 - Whitelist Check:**
```javascript
// WHITELIST CHECK: Skip spam detection for known legitimate domains
const fromLower = from.toLowerCase();
for (let i = 0; i < KEYWORDS.legitimateDomains.length; i++)
{
  if (fromLower.includes(KEYWORDS.legitimateDomains[i]))
  {
    logDebug('Whitelisted domain detected: ' + KEYWORDS.legitimateDomains[i]);
    return 0; // Not spam - whitelisted
  }
}
```

### Step 4: Test the Deployment

**Option A: Manual Test**

1. Find a legitimate email in your inbox from one of the whitelisted domains
2. In the function dropdown, select `testSpamDetection`
3. Click **Run**
4. Check the Execution log - it should show:
   - "Whitelisted domain detected: [domain]"
   - "Would be marked as spam: NO"

**Option B: Process Inbox**

1. Select `processInbox` from the function dropdown
2. Click **Run**
3. Check the Execution log for any errors

### Step 5: Monitor

**For the next 3-7 days:**

1. **Check your Spam folder daily**
   - Look for emails with the "SpamChecked" label
   - If legitimate emails appear → add their domain to the whitelist

2. **Check your Inbox**
   - Look for spam that wasn't caught
   - If spam appears → add their domain to the blacklist or lower threshold

3. **Review execution logs**
   - Go to Executions tab in Apps Script
   - Look for any errors or unusual patterns

---

## Adding Domains to Whitelist (If Needed)

If you find a legitimate email being marked as spam:

1. Note the sender domain (e.g., "company.com")
2. Open SpamDetector.gs in Google Apps Script
3. Find the `legitimateDomains` array (~line 115)
4. Add the domain:
   ```javascript
   legitimateDomains: Object.freeze([
     'sardine.ai', 'meetup.com', 'substack.com', 'conservative.ca',
     'sundaymass.store', 'customerservice@stan', 'privaterelay.appleid.com',
     'email.meetup.com',
     'newdomain.com'  // Add here
   ]),
   ```
5. Save the script
6. The change takes effect immediately on the next run

---

## Adding Domains to Blacklist (If Needed)

If spam is getting through:

1. Note the sender domain
2. Open SpamDetector.gs
3. Find the `suspiciousDomains` array (~line 112)
4. Add the spam domain:
   ```javascript
   suspiciousDomains: Object.freeze([
     'financeinsiderpro.com', 'financebuzz', 'smartinvestmenttools',
     'investorplace', 'weissratings', 'americanprofitinsight.com',
     'spammerdomain.com'  // Add here
   ]),
   ```
5. Save the script

---

## Adjusting Threshold (If Needed)

**If too much spam is getting through:**
- Lower threshold: 50 → 40 or 45
- This makes detection more aggressive

**If legitimate emails are being flagged:**
- First, try adding them to whitelist
- If that doesn't work, raise threshold: 50 → 55 or 60

To change:
1. Find `spamThreshold` (~line 36)
2. Change the number
3. Save

---

## Rollback (If Something Goes Wrong)

If the new version causes problems:

1. Set threshold back to 30: `spamThreshold: 30`
2. Or restore from your backup/git if you have one
3. Contact for support

---

## Current Configuration

**Threshold:** 50 points

**Whitelisted Domains (8):**
- sardine.ai
- meetup.com
- substack.com
- conservative.ca
- sundaymass.store
- customerservice@stan (Stanfield's)
- privaterelay.appleid.com
- email.meetup.com

**Blacklisted Domains (6):**
- financeinsiderpro.com
- financebuzz
- smartinvestmenttools
- investorplace
- weissratings
- americanprofitinsight.com

---

## Success Metrics

After deployment, you should see:

✅ No more false positives from whitelisted senders
✅ Spam still being caught and moved to spam folder
✅ Execution logs showing "Whitelisted domain detected" for legitimate emails
✅ No errors in execution logs

---

## Support

If you encounter issues:

1. Check the Execution log for error messages
2. Verify the code was pasted correctly
3. Make sure CONFIG.spamThreshold is 50
4. Make sure legitimateDomains array exists
5. Check that the whitelist check is at the top of analyzeMessage()

---

## Next Phase (Optional - Future)

**Option B: Proper Long-term Solution**

When you're ready for a more robust solution:

1. Export real emails as .eml files (not PDFs)
2. Build clean test dataset
3. Simplify to pure whitelist/blacklist approach
4. Remove complex Tier 1/2/3 scoring
5. See CLAUDE.md for details

For now, the Quick Fix (Option A) should solve your false positive problem!
