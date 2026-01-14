# Testing Checklist for Script Properties Implementation

## ⚠️ Important: Cannot Test Locally

**Google Apps Script functions cannot be tested outside the Google Apps Script environment.** This means:
- ❌ Cannot run locally in terminal
- ❌ Cannot unit test with standard JS tools
- ✅ Must test in script.google.com after deployment

---

## Pre-Deployment Checks ✅

These I've verified:

### 1. Code Structure
- ✅ `legitimateDomains_DEFAULT` exists and has 12 domains
- ✅ `suspiciousDomains_DEFAULT` exists and has 6 domains
- ✅ `getWhitelist()` function defined
- ✅ `getBlacklist()` function defined
- ✅ `analyzeMessage()` calls `getWhitelist()`
- ✅ `analyzeSender()` calls `getBlacklist()`
- ✅ All 9 management functions defined

### 2. Logic Flow
- ✅ `setup()` calls `initializeScriptProperties()`
- ✅ `initializeScriptProperties()` copies defaults to Script Properties
- ✅ Whitelist check happens BEFORE scoring
- ✅ Returns 0 (not spam) if whitelisted

### 3. Syntax
- ✅ File is 1139 lines (complete)
- ✅ No obvious syntax errors
- ✅ Allman bracing maintained

---

## Post-Deployment Tests (YOU MUST DO)

After deploying to script.google.com, test these:

### Test 1: Initial Setup

**Run:** `setup()`

**Expected in Execution Log:**
```
[INFO] Setting up spam detector...
[INFO] Initialized whitelist with 12 domains
[INFO] Initialized blacklist with 6 domains
[INFO] Setup complete!
```

**If you see errors:** Something wrong with Script Properties initialization

---

### Test 2: View Whitelist

**Run:** `viewWhitelist()`

**Expected in Execution Log:**
```
[INFO] === WHITELIST (12 domains) ===
[INFO]   - sardine.ai
[INFO]   - meetup.com
[INFO]   - substack.com
[INFO]   - conservative.ca
[INFO]   - sundaymass.store
[INFO]   - customerservice@stan
[INFO]   - privaterelay.appleid.com
[INFO]   - email.meetup.com
[INFO]   - ben-evans.com
[INFO]   - linkedin.com
[INFO]   - dsf.ca
[INFO]   - dragonfly
```

**If different:** Initialization didn't work

---

### Test 3: Add to Whitelist

**Method 1: Direct call**
1. In Apps Script, at top of code, add:
```javascript
function testAdd() {
  addToWhitelist('test.com');
}
```
2. Select `testAdd` from dropdown
3. Run it

**Expected in Log:**
```
[INFO] Added to whitelist: test.com
[INFO] Whitelist now has 13 domains
```

**Method 2: Run `viewWhitelist()` again**
- Should now show 13 domains including test.com

---

### Test 4: Duplicate Detection

**Run:** Same `testAdd()` again

**Expected:**
```
[INFO] Domain already in whitelist: test.com
```

(Count should stay 13, not increment to 14)

---

### Test 5: Remove from Whitelist

**Add this function:**
```javascript
function testRemove() {
  removeFromWhitelist('test.com');
}
```

**Run:** `testRemove()`

**Expected:**
```
[INFO] Removed from whitelist: test.com
```

**Verify:** Run `viewWhitelist()` - should be back to 12 domains

---

### Test 6: Blacklist Functions

Same tests but with blacklist:

**Run:** `viewBlacklist()`
**Expected:** 6 domains

**Add test:**
```javascript
function testBlacklist() {
  addToBlacklist('spammer.com');
  viewBlacklist();
  removeFromBlacklist('spammer.com');
}
```

---

### Test 7: Runtime Integration

**Most Important Test!**

1. Find a legitimate email in inbox from a whitelisted domain (e.g., from LinkedIn)
2. Remove "SpamChecked" label if it has one
3. Run `processInbox()`

**Expected in Log:**
```
[INFO] Search query: in:inbox -label:SpamChecked after:YYYY/MM/DD
[INFO] Found 1 threads to process
[DEBUG] Whitelisted domain detected: linkedin.com
[INFO] Completed in XXXms: Processed 1 emails, marked 0 as spam
```

**Key:** Should say "Whitelisted domain detected" and NOT mark as spam

---

### Test 8: Blacklist Integration

1. Create a test function to check scoring:
```javascript
function testBlacklistScoring() {
  const service = PropertiesService.getScriptProperties();
  const blacklist = JSON.parse(service.getProperty('SUSPICIOUS_DOMAINS'));

  logInfo('Blacklist has ' + blacklist.length + ' domains');

  // Test if it includes our defaults
  logInfo('Contains financebuzz: ' + blacklist.includes('financebuzz'));
  logInfo('Contains smartinvestmenttools: ' + blacklist.includes('smartinvestmenttools'));
}
```

2. Run it

**Expected:**
```
[INFO] Blacklist has 6 domains
[INFO] Contains financebuzz: true
[INFO] Contains smartinvestmenttools: true
```

---

### Test 9: Persistence

1. Add a test domain: `addToWhitelist('persistence-test.com')`
2. **Close the browser tab**
3. **Reopen script.google.com** and open your project
4. Run `viewWhitelist()`

**Expected:** Should still see `persistence-test.com` in the list

**Why this matters:** Proves data survives between sessions

---

### Test 10: End-to-End

**Setup:**
1. Have a real spam email in inbox (or move one from spam to inbox)
2. Remove "SpamChecked" label if exists

**Run:** `processInbox()`

**Expected:**
- If sender is NOT whitelisted AND scores >= 50: Moved to spam
- If sender IS whitelisted: Stays in inbox
- Check the logs to verify the logic

---

## Known Limitations (Not Bugs)

1. **Script Properties limit**: 500KB total, 9KB per property
   - Our usage: ~1KB (plenty of room)
   - Can store ~5000 domains before hitting limit

2. **No validation**: Functions don't validate if domain is real
   - You can add 'asdfjkl' and it will accept it
   - This is OK - you control the input

3. **Case sensitive storage**: Domains stored as you type them
   - But matching is case-insensitive (uses `.toLowerCase()`)
   - This is OK - matching works correctly

4. **No wildcards**: Can't use `*.example.com`
   - Use partial matches instead: `example.com`
   - This catches mail.example.com, support.example.com, etc.

---

## Rollback Plan (If Tests Fail)

If something breaks:

### Option 1: Keep old code handy
Before deploying, save current SpamDetector.gs to a backup file

### Option 2: Remove Script Properties
```javascript
function clearScriptProperties() {
  PropertiesService.getScriptProperties().deleteAllProperties();
}
```

### Option 3: Reset to defaults
```javascript
function resetToDefaults() {
  const props = PropertiesService.getScriptProperties();
  props.deleteAllProperties();
  initializeScriptProperties();
}
```

---

## Success Criteria

All tests pass AND:
- ✅ Can add domains without editing code
- ✅ Can remove domains without editing code
- ✅ Changes persist between runs
- ✅ Whitelist prevents spam detection
- ✅ Blacklist increases spam score
- ✅ No errors in execution logs

---

## What I Cannot Test (Limitations)

Because Google Apps Script runs in Google's cloud:
- ❌ Cannot run unit tests locally
- ❌ Cannot use standard JS testing frameworks (Jest, Mocha)
- ❌ Cannot verify Script Properties API without deploying
- ❌ Cannot test Gmail integration without real Gmail account

**Therefore:** You MUST test in the actual environment after deployment.

---

## My Confidence Level

### High Confidence (90%+)

These should work:
- ✅ Basic function structure
- ✅ Script Properties API usage (standard Google API)
- ✅ JSON stringify/parse logic
- ✅ Array operations (add, remove, includes)

### Medium Confidence (70%)

Potential issues:
- ⚠️ Script Properties initialization timing
- ⚠️ Property key naming (typos could break it)
- ⚠️ JSON parsing edge cases

### Needs Testing

Cannot verify without deployment:
- ❓ Performance impact of getWhitelist() calls
- ❓ Integration with analyzeMessage flow
- ❓ Error handling if Script Properties fails

---

## What To Do If Tests Fail

### If `setup()` fails:
- Check error message
- Verify PropertiesService is available
- Try running `initializeScriptProperties()` directly

### If whitelist not loading:
- Run this debug function:
```javascript
function debugScriptProperties() {
  const props = PropertiesService.getScriptProperties();
  const all = props.getProperties();
  logInfo('All properties: ' + JSON.stringify(all));
}
```

### If domains not matching:
- Check case sensitivity
- Check for extra spaces
- Verify the domain is actually in the email From field

---

## Timeline

1. **Deploy** (5 minutes)
2. **Run Tests 1-6** (10 minutes)
3. **Run Tests 7-9** (5 minutes with real emails)
4. **Monitor** (24-48 hours in production)
5. **Iterate** (add domains as needed)

---

## Bottom Line

**I'm 90% confident the code is correct**, but Google Apps Script MUST be tested in the actual environment. Follow this checklist after deployment to verify everything works.

If any test fails, refer to the rollback plan or the debug functions above.

Ready to deploy and test! 🚀
