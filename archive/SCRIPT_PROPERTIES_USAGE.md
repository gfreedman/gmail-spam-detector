# Script Properties Usage Guide

## Overview

The spam detector now uses **Script Properties** to store whitelist and blacklist domains instead of hardcoded arrays. This means you can add/remove domains WITHOUT editing code or redeploying!

---

## Benefits

✅ **No code changes needed** - Add domains without editing SpamDetector.gs
✅ **No redeployment** - Changes take effect on next run (within 15 minutes)
✅ **Safer** - Can't accidentally break the code
✅ **Audit trail** - Can view/track changes in execution logs
✅ **Proper architecture** - Configuration separated from logic

---

## Initial Setup

### First Time Only

1. **Deploy the updated SpamDetector.gs** to Google Apps Script
2. **Run the `setup()` function**
   - Select `setup` from function dropdown
   - Click Run
   - This initializes Script Properties with default whitelist/blacklist

3. **Verify initialization**
   - Check Execution log
   - Should see: "Initialized whitelist with 12 domains"
   - Should see: "Initialized blacklist with 6 domains"

---

## Managing the Whitelist

### View Current Whitelist

1. Select `viewWhitelist` from function dropdown
2. Click Run
3. Check Execution log - you'll see all whitelisted domains

Example output:
```
=== WHITELIST (12 domains) ===
  - sardine.ai
  - meetup.com
  - substack.com
  - conservative.ca
  - sundaymass.store
  - customerservice@stan
  - privaterelay.appleid.com
  - email.meetup.com
  - ben-evans.com
  - linkedin.com
  - dsf.ca
  - dragonfly
```

### Add a Domain to Whitelist

**When to use**: You found a legitimate email in your Spam folder

1. **Note the sender domain** (e.g., "newsletter.example.com")

2. **In Google Apps Script**:
   - At the top of the editor, find the function call area
   - Type: `addToWhitelist('example.com')`
   - Or use the full email if you want exact matching: `addToWhitelist('newsletter@example.com')`

3. **Run it**:
   - Select `addToWhitelist` from dropdown
   - Click Run

4. **Check the log**:
   ```
   Added to whitelist: example.com
   Whitelist now has 13 domains
   ```

**Alternative method**:
```javascript
// You can also call it directly in the editor
function addMyDomain() {
  addToWhitelist('example.com');
}
```
Then run `addMyDomain`

### Remove a Domain from Whitelist

**When to use**: You accidentally whitelisted something

1. Select `removeFromWhitelist` from dropdown
2. Modify the function call: `removeFromWhitelist('example.com')`
3. Click Run

---

## Managing the Blacklist

### View Current Blacklist

1. Select `viewBlacklist` from function dropdown
2. Click Run
3. Check Execution log

Example output:
```
=== BLACKLIST (6 domains) ===
  - financeinsiderpro.com
  - financebuzz
  - smartinvestmenttools
  - investorplace
  - weissratings
  - americanprofitinsight.com
```

### Add a Domain to Blacklist

**When to use**: You found spam that wasn't caught

1. **Note the spam sender domain** (e.g., "spammer.com")

2. **In Google Apps Script**:
   - Type: `addToBlacklist('spammer.com')`
   - Or partial match: `addToBlacklist('spam')`  (catches spam.com, spammer.com, etc.)

3. **Run it**:
   - Select `addToBlacklist` from dropdown
   - Click Run

4. **Check the log**:
   ```
   Added to blacklist: spammer.com
   Blacklist now has 7 domains
   ```

### Remove a Domain from Blacklist

1. Select `removeFromBlacklist` from dropdown
2. Modify: `removeFromBlacklist('example.com')`
3. Click Run

---

## Quick Reference

### Available Functions

| Function | Purpose | Example |
|----------|---------|---------|
| `viewWhitelist()` | Show all whitelisted domains | - |
| `viewBlacklist()` | Show all blacklisted domains | - |
| `addToWhitelist(domain)` | Add legitimate domain | `addToWhitelist('gmail.com')` |
| `addToBlacklist(domain)` | Add spam domain | `addToBlacklist('spammer.com')` |
| `removeFromWhitelist(domain)` | Remove from whitelist | `removeFromWhitelist('example.com')` |
| `removeFromBlacklist(domain)` | Remove from blacklist | `removeFromBlacklist('example.com')` |

---

## Common Workflows

### Workflow 1: Found Legitimate Email in Spam

1. Open the email in Gmail Spam folder
2. Note the sender (e.g., "support@company.com")
3. Extract the domain: "company.com"
4. In Apps Script: `addToWhitelist('company.com')`
5. Run the function
6. Move the email back to inbox manually (or wait - future emails will stay in inbox)

### Workflow 2: Found Spam in Inbox

1. Open the spam email
2. Note the sender domain (e.g., "scam123.com")
3. In Apps Script: `addToBlacklist('scam123.com')`
4. Run the function
5. Move to spam manually (or wait - future emails will auto-move)

### Workflow 3: Bulk Add Multiple Domains

Create a helper function:

```javascript
function addMultipleDomains() {
  // Whitelist
  addToWhitelist('example1.com');
  addToWhitelist('example2.com');
  addToWhitelist('example3.com');

  // Blacklist
  addToBlacklist('spam1.com');
  addToBlacklist('spam2.com');

  logInfo('Done adding domains');
}
```

Then run `addMultipleDomains`

---

## How It Works (Technical)

### Storage

Script Properties stores data as JSON strings:

```javascript
// Stored in Script Properties as:
{
  "LEGITIMATE_DOMAINS": "[\"sardine.ai\",\"meetup.com\",\"substack.com\"]",
  "SUSPICIOUS_DOMAINS": "[\"financeinsiderpro.com\",\"financebuzz\"]"
}
```

### Runtime

When `processInbox()` runs:
1. Calls `getWhitelist()` - loads from Script Properties
2. Calls `getBlacklist()` - loads from Script Properties
3. Uses fresh data (no code changes needed!)

### Performance

- Script Properties are fast (< 10ms to read)
- Loaded once per email batch (not per email)
- No performance impact vs hardcoded arrays

---

## Troubleshooting

### "Script Properties not initialized"

**Fix**: Run `setup()` function once

### "Domain already in whitelist"

This is normal - the function prevents duplicates. No action needed.

### "Changes not taking effect"

1. **Check the 15-minute schedule** - wait for next trigger run
2. **Verify you ran the function** - check Execution log
3. **Manually run `processInbox()`** to test immediately

### "How do I reset to defaults?"

```javascript
function resetToDefaults() {
  const props = PropertiesService.getScriptProperties();
  props.deleteAllProperties();  // Clear everything
  initializeScriptProperties();  // Reload defaults
  logInfo('Reset to defaults');
}
```

---

## Migration Notes

### Old Way (Hardcoded Arrays - BEFORE)

```javascript
legitimateDomains: Object.freeze([
  'sardine.ai', 'meetup.com'  // Had to edit code
]),
```

**To add a domain:**
1. Edit SpamDetector.gs
2. Add domain to array
3. Save
4. Redeploy
5. Hope you didn't break anything

### New Way (Script Properties - NOW)

**To add a domain:**
1. Run `addToWhitelist('example.com')`
2. Done!

---

## Best Practices

✅ **DO**: View whitelist/blacklist occasionally to review
✅ **DO**: Use partial matches for flexibility (`customerservice@` catches all customer service emails)
✅ **DO**: Test with `viewWhitelist()` after adding to confirm
✅ **DO**: Keep a backup list of your custom domains somewhere

❌ **DON'T**: Add wildcards (not supported - use partial strings instead)
❌ **DON'T**: Edit Script Properties manually (use the functions)
❌ **DON'T**: Add too many domains (keep it manageable - aim for < 50 each)

---

## Next Steps

1. ✅ **Deploy updated SpamDetector.gs**
2. ✅ **Run `setup()` to initialize**
3. ✅ **Run `viewWhitelist()` to verify**
4. ✅ **Monitor for a few days**
5. ✅ **Add domains as needed** using the functions

You now have a proper, maintainable configuration system! 🎉
