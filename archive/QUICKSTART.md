# Quick Start Guide

## 5-Minute Setup

### Test Locally First

```bash
# 1. Setup Python environment
bash setup_test_env.sh

# 2. Activate environment
source venv/bin/activate

# 3. Run tests
python test_spam_detector.py

# 4. Compare thresholds
bash compare_thresholds.sh
```

**Result**: You'll see how well the spam detector works on 70 real spam examples.

### Deploy to Gmail

```
1. Go to script.google.com
2. New Project
3. Copy SpamDetector.gs into editor
4. Run setup() function (authorize permissions)
5. Add trigger: processInbox, every 15 minutes
```

**Result**: Gmail will automatically filter spam every 15 minutes.

## Important First Steps

### ⚠️ Adjust the Threshold

The default threshold (60) is **too conservative** for the example spam dataset.

**Recommended**: Change to 50 in `SpamDetector.gs`:

```javascript
const CONFIG = Object.freeze({
  spamThreshold: 50,  // Changed from 60
  // ...
});
```

### 📊 Why?

Test results show:
- Threshold 60: Only catches 10% of spam (7/70)
- Threshold 50: Catches 18.6% of spam (13/70)
- Threshold 40: Catches 42.9% of spam (30/70)

## Files You Need

### For Gmail
- `SpamDetector.gs` - Copy this to Google Apps Script

### For Testing
- `test_spam_detector.py` - Main test script
- `setup_test_env.sh` - Run once to setup
- `compare_thresholds.sh` - Find optimal threshold

### Documentation
- `README.md` - Full setup guide
- `TESTING.md` - Testing documentation
- `SUMMARY.md` - Project overview
- `QUICKSTART.md` - This file

## Common Commands

```bash
# Setup (run once)
bash setup_test_env.sh

# Activate environment (run before testing)
source venv/bin/activate

# Basic test
python test_spam_detector.py

# Test with threshold 50
python test_spam_detector.py --threshold 50

# Verbose mode (shows matched keywords)
python test_spam_detector.py --verbose

# Compare all thresholds
bash compare_thresholds.sh

# Deactivate when done
deactivate
```

## What to Expect

### Test Output Shows

```
SPAM SCORE: 58/100 [OK]
Threshold: 60
--------------------------------------------------------------------------------
Subject Score:   10   <- Points from subject
Sender Score:    15   <- Points from sender
Body Score:      18   <- Points from body
Links Score:      0   <- Points from links
Unicode Score:   15   <- Points from Unicode tricks
--------------------------------------------------------------------------------
Score Breakdown:
  • [SUBJECT] Sensationalist keywords: breaking news (+10)
  • [SENDER] Suspicious domain: smartinvestmenttools (+15)
  • [BODY] Tech hype keywords (3): tesla, self-driving, ai takeover... (+18)
  • [UNICODE] Unicode obfuscation (cyrillic) (+15)
```

This tells you **exactly why** each email got its score!

### Summary Statistics

```
Total analyzed:     70
Marked as SPAM:     7 (10.0%)
Marked as OK:       63 (90.0%)

Score Distribution:
   30- 39: ███████████████ (15)
   40- 49: █████████████████ (17)
   50- 59: ██████ (6)
   60- 69: ████ (4)  <- Only these marked as spam
```

## Next Steps

1. ✅ **Run the tests** to see current detection rate
2. ✅ **Lower the threshold** to 50 (or 45) in SpamDetector.gs
3. ✅ **Deploy to Gmail** via Google Apps Script
4. ✅ **Monitor your spam folder** for a week
5. ✅ **Tune as needed** based on false positives

## Help

- Full setup: See `README.md`
- Testing guide: See `TESTING.md`
- Project overview: See `SUMMARY.md`
- Dataset info: See `CLAUDE.md`

## One-Liner Workflow

```bash
# Test and deploy workflow
bash setup_test_env.sh && \
source venv/bin/activate && \
python test_spam_detector.py --threshold 50 && \
echo "Now copy SpamDetector.gs to script.google.com"
```

**Happy spam filtering! 🎯**
