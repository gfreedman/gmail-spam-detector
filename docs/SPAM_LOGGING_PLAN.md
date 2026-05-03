# Spam Intelligence Logging Plan

**Status:** Approved for implementation  
**Release scope:** Logging only — EML archive + Google Sheets log  
**Last updated:** 2026-05-03

---

## 1. Scope

This release does one thing: **preserve every spam event as evidence**.

**In scope:**
- Automatically log each spam detection to Google Drive (EML) + Google Sheets (structured row)
- Manually log false negatives — spam the script missed — via a Gmail label workflow, with a notes column for why it was missed

**Explicitly deferred:**
- Header parsing (originating IP, SPF/DKIM/DMARC, ESP fingerprinting)
- Domain intelligence / campaign clustering analysis
- Reporting pathways (SpamCop, FTC, ESP abuse teams)
- Automated weekly digest
- IOC extraction
- Attribution work

The goal is: capture everything now, analyze and act later.

---

## 2. Architecture

### 2.1 Detected Spam (Automatic)

```
processThread()
  ├─ [NEW] accumulateLogEntry() — called BEFORE markAsSpam(), captures rawContent
  └─ markAsSpam()
       ├─ [existing] Gmail.Users.Messages.modify()   — move to spam folder
       └─ [existing] Gmail.Users.Messages.batchDelete()  — permanent delete
```

### 2.2 False Negatives (Semi-Manual)

User labels an escaped spam email with the Gmail label **`SpamMissed`**. On each script run (same trigger as the main loop), the script checks for that label, logs the email to Drive and Sheets, then removes the label.

```
checkFalseNegatives()   — runs after detection loop, before flushSpamLog()
  ├─ GmailApp.search("label:SpamMissed")
  └─ for each found:
       ├─ accumulateLogEntry()  — Log Type = FALSE_NEGATIVE
       ├─ thread.removeLabel(spamMissedLabel)
       └─ markAsSpam()  — log + delete, same path as auto-detected spam
```

### 2.3 Non-Blocking Guarantee

`accumulateLogEntry()` and `flushSpamLog()` are each wrapped in a top-level `try/catch`. Any Drive or Sheets failure writes to the Apps Script console and returns silently. **Neither ever throws, delays deletion, or affects the main detection flow.**

### 2.4 Batch Logging at End of Run

Rather than writing to Drive and Sheets per email mid-run, the script accumulates log entries in memory during the detection loop and flushes them all after all deletions are complete. This protects the 6-minute execution window and keeps Drive/Sheets API calls concentrated at the end of the run.

```
processInbox()
  ├─ [existing detection loop — accumulateLogEntry() + markAsSpam() per spam email]
  ├─ checkFalseNegatives()
  └─ flushSpamLog()
       ├─ Drive: one file write per EML (sequential)
       └─ Sheets: single setValues() call for all rows
```

---

## 3. Google Drive — EML Archive

### 3.1 Folder Structure

```
My Drive/
└─ Spam Intelligence/          ← dedicated folder created by setupLogging()
   ├─ Detected/
   │   └─ *.eml
   └─ False Negatives/
       └─ *.eml
```

`setupLogging()` creates `Spam Intelligence/` as a new top-level folder in My Drive. Detected spam and false negatives live in separate subtrees — makes it easy to export one set without the other.

### 3.2 File Naming Convention

```
{ISO-timestamp}_{message-id-hash8}.eml
```

Example: `2026-05-03T09-45-56Z_a3f9b21c.eml`

The sending domain is intentionally **excluded from the filename** — the From header is trivially spoofable and would fill the folder with files named `amazon.com_*.eml`. Domain information lives in the Sheets row where it can be searched and filtered reliably. The message ID hash provides uniqueness; the timestamp provides sortability.

### 3.3 What Gets Stored

`message.getRawContent()` — the full raw MIME message. This is a standards-compliant `.eml` file containing all headers, body parts, and attachments (within the existing 5MB cap). No modifications, no stripping — stored exactly as received, suitable for future forensic analysis.

**Chain of custody:** EMLs are written after the deletion decision is made but logged before `batchDelete()` removes the message. Do not edit files after storage.

### 3.4 Configuration

The Drive folder ID is stored in **Script Properties** under the key `SPAM_LOG_FOLDER_ID`. This follows the same pattern as `BLACKLIST_DOMAINS` and `WHITELIST_DOMAINS`. A `setupLogging()` function creates the folder structure and saves the ID on first run.

---

## 4. Google Sheets — Raw Log

### 4.1 Spreadsheet

A dedicated standalone spreadsheet: **"Spam Intelligence Log"**. The spreadsheet ID is stored in Script Properties under `SPAM_LOG_SHEET_ID`. Created by `setupLogging()` on first run.

One tab: **Raw Log** (append-only, one row per event).

### 4.2 Schema

| Col | Field | Type | Source | Notes |
|-----|-------|------|--------|-------|
| A | Detected At | ISO 8601 | `new Date().toISOString()` | When the script processed it |
| B | Log Type | Enum | Script | `SPAM_DETECTED` or `FALSE_NEGATIVE` |
| C | Gmail Message ID | String | `message.getId()` | Unique key |
| D | Gmail Thread ID | String | `thread.getId()` | |
| E | EML Drive URL | URL | DriveApp response | Direct link to `.eml` file |
| F | Subject | String | `message.getSubject()` | Sanitized (same 100KB cap) |
| G | From Display Name | String | Parsed from `message.getFrom()` | |
| H | From Address | String | Parsed from `message.getFrom()` | |
| I | Sending Domain | String | Extracted from From address | e.g. `1stamericanpath.com` |
| J | Reply-To Address | String | `message.getReplyTo()` | Mismatch with From = fraud signal |
| K | Rule Triggered | String | `makeVerdict()` | `Rule 1`–`Rule 5`, or `NONE` for false negatives |
| L | Rule Description | String | Detection log string | e.g. `Bulk email + blacklisted sender` |
| M | Clickbait Count | Integer | `signals.clickbaitCount` | `0` for false negatives |
| N | Signals Detected | String (CSV) | `signals` object | e.g. `BULK,BLACKLISTED,FEAR` |
| O | Bulk Email Service | Boolean | `signals.bulkEmailService` | |
| P | Has Attachment | Boolean | `message.getAttachments().length > 0` | |
| Q | List-Unsubscribe Present | Boolean | Header presence check | Absence = likely CAN-SPAM violation |
| R | False Negative Notes | String | **Manual** | Why the script missed it (false negatives only) |
| S | Notes | String | **Manual** | General free-form notes |

19 columns total. Columns R and S are blank on auto-detected spam — the user fills them in when reviewing false negatives.

---

## 5. False Negative Workflow

1. User finds a spam email that reached their inbox uncaught
2. User applies the Gmail label **`SpamMissed`** to the email (one click)
3. On the next script trigger (runs every few minutes), `checkFalseNegatives()` finds it
4. Script writes EML to `False Negatives/`, appends a Sheets row with `Log Type = FALSE_NEGATIVE`, `Rule Triggered = NONE`
5. Script removes the `SpamMissed` label, then permanently deletes the email via `batchDelete`
6. User opens the Sheets row, fills in Column R (False Negative Notes) explaining why it was missed — e.g. *"Only 1 clickbait pattern, needs 2 for Rule 2"* or *"Domain not yet blacklisted"*

The script **deletes false negative emails** after logging — same permanent deletion path as auto-detected spam (`batchDelete`). Logging and deletion happen together; the `SpamMissed` label is the user's trigger to both log and destroy the email.

---

## 6. Permissions

### 6.1 New OAuth Scopes Required

Two scopes need to be added to `appsscript.json`:

| Scope | Why |
|-------|-----|
| `https://www.googleapis.com/auth/drive` | Create folders and write EML files in Drive. `DriveApp.createFolder()` requires the full `drive` scope — `drive.file` is insufficient for folder creation. |
| `https://www.googleapis.com/auth/spreadsheets` | Create the log spreadsheet and append rows. |

`DriveApp` and `SpreadsheetApp` are both built-in Apps Script services — no additional Advanced Services entries needed in `appsscript.json`.

### 6.2 Updated `appsscript.json`

```json
{
  "timeZone": "America/New_York",
  "dependencies": {
    "enabledAdvancedServices": [
      {
        "userSymbol": "Gmail",
        "version": "v1",
        "serviceId": "gmail"
      }
    ]
  },
  "exceptionLogging": "STACKDRIVER",
  "runtimeVersion": "V8",
  "oauthScopes": [
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.labels",
    "https://www.googleapis.com/auth/script.external_request",
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/spreadsheets"
  ]
}
```

### 6.3 Authorization Flow

When the updated script runs for the first time after deploy, Apps Script will detect the new scopes and prompt the user to re-authorize. This is a one-time popup in the browser. Steps:

1. Deploy via CI (`clasp push`) as normal
2. Open the Apps Script editor (script.google.com)
3. Click **Run → checkSpam** (or any function)
4. A browser dialog appears: *"This app wants to access your Google Account"*
5. Review the two new permissions (Drive files, Sheets) and click **Allow**
6. Authorization is saved — no further prompts on subsequent runs

If the script is triggered automatically (time-based), the trigger will fail silently until the user manually authorizes. **Run `setupLogging()` manually from the editor after deploy to force the auth prompt and create the folder/sheet.**

### 6.4 `setupLogging()` Function

A one-time setup function that:
1. Triggers the OAuth authorization dialog for the new scopes
2. Creates the `Spam Intelligence/Detected/` and `Spam Intelligence/False Negatives/` folder hierarchy in Drive
3. Creates the `Spam Intelligence Log` spreadsheet with the correct headers in row 1
4. Creates the `SpamMissed` Gmail label if it doesn't exist
5. Saves the folder ID and spreadsheet ID to Script Properties (`SPAM_LOG_FOLDER_ID`, `SPAM_LOG_SHEET_ID`)

Must be run once manually from the Apps Script editor after first deploy of this feature.

---

## 7. Script Properties Configuration

| Key | Value | Set By |
|-----|-------|--------|
| `SPAM_LOG_FOLDER_ID` | Drive folder ID for `Spam Intelligence/` root | `setupLogging()` |
| `SPAM_LOG_SHEET_ID` | Spreadsheet ID for `Spam Intelligence Log` | `setupLogging()` |

Both are read on every script run via `PropertiesService.getScriptProperties()`. If either is missing (e.g. `setupLogging()` was never run), `flushSpamLog()` logs a warning and returns — it does not throw.

---

## 8. Implementation

### Phase 1 — Complete Logging (This Release)

| Task | Description |
|------|-------------|
| `setupLogging()` | One-time setup: create Drive folders, Sheets, SpamMissed label, save IDs to Script Properties |
| `accumulateLogEntry(message, signals, logType)` | Captures log entry (incl. rawContent) into in-memory buffer before deletion |
| `flushSpamLog()` | End-of-run flush: writes EMLs to Drive, appends all rows to Sheets in one setValues() call |
| `checkFalseNegatives()` | Scans for `SpamMissed` label, accumulates entries, removes label, deletes emails |
| Update `processThread()` | Call `accumulateLogEntry()` before `markAsSpam()` |
| Update `processInbox()` | Call `checkFalseNegatives()` + `flushSpamLog()` after detection loop |
| Update `appsscript.json` | Add Drive + Sheets scopes |
| Tests | Verify column count, filename format, non-blocking behavior, false negative workflow |

### Deferred to Future Releases

- Header parsing (originating IP, SPF/DKIM/DMARC, ESP identification)
- Domain Intelligence and Campaign Clusters Sheets tabs
- Automated weekly digest email
- Reporting workflow (SpamCop, FTC, ESP abuse)
- IOC extraction and STIX export
- Attribution confidence scoring

---

## 9. Decisions

| Question | Decision |
|----------|----------|
| Drive location | `setupLogging()` creates a new `Spam Intelligence/` folder at My Drive root |
| False negative deletion | Log + permanently delete via `batchDelete` — same path as auto-detected spam |
| Retroactive false negatives | None — logging starts from deploy date forward |
