# How to Export Real Emails from Gmail

This guide shows you how to export actual email files (.eml format) from Gmail instead of PDFs. Real email files preserve the original structure, headers, and formatting, making them much better for testing spam detection.

---

## Why Export Real Emails?

**Problems with PDFs:**
- ❌ Text extraction creates artifacts (Unicode ligatures, malformed headers)
- ❌ Doesn't preserve original email structure
- ❌ Causes false positives in testing (100% false positive rate!)

**Benefits of .eml files:**
- ✅ Preserves original email headers
- ✅ No text extraction artifacts
- ✅ Can be tested with actual email libraries
- ✅ Shows real spam patterns, not PDF bugs

---

## Method 1: Gmail Web Interface (Easiest)

### For Individual Emails

1. **Open Gmail** in your browser
2. **Open the email** you want to export
3. **Click the three dots** (⋮) in the top right
4. **Select "Download message"**
5. The email downloads as a `.eml` file
6. Save it to `spam_examples/` or `ham_examples/`

### Limitations
- One email at a time
- Manual process
- Good for small datasets (10-20 emails)

---

## Method 2: Google Takeout (For Bulk Export)

### Steps

1. **Go to [Google Takeout](https://takeout.google.com/)**

2. **Deselect all** products (click "Deselect all")

3. **Select only "Mail"**
   - Click on "Mail"
   - Click "All Mail data included"
   - **Deselect "Include all messages in Mail"**
   - Select specific labels:
     - Select "Spam" (for spam examples)
     - Select "Inbox" (for ham examples if you have false positives)

4. **Choose file type**
   - Under "Multiple formats", select **.mbox** format
   - .mbox is a standard email format that can be easily parsed

5. **Click "Next step"**

6. **Choose delivery method**
   - "Send download link via email" (recommended)
   - File size: Choose appropriate (2GB is fine)
   - Click "Create export"

7. **Wait for email**
   - Google will email you when ready (usually 10 minutes to few hours)

8. **Download and extract**
   - Click link in email
   - Download the .zip file
   - Extract it

---

## Method 3: Gmail API with Python (Advanced)

### Setup

```bash
pip install google-api-python-client google-auth-httplib2 google-auth-oauthlib
```

### Python Script

```python
#!/usr/bin/env python3
"""
Export emails from Gmail using Gmail API
"""

import os
import base64
from pathlib import Path
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# Scopes needed
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def authenticate():
    """Authenticate with Gmail API"""
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)

        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return build('gmail', 'v1', credentials=creds)

def export_emails(service, query, output_dir, max_results=50):
    """
    Export emails matching query to .eml files

    Args:
        service: Gmail API service
        query: Gmail search query (e.g., 'in:spam', 'from:example.com')
        output_dir: Directory to save .eml files
        max_results: Maximum number of emails to export
    """
    output_path = Path(output_dir)
    output_path.mkdir(exist_ok=True)

    # Search for messages
    results = service.users().messages().list(
        userId='me', q=query, maxResults=max_results
    ).execute()

    messages = results.get('messages', [])

    if not messages:
        print(f'No messages found for query: {query}')
        return

    print(f'Found {len(messages)} messages')

    for i, msg in enumerate(messages):
        # Get full message
        message = service.users().messages().get(
            userId='me', id=msg['id'], format='raw'
        ).execute()

        # Decode message
        msg_str = base64.urlsafe_b64decode(message['raw']).decode('utf-8')

        # Extract subject for filename
        subject = 'Unknown'
        for line in msg_str.split('\n'):
            if line.lower().startswith('subject:'):
                subject = line[8:].strip()[:50]  # First 50 chars
                # Clean filename
                subject = ''.join(c for c in subject if c.isalnum() or c in (' ', '-', '_'))
                break

        # Save to .eml file
        filename = f'{i+1:03d}_{subject}.eml'
        filepath = output_path / filename

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(msg_str)

        print(f'Saved: {filename}')

    print(f'\\nExported {len(messages)} emails to {output_dir}/')

if __name__ == '__main__':
    # Authenticate
    service = authenticate()

    # Export spam examples
    print('\\n=== Exporting SPAM examples ===')
    export_emails(service, 'in:spam', 'spam_examples_real', max_results=50)

    # Export ham examples (inbox, not spam)
    print('\\n=== Exporting HAM examples ===')
    export_emails(service, 'in:inbox -in:spam', 'ham_examples_real', max_results=50)
```

### Setup Gmail API

1. **Go to [Google Cloud Console](https://console.cloud.google.com/)**

2. **Create a project** (or select existing)

3. **Enable Gmail API**:
   - Go to "APIs & Services" → "Library"
   - Search for "Gmail API"
   - Click "Enable"

4. **Create credentials**:
   - Go to "APIs & Services" → "Credentials"
   - Click "Create Credentials" → "OAuth client ID"
   - Application type: "Desktop app"
   - Download JSON, save as `credentials.json`

5. **Run the script**:
   ```bash
   python export_emails.py
   ```
   - First run will open browser for authorization
   - Emails will be saved to `spam_examples_real/` and `ham_examples_real/`

---

## Method 4: Thunderbird/Outlook (Desktop Client)

### Using Thunderbird

1. **Install Thunderbird**
2. **Add your Gmail account**
3. **Wait for emails to sync**
4. **Right-click on email** → **Save As** → Choose `.eml` format
5. Repeat for each email you want to export

### Using Outlook (Mac/Windows)

1. **Open Outlook**
2. **Add Gmail account**
3. **Select email**
4. **File** → **Save As** → Choose "Outlook Message Format (.msg)"
   - Note: .msg files need conversion to .eml for Python parsing

---

## Recommended Approach

**For this project, I recommend:**

### Step 1: Use Gmail Web Interface (Quick)
- Download 10 spam emails and 10 ham emails manually
- Save to `spam_examples_real/` and `ham_examples_real/`
- Good enough for initial testing

### Step 2: Test with Real Emails
- Update `test_spam_detector.py` to parse .eml files instead of PDFs
- Re-run analysis to see true detection rates

### Step 3: Iterate
- Add more emails as needed
- Update whitelist/blacklist based on REAL results (not PDF artifacts)

---

## Parsing .eml Files in Python

Update `test_spam_detector.py` to use Python's email library:

```python
import email
from email import policy

def extract_email_from_eml(eml_path):
    """Extract email data from .eml file"""
    with open(eml_path, 'rb') as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    return EmailData(
        filename=Path(eml_path).name,
        subject=msg.get('subject', ''),
        sender=msg.get('from', ''),
        date=msg.get('date', ''),
        body_text=msg.get_body(preferencelist=('plain',)).get_content() if msg.get_body(preferencelist=('plain',)) else '',
        body_html=msg.get_body(preferencelist=('html',)).get_content() if msg.get_body(preferencelist=('html',)) else ''
    )
```

---

## Summary

| Method | Effort | Bulk Export | Best For |
|--------|--------|-------------|----------|
| Gmail Web UI | Low | No | 10-20 emails |
| Google Takeout | Medium | Yes | 100+ emails |
| Gmail API (Python) | High | Yes | Automation, large datasets |
| Thunderbird | Low | No | Quick exports |

**Recommended**: Start with Gmail Web UI (Method 1) to get 10-20 real emails, then test. This will immediately show if your spam detector works on real emails vs PDFs.

---

## Next Steps

1. **Export 10 spam + 10 ham emails** using Gmail Web UI
2. **Create new directories**: `spam_examples_real/` and `ham_examples_real/`
3. **Update test script** to parse .eml files
4. **Re-run tests** to see true detection rate
5. **Update whitelist/blacklist** based on real results

This will give you a **clean, artifact-free dataset** for proper testing!
