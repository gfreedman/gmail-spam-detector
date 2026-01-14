# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Purpose

This is an anti-spam dataset repository containing a collection of real-world spam email examples. The repository serves as a resource for:
- Spam detection and classification research
- Training anti-spam machine learning models
- Analyzing spam email patterns and tactics
- Building defensive security tools for email filtering

## Data Structure

### spam_examples/
Contains approximately 70 PDF files, each representing a spam email converted to PDF format. These PDFs preserve:
- Email headers (From, Subject, Date, To)
- Email body content with original formatting
- Embedded images and links
- Footer disclaimers and unsubscribe information

### Spam Categories Observed
The spam examples cover various common spam types:
- **Investment scams**: Fake stock tips, cryptocurrency schemes, "insider" financial opportunities
- **Credit card offers**: Amazon/Prime card promotions with misleading bonus claims
- **Political/fear-mongering**: Sensationalist headlines about government, AI, economy
- **Government benefit scams**: Fake claims about tax refunds, monthly checks, "public laws"
- **Health products**: Medical cure claims, supplement pitches
- **Tech hype**: Tesla, AI, SpaceX investment opportunities

### Common Spam Characteristics
The PDFs demonstrate typical spam tactics:
- Unicode character substitution to evade filters (e.g., "саѕh" instead of "cash", "ᖯοnυѕ" instead of "bonus")
- Sensationalist subject lines with urgency ("URGENT", "Breaking News", "WARNING")
- Clickbait headlines designed to trigger fear or FOMO
- Legitimate-looking sender names but suspicious email domains
- Footer disclaimers revealing the actual sender/marketing company
- Multiple unsubscribe mechanisms buried in fine print

## Working with This Dataset

### Reading PDF Files
The spam examples are stored as PDFs to preserve the exact visual presentation of the emails. When analyzing these files:
- Use PDF reading tools to extract text and metadata
- Pay attention to email headers which contain sender/recipient information
- Note the use of special characters and Unicode substitutions in the body text
- Footer sections often reveal the actual marketing company behind the spam

### Common Analysis Tasks
When working with this dataset, you may need to:
- Extract email headers (From, Subject, Date, To) from PDFs
- Parse body text while handling Unicode character substitutions
- Identify URLs and track where links redirect
- Extract sender domain information
- Categorize spam types (investment, health, political, etc.)
- Identify common linguistic patterns and fear-appeal tactics
- Build feature extractors for machine learning models

### File Naming Convention
PDF filenames are derived from the email subject lines, which often:
- Start with sensationalist keywords (e.g., "Caught on Camera", "Breaking News", "WARNING")
- Use Unicode characters in place of ASCII letters
- Include dates (typically recent, to create urgency)
- May have leading spaces in the filename

### Important Notes
- This is a defensive security dataset for spam detection research only
- PDFs may contain malicious links - do not click embedded URLs
- Some filenames contain special Unicode characters that may require careful handling in scripts
- The repository currently contains no code - it is purely a data collection

## Defensive Use Cases

This dataset is intended for legitimate defensive security purposes:
- Training spam classifiers and email filters
- Analyzing spam evolution and new tactics
- Building features for content-based spam detection
- Studying social engineering techniques used in spam
- Creating test cases for email security systems
- Developing unsubscribe link validators
- Analyzing domain reputation patterns
