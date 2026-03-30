# IntelExtractor - SecureBERT 2.0 Threat Intelligence IOC Extractor

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-blue.svg" alt="Python">
  <img src="https://img.shields.io/badge/Streamlit-Web UI-FF4B4B.svg" alt="Streamlit">
  <img src="https://img.shields.io/badge/License-Apache 2.0-green.svg" alt="License">
</p>

## Overview

**IntelExtractor** uses **SecureBERT 2.0** - Cisco's domain-specific AI language model for cybersecurity - to automatically extract Indicators of Compromise (IOCs) from threat intelligence reports, DFIR documents, and web pages.

### What It Extracts

| Category | Examples |
|----------|----------|
| **Indicators** | IP addresses, domains, hashes, CVEs, emails |
| **Malware** | Malware families (Emotet, LockBit, Cobalt Strike) |
| **Vulnerabilities** | CVE IDs (CVE-2024-12345) |
| **Organizations** | Threat groups, security companies |
| **Systems** | Software, platforms, services |

## Features

- **Multiple Input Sources**
  - 📝 Text input - Paste threat intelligence directly
  - 📁 File upload - PDF, TXT, CSV, JSON, MD files
  - 🌐 URL scraping - Fetch content from web pages

- **Smart Processing**
  - Chunked processing for large documents
  - Deduplication of extracted IOCs
  - Extraction history with local storage

- **Easy Export**
  - Download extracted IOCs as text file

## Requirements

```
Python 3.10+
torch>=2.1.0
transformers>=4.36.0
streamlit
pdfplumber
beautifulsoup4
requests
pandas
```

## Installation

1. **Clone the repository**
```bash
git clone https://github.com/stimway9-ops/IntelExtractor.git
cd IntelExtractor
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Run the application**
```bash
python -m streamlit run app.py
```

4. **Open browser**
Navigate to: `http://localhost:8501`

## Usage

### Method 1: Web Interface

Run the Streamlit app and use the tabs:

1. **Text Input Tab** - Paste any threat report text
2. **File Upload Tab** - Upload PDF reports, log files, IOC exports
3. **URL Tab** - Enter a URL to scrape and extract IOCs

### Method 2: CLI Script

```bash
python extract_iocs.py
```

Then paste or type your threat intelligence text when prompted.

## How It Works

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│  Input Source   │ ──▶ │  SecureBERT 2.0 NER  │ ──▶ │  IOC Categories │
│  (Text/File/URL)│     │  AI Model            │     │  (5 entity types│
└─────────────────┘     └──────────────────────┘     └─────────────────┘
```

The **SecureBERT 2.0 NER model** (`cisco-ai/SecureBERT2.0-NER`) is:
- Fine-tuned on cybersecurity corpus
- Achieves 94.5% F1-score on NER tasks
- Recognizes 5 entity types specific to threat intelligence

## Privacy Note

After the initial model download from HuggingFace, text processing happens locally on your machine. Set offline mode for complete privacy:

```bash
export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
```

## Project Structure

```
IntelExtractor/
├── app.py              # Streamlit web UI
├── extract_iocs.py     # CLI extraction script
├── requirements.txt    # Python dependencies
└── README.md           # This file
```

## Example IOCs Extracted

Input text:
```
The Emotet malware is being distributed via malicious documents.
Researchers at Cisco Talos identified the campaign targeting financial
institutions. The attack used Cobalt Strike beacon at 10.0.0.25 communicating
with evil.example.net. Vulnerability CVE-2021-44228 was exploited.
```

Output:
- **Indicators**: 10.0.0.25, evil.example.net, CVE-2021-44228
- **Malware**: Emotet, Cobalt Strike beacon
- **Organizations**: Cisco Talos, financial institutions

## License

Apache License 2.0 - See LICENSE file for details.

## Acknowledgments

- [Cisco AI](https://github.com/cisco-ai-defense) - SecureBERT 2.0 model
- [HuggingFace](https://huggingface.co/cisco-ai/SecureBERT2.0-NER) - Model hosting by
- [SecureBERT 2.0 Paper](https://arxiv.org/pdf/2510.00240) - Research paper