# Phishing Link Scanner

This Python tool is designed to detect potentially phishing URLs by analyzing various features of a given URL. It uses heuristic analysis, WHOIS lookups, domain information, and checks for suspicious keywords, URL shorteners, and other potential phishing indicators.

## Features

- **Suspicious Keyword Detection**: Identifies phishing-related keywords such as "login", "update", "secure", "password", etc.
- **URL Shortener Detection**: Detects URLs using shorteners like `bit.ly`, `tinyurl.com`, etc.
- **Domain Age Check**: Flags new domains (less than 6 months old) as suspicious.
- **WHOIS Lookup**: Retrieves domain registration information to assess domain age.
- **HTTPS Check**: Identifies URLs that do not use secure `https://`.
- **Detailed Analysis**: Outputs various URL features such as length, the presence of IP addresses, suspicious words, etc.
  
## Installation

### Prerequisites

1. **Python 3.6 or later** is required.
2. You will need to install the necessary Python packages:

   ```bash
   pip install tldextract python-whois
