import re
import urllib
import tldextract
import whois
from datetime import datetime

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "webscr", "signin",
    "banking", "confirm", "pay", "submit", "password", "ebayisapi", "cmd"
]

SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly"
]

def extract_features(url):
    features = {}
    parsed_url = urllib.parse.urlparse(url)

    # Extract domain
    extracted = tldextract.extract(url)
    domain = ".".join(part for part in [extracted.domain, extracted.suffix] if part)

    features['domain'] = domain
    features['url_length'] = len(url)
    features['has_ip'] = bool(re.match(r'^http[s]?://\d{1,3}(\.\d{1,3}){3}', url))
    features['has_at'] = '@' in url
    features['has_https'] = parsed_url.scheme == 'https'
    features['num_dots'] = url.count('.')
    features['uses_shortener'] = any(short in url for short in SHORTENERS)
    features['has_suspicious_words'] = any(word in url.lower() for word in SUSPICIOUS_KEYWORDS)

    # WHOIS lookup
    try:
        whois_info = whois.whois(domain)
        creation_date = whois_info.creation_date

        # Handle potential list format
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days
            features['domain_age_days'] = age_days
            features['new_domain'] = age_days < 180  # less than 6 months old
        else:
            features['domain_age_days'] = -1
            features['new_domain'] = True  # unknown? play it safe
    except Exception as e:
        features['domain_age_days'] = -1
        features['new_domain'] = True  # If we can't get WHOIS info, flag it

    return features

def classify(features):
    score = 0

    if features['url_length'] > 75:
        score += 1
    if features['has_ip']:
        score += 2
    if features['has_at']:
        score += 1
    if not features['has_https']:
        score += 1
    if features['num_dots'] > 5:
        score += 1
    if features['uses_shortener']:
        score += 2
    if features['has_suspicious_words']:
        score += 2
    if features.get('new_domain', False):
        score += 2  # recently registered = extra suspicious

    if score >= 5:
        return "⚠️ Suspicious (Likely Phishing)"
    else:
        return "✅ Likely Safe"

def main():
    url = input("Enter a URL to check: ").strip()
    features = extract_features(url)
    result = classify(features)

    print("\n🔍 Analysis:")
    for k, v in features.items():
        print(f"{k}: {v}")
    print("\nResult: ", result)

if __name__ == "__main__":
    main()
