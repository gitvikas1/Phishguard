import re
from urllib.parse import urlparse
import tldextract

SUSPICIOUS_TLDS = {
    "zip","review","country","stream","gq","ml","tk","cf","work","fit","xyz","men","date","click","party","cam","rest"
}

def has_ip_in_domain(domain: str) -> bool:
    # IPv4 pattern
    ipv4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    # IPv4 dotted (subdomain forms), we just check if any label is almost fully numeric
    if ipv4.match(domain):
        return True
    labels = domain.split('.')
    return any(label.isdigit() for label in labels)

def count_special_chars(s: str) -> int:
    return len(re.findall(r"[^A-Za-z0-9]", s))

def extract_features(url: str):
    parsed = urlparse(url if re.match(r'^https?://', url, re.I) else 'http://' + url)
    ext = tldextract.extract(parsed.netloc or parsed.path)  # handle bare domains
    domain = ".".join([p for p in [ext.domain] if p])  # core domain
    suffix = ext.suffix or ""
    subdomain = ext.subdomain or ""

    fqdn = ".".join([p for p in [subdomain, domain, suffix] if p])
    domain_len = len(domain)
    url_len = len(url)
    num_digits = sum(c.isdigit() for c in url)
    num_subdomains = len([p for p in subdomain.split('.') if p]) if subdomain else 0
    spec_chars = count_special_chars(url)
    uses_https = parsed.scheme.lower() == "https"
    has_at = "@" in url
    has_hyphen = "-" in (ext.domain or "")
    tld_suspicious = suffix.split(".")[-1].lower() in SUSPICIOUS_TLDS if suffix else False
    ip_in_domain = has_ip_in_domain(ext.registered_domain or parsed.netloc or "")

    # Simple lexical patterns
    keywords = ["login", "verify", "secure", "update", "free", "bonus", "win", "gift", "confirm", "account"]
    keyword_hits = sum(1 for k in keywords if k in url.lower())

    return {
        "domain_len": domain_len,
        "url_len": url_len,
        "num_digits": num_digits,
        "num_subdomains": num_subdomains,
        "spec_chars": spec_chars,
        "uses_https": int(uses_https),
        "has_at": int(has_at),
        "has_hyphen": int(has_hyphen),
        "tld_suspicious": int(tld_suspicious),
        "ip_in_domain": int(ip_in_domain),
        "keyword_hits": keyword_hits,
    }

FEATURE_ORDER = [
    "domain_len","url_len","num_digits","num_subdomains","spec_chars",
    "uses_https","has_at","has_hyphen","tld_suspicious","ip_in_domain","keyword_hits"
]

def vectorize(feats: dict):
    return [feats[k] for k in FEATURE_ORDER]
