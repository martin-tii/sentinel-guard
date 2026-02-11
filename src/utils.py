import logging
import sys
import re
from urllib.parse import urlparse

def setup_logging():
    """Configures logging for Project Sentinel."""
    logger = logging.getLogger("Sentinel")
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Console Handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    # File Handler
    fh = logging.FileHandler("audit.log")
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    return logger

logger = setup_logging()

def audit(action, details, status="ALLOWED"):
    """Logs an action to the audit log."""
    logger.info(f"[{status}] {action}: {details}")

def is_phishing_url(url, config=None):
    """
    Static analysis of URLs to detect phishing indicators.
    """
    if not config: config = {}
    
    # Handle missing scheme (e.g., "google.com" -> "http://google.com")
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
        
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        if not domain: # Fallback if URL parsing fails or is just a path
             return False, ""
    except Exception:
        return True, "Malformed URL"
    
    # 1. IP Address Check
    # Regex for IP (IPv4)
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
        return True, "Direct IP access is suspicious."

    # 2. Risky TLDs
    blocked_tlds = config.get("blocked_tlds", [".zip", ".xyz", ".top", ".gq"])
    if any(domain.endswith(tld) for tld in blocked_tlds):
        return True, f"Blocked TLD detected: {domain}"

    # 3. Suspicious Subdomains (e.g., google.com.verify-login.net)
    # If the domain has more than 3 parts and contains a major brand
    parts = domain.split('.')
    major_brands = ["google", "microsoft", "apple", "amazon", "bank", "paypal"]
    
    if len(parts) > 3:
        if any(brand in domain for brand in major_brands):
            # Check if the brand is NOT the main domain
            # e.g. "google" is in "google.update.com" -> update.com is the domain
            # We assume the last 2 parts are the main domain (effective TLD logic is complex, this is a heuristic)
            main_domain = ".".join(parts[-2:]) 
            if not any(brand in main_domain for brand in major_brands):
                return True, "Brand impersonation in subdomain."

    return False, ""