import math
import time
import logging
import os
from collections import deque

import requests
from dotenv import load_dotenv

# --- LOADING .env ---
load_dotenv()

# --- CONFIG ---
PIHOLE_URL = os.getenv("PIHOLE_URL", "http://10.0.1.100")
PIHOLE_PASSWORD = os.getenv("PIHOLE_PASSWORD")

if not PIHOLE_PASSWORD:
    raise EnvironmentError("❌ Missing PIHOLE_PASSWORD in .env")

ENTROPY_THRESHOLD = 3.8
SCAN_INTERVAL     = 15
MAX_SCANNED_CACHE = 5000

WHITELIST = [
    "google", "microsoft", "apple", "office", "azure",
    "amazonaws", "tiktok", "netflix", "icloud"
]

# --- LOGGING ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("sentinel-pihole.log", encoding="utf-8")
    ]
)
log = logging.getLogger("SENTINEL-PIHOLE")

# --- CACHE ---
already_scanned: deque = deque(maxlen=MAX_SCANNED_CACHE)
scanned_set: set = set()
api_token: str = ""


def get_api_token() -> str:
    """Authenticates with Pi-hole v6 API and returns a session token."""
    url = f"{PIHOLE_URL}/api/auth"
    try:
        r = requests.post(url, json={"password": PIHOLE_PASSWORD}, timeout=10)
        r.raise_for_status()
        token = r.json().get("session", {}).get("sid", "")
        if token:
            log.info("✅ Authenticated with Pi-hole API.")
            return token
        log.error("❌ Authentication failed: no token received.")
    except Exception as e:
        log.error(f"Authentication error: {e}")
    return ""


def get_max_entropy(domain: str) -> float:
    """Calculates the maximum Shannon entropy among domain parts."""
    max_score = 0.0
    for part in domain.split("."):
        if len(part) < 4:
            continue
        prob = [float(part.count(c)) / len(part) for c in dict.fromkeys(part)]
        entropy = -sum(p * math.log2(p) for p in prob)
        if entropy > max_score:
            max_score = entropy
    return max_score


def block_domain(domain: str) -> None:
    """Adds a domain to Pi-hole's blocklist."""
    url = f"{PIHOLE_URL}/api/domains/deny"
    headers = {"sid": api_token}
    payload = {"domain": domain, "comment": "Blocked by Sentinel"}
    try:
        r = requests.post(url, json=payload, headers=headers, timeout=5)
        if r.status_code in (200, 201):
            log.info(f"✅ Blocked successfully: {domain}")
        elif r.status_code == 409:
            log.info(f"⏭️  Already blocked: {domain}")
        else:
            log.error(f"Pi-hole error ({r.status_code}): {r.text}")
    except Exception as e:
        log.error(f"Network error while blocking {domain}: {e}")


def is_whitelisted(domain: str) -> bool:
    """Checks if the domain is whitelisted."""
    return any(w in domain for w in WHITELIST)


def add_to_cache(domain: str) -> None:
    """Adds a domain to the cache with proper eviction handling."""
    if len(already_scanned) == MAX_SCANNED_CACHE:
        oldest = already_scanned[0]
        scanned_set.discard(oldest)
    already_scanned.append(domain)
    scanned_set.add(domain)


def process_domain(domain: str) -> None:
    """Analyzes a domain and blocks it if entropy is too high."""
    if is_whitelisted(domain):
        return

    score = get_max_entropy(domain)
    if score <= ENTROPY_THRESHOLD:
        return

    log.warning(f"⚠️  Suspicious domain: {domain} (entropy: {score:.2f}) → Blocking...")
    block_domain(domain)


def fetch_new_domains() -> set:
    """Retrieves recent domains from Pi-hole query log."""
    url = f"{PIHOLE_URL}/api/queries?max=200"
    headers = {"sid": api_token}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        r.raise_for_status()
        queries = r.json().get("queries", [])
        domains = {q["domain"].lower() for q in queries if "domain" in q}
        return domains - scanned_set
    except Exception as e:
        log.error(f"Error fetching query log: {e}")
        return set()


def main() -> None:
    global api_token
    log.info("🚀 SENTINEL PIHOLE ACTIVATED")

    api_token = get_api_token()
    if not api_token:
        log.error("❌ Could not authenticate. Exiting.")
        return

    while True:
        new_domains = fetch_new_domains()

        if new_domains:
            log.info(f"🔎 {len(new_domains)} new domains detected.")
            for domain in new_domains:
                if domain not in scanned_set:
                    add_to_cache(domain)
                process_domain(domain)

        log.info(f"😴 Wait {SCAN_INTERVAL}s... (cache: {len(scanned_set)} domains)")
        time.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    main()
