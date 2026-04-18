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
AGH_URL    = os.getenv("AGH_URL", "http://10.0.1.100:80")
AGH_USER   = os.getenv("AGH_USER")
AGH_PASS   = os.getenv("AGH_PASS")
VT_API_KEY = os.getenv("VT_API_KEY")

if not all([AGH_USER, AGH_PASS, VT_API_KEY]):
    raise EnvironmentError("❌ Variables manquantes dans le .env (AGH_USER, AGH_PASS, VT_API_KEY)")

ENTROPY_THRESHOLD   = 3.8
SCAN_INTERVAL       = 15
VT_RATE_LIMIT_DELAY = 15
MAX_SCANNED_CACHE   = 5000

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
        logging.FileHandler("sentinel.log", encoding="utf-8")
    ]
)
log = logging.getLogger("SENTINEL")

# --- HTTP SESSION ---
session = requests.Session()
session.auth = (AGH_USER, AGH_PASS)

# --- CACHE ---
already_scanned: deque = deque(maxlen=MAX_SCANNED_CACHE)
scanned_set: set = set()


def get_max_entropy(domain: str) -> float:
    """Calcule l'entropie de Shannon maximale parmi les parties du domaine."""
    max_score = 0.0
    for part in domain.split("."):
        if len(part) < 4:
            continue
        prob = [float(part.count(c)) / len(part) for c in dict.fromkeys(part)]
        entropy = -sum(p * math.log2(p) for p in prob)
        if entropy > max_score:
            max_score = entropy
    return max_score


def get_vt_score(domain: str) -> int:
    """Interroge VirusTotal et retourne le score malicious + suspicious."""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            stats = r.json()["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0) + stats.get("suspicious", 0)
        if r.status_code == 429:
            log.warning("Rate limit VirusTotal atteint. Pause de 60s...")
            time.sleep(60)
    except Exception as e:
        log.error(f"Erreur VirusTotal pour {domain} : {e}")
    return 0


def block_domain(domain: str) -> None:
    """Ajoute un domaine aux règles de filtrage AdGuard Home via set_rules."""
    url_get = f"{AGH_URL}/control/filtering/status"
    url_set = f"{AGH_URL}/control/filtering/set_rules"
    try:
        r = session.get(url_get, timeout=5)
        r.raise_for_status()
        existing_rules = r.json().get("user_rules", [])
        new_rule = f"||{domain}^"
        if new_rule in existing_rules:
            log.info(f"⏭️  Déjà dans les règles : {domain}")
            return
        existing_rules.append(new_rule)
        r2 = session.post(url_set, json={"rules": existing_rules}, timeout=5)
        if r2.status_code == 200:
            log.info(f"✅ Bloqué avec succès : {domain}")
        else:
            log.error(f"Erreur AdGuard ({r2.status_code}) : {r2.text}")
    except Exception as e:
        log.error(f"Erreur réseau lors du blocage de {domain} : {e}")


def is_whitelisted(domain: str) -> bool:
    """Vérifie si le domaine est dans la whitelist."""
    return any(w in domain for w in WHITELIST)


def add_to_cache(domain: str) -> None:
    """Ajoute un domaine au cache en gérant proprement l'éjection."""
    if len(already_scanned) == MAX_SCANNED_CACHE:
        oldest = already_scanned[0]
        scanned_set.discard(oldest)
    already_scanned.append(domain)
    scanned_set.add(domain)


def process_domain(domain: str) -> None:
    """Analyzes a domain and blocks it if necessary."""
    if is_whitelisted(domain):
        return

    score = get_max_entropy(domain)
    if score <= ENTROPY_THRESHOLD:
        return

    log.warning(f"⚠️  Suspicious domain : {domain} (entropie: {score:.2f})")

    time.sleep(VT_RATE_LIMIT_DELAY)
    vt_result = get_vt_score(domain)

    if vt_result >= 1:
        log.warning(f"🚫 VirusTotal score={vt_result} → Blocking {domain}")
        block_domain(domain)
    else:
        log.info(f"✅ VirusTotal OK for {domain}")


def fetch_new_domains() -> set:
    """Retrieves recent domains from AdGuard and returns the new ones."""
    try:
        r = session.get(f"{AGH_URL}/control/querylog?limit=200", timeout=10)
        r.raise_for_status()
        data = r.json().get("data", [])
        domains = {e["question"]["name"].lower() for e in data}
        return domains - scanned_set
    except Exception as e:
        log.error(f"Error fetching query log : {e}")
        return set()


def main() -> None:
    log.info("🚀 SENTINEL ACTIVATED AND READY")

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
