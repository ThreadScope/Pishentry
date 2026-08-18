import json
import os
import glob
import random
import pandas as pd
from typing import List, Dict, Set, Tuple

# Comprehensive seed legitimate portals
LEGITIMATE_SEEDS = [
    "https://paypal.com",
    "https://www.paypal.com/signin",
    "https://google.com",
    "https://accounts.google.com/signin",
    "https://github.com",
    "https://github.com/login",
    "https://microsoft.com",
    "https://login.microsoftonline.com",
    "https://amazon.com",
    "https://apple.com",
    "https://wikipedia.org",
    "https://netflix.com",
    "https://linkedin.com",
    "https://twitter.com",
    "https://reddit.com",
    "https://adobe.com",
    "https://zoom.us",
    "https://dropbox.com",
    "https://ebay.com",
    "https://spotify.com",
    "https://chase.com",
    "https://www.chase.com",
    "https://wellsfargo.com",
    "https://bankofamerica.com",
    "https://dhl.com",
    "https://mydhl.express.dhl",
    "https://facebook.com",
    "https://instagram.com",
    "https://hsbc.com",
    "https://barclays.co.uk",
    "https://bnp.fr",
    "https://steampowered.com",
    "https://cloudflare.com",
    "https://stackoverflow.com",
    "https://python.org",
    "https://fastapi.tiangolo.com"
]

# Targeted seed phishing variants
PHISHING_SEEDS = [
    "http://paypa1-secure-login.tk/auth",
    "http://paypal-verification-account.ml/login",
    "http://login.paypal.com.user-auth-portal.xyz/signin",
    "http://accounts-google-security.ga/login",
    "http://goog1e-verify-account.gq/signin",
    "http://github-auth-verify.tk/session",
    "http://xn--80ak6aa92e.com/paypal",
    "http://microsoft-online-update.cfd/auth",
    "http://amazon-prime-security-verify.top/login",
    "http://chase-bank-online-security.xyz/login",
    "http://wellsfargo-verify-customer.info/signin",
    "http://bankofamerica-secure-update.buzz/auth",
    "http://appleid-apple-verify-service.rest/login",
    "http://netflix-billing-update-account.site/renew",
    "http://dhl-express-tracking-parcel.xyz/login",
    "http://192.168.1.100:8080/paypal/login.php",
    "http://login.microsoft.com.account-protection-support.xyz/auth",
    "http://secure-adobe-docu-verify.site/view",
    "http://instagram-help-security-badge.cam/verify",
    "http://steamcommunity-gift-trade.trade/login"
]


def extract_samples_from_workspace() -> Tuple[Set[str], Set[str]]:
    """
    Extracts all available phishing and benign URLs from the samples/ directory.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    samples_dir = os.path.join(base_dir, "samples")
    
    phish_urls: Set[str] = set(PHISHING_SEEDS)
    benign_urls: Set[str] = set(LEGITIMATE_SEEDS)

    if not os.path.exists(samples_dir):
        print(f"Notice: Samples directory {samples_dir} not found. Using seed data.")
        return phish_urls, benign_urls

    # 1. URLnet datasets (test_phish.txt, test_benign.txt, output_phish.txt, output_benign.txt)
    urlnet_files = glob.glob(os.path.join(samples_dir, "**", "URLnet", "*.txt"), recursive=True)
    for fpath in urlnet_files:
        basename = os.path.basename(fpath).lower()
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                for line in fp:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split("\t")
                    url = None
                    label = None
                    if len(parts) >= 2:
                        if parts[0] in ["1", "0", "-1"]:
                            label = 1 if parts[0] == "1" else 0
                            url = parts[1].strip()
                        elif parts[1] in ["1", "0", "-1"]:
                            url = parts[0].strip()
                            label = 1 if parts[1] == "1" else 0
                        elif parts[0].startswith(("http://", "https://")):
                            url = parts[0].strip()
                            label = 1 if "phish" in basename else 0
                    elif len(parts) == 1 and parts[0].startswith(("http://", "https://")):
                        url = parts[0].strip()
                        label = 1 if "phish" in basename else 0

                    if url and url.startswith(("http://", "https://")) and len(url) > 8:
                        if label == 1:
                            phish_urls.add(url)
                        elif label == 0:
                            benign_urls.add(url)
        except Exception as e:
            print(f"Warning: Could not process {fpath}: {e}")

    # 2. Threat Intel Excel sheets in sacaping/
    excel_files = glob.glob(os.path.join(samples_dir, "**", "*.xlsx"), recursive=True)
    for xf in excel_files:
        try:
            df = pd.read_excel(xf)
            for col in df.columns:
                for val in df[col].dropna():
                    v_str = str(val).strip()
                    if v_str.startswith(("http://", "https://")) and len(v_str) > 8:
                        phish_urls.add(v_str)
        except Exception as e:
            print(f"Warning: Could not process Excel {xf}: {e}")

    # 3. Screenshot file names from archive/screenshots/
    genuine_shot_dir = os.path.join(samples_dir, "sacaping", "archive", "screenshots", "genuine_site_0")
    if os.path.exists(genuine_shot_dir):
        for fname in os.listdir(genuine_shot_dir):
            if fname.endswith((".png", ".jpg")):
                clean = fname.replace("genuine_", "").rsplit("_", 1)[0]
                if clean and "." in clean:
                    benign_urls.add("https://" + clean)

    phish_shot_dir = os.path.join(samples_dir, "sacaping", "archive", "screenshots", "phishing_site_1")
    if os.path.exists(phish_shot_dir):
        for fname in os.listdir(phish_shot_dir):
            if fname.endswith((".png", ".jpg")):
                clean = fname.replace("phishing_", "").rsplit("_", 1)[0]
                if clean and "." in clean:
                    phish_urls.add("http://" + clean)

    # 4. Ingest canonical brand domains from protected_brands.json
    brands_json = os.path.join(base_dir, "data", "protected_brands.json")
    if os.path.exists(brands_json):
        try:
            with open(brands_json, "r", encoding="utf-8") as f:
                brands = json.load(f)
                for b in brands:
                    for d in b.get("canonical_domains", []):
                        if not d.startswith(("http://", "https://")):
                            benign_urls.add("https://" + d)
                        else:
                            benign_urls.add(d)
        except Exception:
            pass

    return phish_urls, benign_urls


def build_dataset(max_samples_per_class: int = 10000) -> str:
    """
    Builds a large-scale, balanced multi-modal training dataset from all sample files.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.join(base_dir, "training")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "dataset.json")

    print("Extracting URLs from samples directory and threat feeds...")
    phish_set, benign_set = extract_samples_from_workspace()
    print(f"Total raw pools: {len(phish_set)} phishing URLs, {len(benign_set)} benign URLs.")

    # Convert to list and balance
    phish_list = list(phish_set)
    benign_list = list(benign_set)

    random.seed(42)
    random.shuffle(phish_list)
    random.shuffle(benign_list)

    sampled_phish = phish_list[:max_samples_per_class]
    sampled_benign = benign_list[:max_samples_per_class]

    dataset: List[Dict] = []
    for u in sampled_benign:
        dataset.append({"url": u, "label": 0})
    for u in sampled_phish:
        dataset.append({"url": u, "label": 1})

    random.shuffle(dataset)

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    print(f"Successfully created balanced dataset with {len(dataset)} samples ({len(sampled_benign)} benign, {len(sampled_phish)} phishing) in {out_file}.")
    return out_file


if __name__ == "__main__":
    build_dataset(max_samples_per_class=10000)
