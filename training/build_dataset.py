import json
import os
import random
import requests
from typing import List, Dict

# Standard seed datasets for quick baseline
LEGITIMATE_SEED = [
    "https://paypal.com",
    "https://google.com",
    "https://github.com",
    "https://microsoft.com",
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
    "https://wellsfargo.com",
    "https://bankofamerica.com",
    "https://dhl.com"
]

PHISHING_SEED = [
    "http://paypa1-secure-login.tk/auth",
    "http://paypal-verification-account.ml/login",
    "http://login.paypal.com.user-auth-portal.xyz",
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
    "http://dhl-express-tracking-parcel.xyz/login"
]

def load_sample_urls_from_file(filepath: str, sample_size: int = 250) -> List[str]:
    urls = []
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split("\t")
                    if len(parts) >= 2:
                        u = parts[1].strip()
                        if u.startswith(("http://", "https://")):
                            urls.append(u)
                    elif len(parts) == 1 and parts[0].startswith(("http://", "https://")):
                        urls.append(parts[0].strip())
        except Exception as e:
            print(f"Notice: Could not load sample dataset from {filepath}: {e}")
    
    if len(urls) > sample_size:
        random.seed(42)
        return random.sample(urls, sample_size)
    return urls

def build_dataset():
    os.makedirs("training", exist_ok=True)
    
    sample_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample")
    urlnet_phish = os.path.join(sample_dir, "URLnet", "test_phish.txt")
    urlnet_benign = os.path.join(sample_dir, "URLnet", "test_benign.txt")
    
    sampled_phish = load_sample_urls_from_file(urlnet_phish, sample_size=250)
    sampled_benign = load_sample_urls_from_file(urlnet_benign, sample_size=250)
    
    all_phish = list(set(PHISHING_SEED + sampled_phish))
    all_legit = list(set(LEGITIMATE_SEED + sampled_benign))
    
    dataset = []
    for u in all_legit:
        dataset.append({"url": u, "label": 0})
    for u in all_phish:
        dataset.append({"url": u, "label": 1})
        
    random.seed(42)
    random.shuffle(dataset)
    
    out_file = "training/dataset.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)
        
    print(f"Successfully generated dataset with {len(dataset)} entries ({len(all_legit)} legit, {len(all_phish)} phishing) in {out_file}.")

if __name__ == "__main__":
    build_dataset()
