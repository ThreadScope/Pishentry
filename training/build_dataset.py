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
    "https://fastapi.tiangolo.com",
    "https://youtube.com",
    "https://yahoo.com",
    "https://bing.com",
    "https://duckduckgo.com",
    "https://wordpress.org",
    "https://mozilla.org",
    "https://w3.org",
    "https://gnu.org",
    "https://archive.org",
    "https://nytimes.com",
    "https://bbc.com",
    "https://cnn.com",
    "https://medium.com",
    "https://gitlab.com",
    "https://bitbucket.org",
    "https://docker.com",
    "https://kubernetes.io",
    "https://pypi.org",
    "https://npmjs.com",
    "https://crates.io",
    "https://go.dev",
    "https://rust-lang.org",
    "https://apache.org",
    "https://mit.edu",
    "https://stanford.edu",
    "https://harvard.edu",
    "https://berkeley.edu",
    "https://nih.gov",
    "https://nasa.gov",
    "https://weather.gov",
    "https://loc.gov",
    "https://un.org",
    "https://who.int",
    "https://cern.ch",
    "https://stripe.com",
    "https://capitalone.com",
    "https://fidelity.com",
    "https://vanguard.com",
    "https://schwab.com",
    "https://fedex.com",
    "https://ups.com",
    "https://usps.com",
    "https://uber.com",
    "https://airbnb.com",
    "https://booking.com",
    "https://expedia.com",
    "https://disneyplus.com",
    "https://hulu.com",
    "https://epicgames.com",
    "https://nvidia.com",
    "https://intel.com",
    "https://amd.com",
    "https://ibm.com",
    "https://oracle.com",
    "https://cisco.com",
    "https://salesforce.com",
    "https://slack.com",
    "https://notion.so",
    "https://figma.com",
    "https://canva.com",
    "https://atlassian.com",
    "https://jira.com",
    "https://trello.com",
    "https://zendesk.com",
    "https://shopify.com",
    "https://target.com",
    "https://walmart.com",
    "https://bestbuy.com",
    "https://homedepot.com",
    "https://ikea.com",
    "https://costco.com"
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
    Extracts all available phishing and benign URLs from samples, data, and Phishing.Database directories.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    search_dirs = [
        os.path.join(base_dir, "samples"),
        os.path.join(base_dir, "sample"),
        os.path.join(base_dir, "data")
    ]

    phish_urls: Set[str] = set(PHISHING_SEEDS)
    benign_urls: Set[str] = set(LEGITIMATE_SEEDS)

    # 1. URLnet datasets across all search directories
    for sdir in search_dirs:
        if not os.path.exists(sdir):
            continue
        urlnet_files = glob.glob(os.path.join(sdir, "**", "URLnet", "*.txt"), recursive=True)
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

    # 2. Threat Intel Excel sheets
    for sdir in search_dirs:
        if not os.path.exists(sdir):
            continue
        excel_files = glob.glob(os.path.join(sdir, "**", "*.xlsx"), recursive=True)
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
    for sdir in search_dirs:
        genuine_shot_dir = os.path.join(sdir, "sacaping", "archive", "screenshots", "genuine_site_0")
        if os.path.exists(genuine_shot_dir):
            for fname in os.listdir(genuine_shot_dir):
                if fname.endswith((".png", ".jpg")):
                    clean = fname.replace("genuine_", "").rsplit("_", 1)[0]
                    if clean and "." in clean:
                        benign_urls.add("https://" + clean)

        phish_shot_dir = os.path.join(sdir, "sacaping", "archive", "screenshots", "phishing_site_1")
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

    # 5. Phishing.Database Ingestion
    phish_db_dirs = glob.glob(os.path.join(base_dir, "**", "Phishing.Database"), recursive=True)
    for pdb_dir in phish_db_dirs:
        if not os.path.exists(pdb_dir) or not os.path.isdir(pdb_dir):
            continue
        print(f"Ingesting Phishing.Database real-time feed from {pdb_dir}...")
        txt_files = glob.glob(os.path.join(pdb_dir, "**", "*.txt"), recursive=True)
        txt_files.extend(glob.glob(os.path.join(pdb_dir, "**", "*.adblock"), recursive=True))

        for tf in txt_files:
            bname = os.path.basename(tf).lower()
            if "invalid" in bname or "manifest" in bname or "license" in bname or "readme" in bname:
                continue
            try:
                with open(tf, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        if line.startswith(("http://", "https://", "ftp://")):
                            phish_urls.add(line)
                        elif "." in line and not line.startswith("[") and not line.startswith("!"):
                            phish_urls.add("http://" + line)
            except Exception as e:
                print(f"Warning: Could not process Phishing.Database file {tf}: {e}")

    # 6. Cybersecurity-Datasets & External CSV/TXT Feed Ingestion
    cyber_dirs = glob.glob(os.path.join(base_dir, "**", "Cybersecurity-Datasets"), recursive=True)
    for cdir in cyber_dirs:
        if not os.path.exists(cdir) or not os.path.isdir(cdir):
            continue
        print(f"Ingesting Cybersecurity-Datasets repository from {cdir}...")
        csv_files = glob.glob(os.path.join(cdir, "**", "*.csv"), recursive=True)
        txt_files = glob.glob(os.path.join(cdir, "**", "*.txt"), recursive=True)

        for cf in csv_files + txt_files:
            bname = os.path.basename(cf).lower()
            if "readme" in bname or "license" in bname:
                continue
            try:
                if cf.endswith(".csv"):
                    df = pd.read_csv(cf, nrows=50000)
                    url_col = None
                    label_col = None
                    for c in df.columns:
                        clower = c.lower()
                        if "url" in clower or "domain" in clower or "link" in clower:
                            url_col = c
                        elif "label" in clower or "class" in clower or "phish" in clower or "target" in clower or "type" in clower:
                            label_col = c

                    if url_col:
                        for idx, row in df.iterrows():
                            val = str(row[url_col]).strip()
                            if not val or val.lower() == "nan":
                                continue
                            if not val.startswith(("http://", "https://")):
                                val = "http://" + val
                            
                            is_phish = True
                            if label_col:
                                lval = str(row[label_col]).lower().strip()
                                if lval in ["0", "benign", "legitimate", "good", "safe"]:
                                    is_phish = False
                            
                            if is_phish:
                                phish_urls.add(val)
                            else:
                                benign_urls.add(val)
                elif cf.endswith(".txt"):
                    with open(cf, "r", encoding="utf-8", errors="ignore") as f:
                        for line in f:
                            line = line.strip()
                            if not line or line.startswith("#"):
                                continue
                            if line.startswith(("http://", "https://")):
                                phish_urls.add(line)
                            elif "." in line:
                                phish_urls.add("http://" + line)
            except Exception as e:
                print(f"Warning: Could not process dataset file {cf}: {e}")

    # Generate additional benign paths from legitimate seeds to build rich benign dataset
    expanded_benign = set(benign_urls)
    common_paths = ["", "/login", "/auth", "/signin", "/docs", "/support", "/about", "/contact", "/terms", "/privacy", "/api", "/download", "/faq", "/news"]
    for seed in list(benign_urls):
        base = seed.rstrip("/")
        for p in common_paths:
            expanded_benign.add(base + p)
    benign_urls = expanded_benign

    return phish_urls, benign_urls


def build_dataset(max_samples_per_class: int = 10000) -> str:
    """
    Builds a large-scale, balanced multi-modal training dataset from all sample files and Phishing.Database.
    """
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    out_dir = os.path.join(base_dir, "training")
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "dataset.json")

    print("Extracting URLs from workspace, sample directories, and Phishing.Database feeds...")
    phish_set, benign_set = extract_samples_from_workspace()
    print(f"Total raw pools: {len(phish_set)} phishing URLs, {len(benign_set)} benign URLs.")

    phish_list = list(phish_set)
    benign_list = list(benign_set)

    random.seed(42)
    random.shuffle(phish_list)
    random.shuffle(benign_list)

    target_per_class = min(max_samples_per_class, len(phish_list), len(benign_list))
    if target_per_class < max_samples_per_class:
        # If one class is smaller, balance according to the smaller pool size
        print(f"Note: Balancing dataset to {target_per_class} per class based on available pool sizes.")

    sampled_phish = phish_list[:target_per_class]
    sampled_benign = benign_list[:target_per_class]

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

