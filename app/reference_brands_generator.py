"""
app/reference_brands_generator.py
=================================
Automated Generator & Indexer for 35+ Official Enterprise Brand Reference DOMs,
Landing Pages, Login Portals, and Visual Baselines.

Generates production-grade HTML DOM trees (login forms, landing layouts, token anchors)
and visual identity assets for ground-truth reference matching in CloneCatcher AI.
"""

import os
import json
import logging
from typing import Dict, List, Any
from PIL import Image, ImageDraw

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
REF_DIR = os.path.join(DATA_DIR, "reference")
PROTECTED_BRANDS_FILE = os.path.join(DATA_DIR, "protected_brands.json")

# 38 Enterprise Brand Reference Specifications
ALL_REFERENCE_BRANDS: List[Dict[str, Any]] = [
    {
        "brand_id": "google",
        "display_name": "Google",
        "official_login_url": "https://accounts.google.com",
        "canonical_domains": ["google.com", "accounts.google.com", "myaccount.google.com", "google.co.in", "google.co.uk"],
        "brand_color": "#4285F4",
        "official_cert_issuer": "Google Trust Services LLC (GTS CA 1C3)",
        "security_advice": "Google Account authentication is exclusively hosted at accounts.google.com signed by Google Trust Services CA. Look for FIDO2/WebAuthn prompts.",
        "keywords": ["google", "gmail", "gsuite", "google account", "accounts.google.com", "google workspace"],
        "form_action": "https://accounts.google.com/signin/v2/challenge/pwd"
    },
    {
        "brand_id": "microsoft",
        "display_name": "Microsoft / Office 365",
        "official_login_url": "https://login.microsoftonline.com",
        "canonical_domains": ["microsoft.com", "office.com", "login.microsoftonline.com", "live.com", "microsoftonline.com"],
        "brand_color": "#00A4EF",
        "official_cert_issuer": "Microsoft Azure TLS Issuing CA / DigiCert",
        "security_advice": "Enterprise Microsoft 365 credentials should only ever be inputted on login.microsoftonline.com or verified corporate ADFS federation endpoints.",
        "keywords": ["microsoft", "office 365", "outlook", "login.microsoftonline.com", "azure", "entra id", "onedrive"],
        "form_action": "https://login.microsoftonline.com/common/login"
    },
    {
        "brand_id": "paypal",
        "display_name": "PayPal",
        "official_login_url": "https://www.paypal.com/signin",
        "canonical_domains": ["paypal.com", "www.paypal.com", "paypalobjects.com"],
        "brand_color": "#003087",
        "official_cert_issuer": "DigiCert Global Root CA (DigiCert Inc)",
        "security_advice": "Legitimate PayPal portals operate strictly under *.paypal.com with EV/OV DigiCert TLS certificates and never ask for account credentials via IP addresses or dynamic TLDs.",
        "keywords": ["paypal", "paypal inc", "paypal balance", "pay with paypal", "paypal checkout"],
        "form_action": "https://www.paypal.com/signin"
    },
    {
        "brand_id": "apple",
        "display_name": "Apple / iCloud",
        "official_login_url": "https://appleid.apple.com",
        "canonical_domains": ["apple.com", "appleid.apple.com", "icloud.com", "idmsa.apple.com"],
        "brand_color": "#A2AAAD",
        "official_cert_issuer": "Apple Public EV Server RSA CA 1 - G1",
        "security_advice": "Authentic Apple ID login prompts use Apple PKI root certificates and enforce hardware Two-Factor Authentication on trusted Apple devices.",
        "keywords": ["apple", "apple id", "icloud", "apple inc", "sign in with apple", "find my"],
        "form_action": "https://appleid.apple.com/auth/authorize"
    },
    {
        "brand_id": "amazon",
        "display_name": "Amazon",
        "official_login_url": "https://www.amazon.com/ap/signin",
        "canonical_domains": ["amazon.com", "www.amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "aws.amazon.com"],
        "brand_color": "#FF9900",
        "official_cert_issuer": "Amazon RSA 2048 M01 / DigiCert",
        "security_advice": "Amazon sign-in forms are strictly served under *.amazon.com/ap/signin or console.aws.amazon.com with Amazon Trust Services certificates.",
        "keywords": ["amazon", "amazon prime", "aws", "amazon web services", "sign in to amazon"],
        "form_action": "https://www.amazon.com/ap/signin"
    },
    {
        "brand_id": "netflix",
        "display_name": "Netflix",
        "official_login_url": "https://www.netflix.com/login",
        "canonical_domains": ["netflix.com", "www.netflix.com"],
        "brand_color": "#E50914",
        "official_cert_issuer": "DigiCert Global Root G2",
        "security_advice": "Netflix membership accounts are accessed solely via https://www.netflix.com/login. Be vigilant against fake SMS/email renewal links.",
        "keywords": ["netflix", "netflix inc", "watch netflix", "sign in to netflix", "unlimited movies"],
        "form_action": "https://www.netflix.com/login"
    },
    {
        "brand_id": "facebook",
        "display_name": "Meta / Facebook",
        "official_login_url": "https://www.facebook.com/login",
        "canonical_domains": ["facebook.com", "www.facebook.com", "meta.com", "fb.com"],
        "brand_color": "#1877F2",
        "official_cert_issuer": "DigiCert High Assurance TLS Hybrid ECC SHA384 2020 CA1",
        "security_advice": "Facebook and Meta authentication portals operate on *.facebook.com. Check for WebAuthn passkey prompts.",
        "keywords": ["facebook", "meta", "meta platforms", "log into facebook", "connect with facebook"],
        "form_action": "https://www.facebook.com/login/device-based/regular/login/"
    },
    {
        "brand_id": "instagram",
        "display_name": "Instagram",
        "official_login_url": "https://www.instagram.com/accounts/login",
        "canonical_domains": ["instagram.com", "www.instagram.com"],
        "brand_color": "#E1306C",
        "official_cert_issuer": "DigiCert TLS Hybrid ECC SHA384 2020 CA1",
        "security_advice": "Instagram login requests are delivered exclusively via *.instagram.com endpoints.",
        "keywords": ["instagram", "instagram from meta", "log in with instagram", "instagram.com"],
        "form_action": "https://www.instagram.com/accounts/login/ajax/"
    },
    {
        "brand_id": "github",
        "display_name": "GitHub",
        "official_login_url": "https://github.com/login",
        "canonical_domains": ["github.com", "www.github.com"],
        "brand_color": "#24292E",
        "official_cert_issuer": "DigiCert TLS Hybrid ECC SHA384 2020 CA1",
        "security_advice": "Authentic GitHub sessions reside solely on github.com. All official login forms support hardware security keys natively.",
        "keywords": ["github", "github inc", "sign in to github", "github enterprise", "github copilot"],
        "form_action": "https://github.com/session"
    },
    {
        "brand_id": "gitlab",
        "display_name": "GitLab",
        "official_login_url": "https://gitlab.com/users/sign_in",
        "canonical_domains": ["gitlab.com", "about.gitlab.com"],
        "brand_color": "#FC6D26",
        "official_cert_issuer": "Cloudflare Inc ECC CA-3 / DigiCert",
        "security_advice": "Official GitLab Cloud sessions are hosted strictly under https://gitlab.com/users/sign_in.",
        "keywords": ["gitlab", "gitlab devops", "sign in to gitlab", "gitlab inc"],
        "form_action": "https://gitlab.com/users/sign_in"
    },
    {
        "brand_id": "bankofamerica",
        "display_name": "Bank of America",
        "official_login_url": "https://www.bankofamerica.com",
        "canonical_domains": ["bankofamerica.com", "www.bankofamerica.com", "bofa.com", "merrill.com"],
        "brand_color": "#012169",
        "official_cert_issuer": "Entrust Certificate Authority / DigiCert Inc",
        "security_advice": "Bank of America banking portals enforce Extended Validation (EV) certificates and will never request your Debit Card PIN via email.",
        "keywords": ["bank of america", "bofa", "merrill lynch", "online banking passcode", "bofa login"],
        "form_action": "https://secure.bankofamerica.com/login/sign-in/signOnV2Screen.go"
    },
    {
        "brand_id": "chase",
        "display_name": "Chase Bank",
        "official_login_url": "https://www.chase.com",
        "canonical_domains": ["chase.com", "www.chase.com", "jpmorganchase.com"],
        "brand_color": "#117ACA",
        "official_cert_issuer": "DigiCert High Assurance TLS CA",
        "security_advice": "Chase online banking requires secure HTTPS on chase.com. Verify the security padlock and ensure the URL does not contain typosquats.",
        "keywords": ["chase", "jpmorgan", "chase online", "chase bank", "jpmorgan chase", "chase sapphire"],
        "form_action": "https://secure07c.chase.com/web/auth/dashboard"
    },
    {
        "brand_id": "wellsfargo",
        "display_name": "Wells Fargo",
        "official_login_url": "https://www.wellsfargo.com",
        "canonical_domains": ["wellsfargo.com", "www.wellsfargo.com"],
        "brand_color": "#D71E28",
        "official_cert_issuer": "Entrust Authority / DigiCert",
        "security_advice": "Wells Fargo accounts require authentic TLS negotiation on wellsfargo.com.",
        "keywords": ["wells fargo", "wellsfargo online", "wells fargo sign on", "wells fargo banking"],
        "form_action": "https://connect.secure.wellsfargo.com/auth/login/do"
    },
    {
        "brand_id": "citibank",
        "display_name": "Citibank",
        "official_login_url": "https://www.citi.com",
        "canonical_domains": ["citi.com", "www.citi.com", "citibank.com"],
        "brand_color": "#003B70",
        "official_cert_issuer": "DigiCert Global Root CA",
        "security_advice": "Citi online services reside under *.citi.com. Never provide your OTP to external callers.",
        "keywords": ["citibank", "citi", "citi cards", "citigroup", "citi online"],
        "form_action": "https://online.citi.com/US/login.do"
    },
    {
        "brand_id": "hsbc",
        "display_name": "HSBC",
        "official_login_url": "https://www.hsbc.com",
        "canonical_domains": ["hsbc.com", "www.hsbc.com", "hsbc.co.uk"],
        "brand_color": "#DB0011",
        "official_cert_issuer": "DigiCert Global Root CA",
        "security_advice": "HSBC international portals enforce strict mutual SSL and security token devices.",
        "keywords": ["hsbc", "hsbc holdings", "hsbc online banking", "hsbc uk"],
        "form_action": "https://www.hsbc.co.uk/security/"
    },
    {
        "brand_id": "barclays",
        "display_name": "Barclays",
        "official_login_url": "https://www.barclays.co.uk",
        "canonical_domains": ["barclays.co.uk", "www.barclays.co.uk", "barclays.com"],
        "brand_color": "#00AEEF",
        "official_cert_issuer": "DigiCert Global Root CA",
        "security_advice": "Barclays Online Banking operates exclusively via barclays.co.uk.",
        "keywords": ["barclays", "barclays bank", "barclays online banking", "barclays corporate"],
        "form_action": "https://bank.barclays.co.uk/olb/authlogin/loginAppContainer.do"
    },
    {
        "brand_id": "sbi",
        "display_name": "State Bank of India (SBI)",
        "official_login_url": "https://www.onlinesbi.sbi",
        "canonical_domains": ["onlinesbi.sbi", "sbi.co.in", "bank.sbi"],
        "brand_color": "#280071",
        "official_cert_issuer": "eMudhra / DigiCert TLS CA",
        "security_advice": "Official State Bank of India net banking is only hosted on onlinesbi.sbi or sbi.co.in. Beware of fake APKs and SMS phishing.",
        "keywords": ["state bank of india", "onlinesbi", "sbi", "sbi netbanking", "yono sbi"],
        "form_action": "https://retail.onlinesbi.sbi/retail/login.htm"
    },
    {
        "brand_id": "hdfc",
        "display_name": "HDFC Bank",
        "official_login_url": "https://netbanking.hdfcbank.com",
        "canonical_domains": ["hdfcbank.com", "netbanking.hdfcbank.com"],
        "brand_color": "#004C8F",
        "official_cert_issuer": "DigiCert SHA2 Extended Validation Server CA",
        "security_advice": "HDFC Bank NetBanking requires customer ID authentication on *.hdfcbank.com with verified EV certificate.",
        "keywords": ["hdfc", "hdfc bank", "hdfc netbanking", "hdfc customer id"],
        "form_action": "https://netbanking.hdfcbank.com/netbanking/entry"
    },
    {
        "brand_id": "icici",
        "display_name": "ICICI Bank",
        "official_login_url": "https://infinity.icicibank.com",
        "canonical_domains": ["icicibank.com", "infinity.icicibank.com"],
        "brand_color": "#B82928",
        "official_cert_issuer": "DigiCert High Assurance EV Root CA",
        "security_advice": "Authentic ICICI Internet Banking is hosted at infinity.icicibank.com.",
        "keywords": ["icici", "icici bank", "infinity login", "icici netbanking", "imobile"],
        "form_action": "https://infinity.icicibank.com/corp/AuthenticationController"
    },
    {
        "brand_id": "dhl",
        "display_name": "DHL Express",
        "official_login_url": "https://mydhl.express.dhl",
        "canonical_domains": ["dhl.com", "express.dhl", "mydhl.express.dhl", "dhl.de"],
        "brand_color": "#FFCC00",
        "official_cert_issuer": "Deutsche Telekom Security GmbH / DigiCert",
        "security_advice": "DHL Express tracking notifications always direct customers to *.dhl.com or *.express.dhl. Never enter payment details on unfamiliar tracking links.",
        "keywords": ["dhl", "dhl express", "dhl parcel", "dhl tracking", "mydhl"],
        "form_action": "https://mydhl.express.dhl/login"
    },
    {
        "brand_id": "fedex",
        "display_name": "FedEx",
        "official_login_url": "https://www.fedex.com",
        "canonical_domains": ["fedex.com", "www.fedex.com"],
        "brand_color": "#4D148C",
        "official_cert_issuer": "DigiCert Global Root CA",
        "security_advice": "FedEx delivery manager and shipment tracking operate exclusively on fedex.com.",
        "keywords": ["fedex", "fedex express", "fedex tracking", "fedex delivery manager"],
        "form_action": "https://www.fedex.com/login"
    },
    {
        "brand_id": "ups",
        "display_name": "UPS",
        "official_login_url": "https://www.ups.com",
        "canonical_domains": ["ups.com", "www.ups.com"],
        "brand_color": "#351C15",
        "official_cert_issuer": "DigiCert Global Root CA",
        "security_advice": "Official United Parcel Service notifications originate exclusively from ups.com.",
        "keywords": ["ups", "united parcel service", "ups tracking", "ups my choice"],
        "form_action": "https://www.ups.com/lasso/login"
    },
    {
        "brand_id": "usps",
        "display_name": "USPS",
        "official_login_url": "https://reg.usps.com",
        "canonical_domains": ["usps.com", "reg.usps.com", "tools.usps.com"],
        "brand_color": "#004B87",
        "official_cert_issuer": "Entrust Authority / DigiCert",
        "security_advice": "United States Postal Service authentication is hosted at reg.usps.com.",
        "keywords": ["usps", "united states postal service", "usps tracking", "informed delivery"],
        "form_action": "https://reg.usps.com/entreg/LoginAction_input"
    },
    {
        "brand_id": "adobe",
        "display_name": "Adobe",
        "official_login_url": "https://auth.services.adobe.com",
        "canonical_domains": ["adobe.com", "auth.services.adobe.com", "creativecloud.adobe.com"],
        "brand_color": "#FF0000",
        "official_cert_issuer": "DigiCert Global Root G2",
        "security_advice": "Adobe Creative Cloud sign-in redirects to auth.services.adobe.com.",
        "keywords": ["adobe", "adobe creative cloud", "adobe acrobat", "sign in with adobe id"],
        "form_action": "https://auth.services.adobe.com/en_US/index.html"
    },
    {
        "brand_id": "docusign",
        "display_name": "DocuSign",
        "official_login_url": "https://account.docusign.com",
        "canonical_domains": ["docusign.com", "account.docusign.com", "app.docusign.com"],
        "brand_color": "#2962FF",
        "official_cert_issuer": "DigiCert TLS RSA SHA256 2020 CA1",
        "security_advice": "DocuSign document signing and user logins operate exclusively on *.docusign.com.",
        "keywords": ["docusign", "docusign inc", "electronic signature", "review and sign document"],
        "form_action": "https://account.docusign.com/username"
    },
    {
        "brand_id": "dropbox",
        "display_name": "Dropbox",
        "official_login_url": "https://www.dropbox.com/login",
        "canonical_domains": ["dropbox.com", "www.dropbox.com"],
        "brand_color": "#0061FF",
        "official_cert_issuer": "DigiCert Global Root CA",
        "security_advice": "Dropbox cloud authentication requires secure connection on dropbox.com.",
        "keywords": ["dropbox", "dropbox business", "sign in to dropbox", "dropbox cloud"],
        "form_action": "https://www.dropbox.com/ajax_login"
    },
    {
        "brand_id": "linkedin",
        "display_name": "LinkedIn",
        "official_login_url": "https://www.linkedin.com/login",
        "canonical_domains": ["linkedin.com", "www.linkedin.com"],
        "brand_color": "#0A66C2",
        "official_cert_issuer": "DigiCert Global Root CA",
        "security_advice": "LinkedIn professional network accounts authenticate solely via linkedin.com.",
        "keywords": ["linkedin", "linkedin corporation", "sign in to linkedin", "linkedin learning"],
        "form_action": "https://www.linkedin.com/uas/login-submit"
    },
    {
        "brand_id": "twitter",
        "display_name": "X / Twitter",
        "official_login_url": "https://x.com/i/flow/login",
        "canonical_domains": ["x.com", "twitter.com"],
        "brand_color": "#000000",
        "official_cert_issuer": "DigiCert TLS Hybrid ECC SHA384 2020 CA1",
        "security_advice": "Official X and Twitter logins use x.com or twitter.com.",
        "keywords": ["twitter", "x.com", "twitter.com", "sign in to x", "sign in to twitter"],
        "form_action": "https://x.com/i/api/1.1/onboarding/task.json"
    },
    {
        "brand_id": "coinbase",
        "display_name": "Coinbase",
        "official_login_url": "https://www.coinbase.com/signin",
        "canonical_domains": ["coinbase.com", "www.coinbase.com", "pro.coinbase.com"],
        "brand_color": "#0052FF",
        "official_cert_issuer": "Amazon Trust Services / Cloudflare",
        "security_advice": "Coinbase cryptocurrency accounts authenticate strictly via coinbase.com with FIDO2 WebAuthn support.",
        "keywords": ["coinbase", "coinbase pro", "coinbase wallet", "sign in to coinbase"],
        "form_action": "https://www.coinbase.com/signin"
    },
    {
        "brand_id": "binance",
        "display_name": "Binance",
        "official_login_url": "https://accounts.binance.com/en/login",
        "canonical_domains": ["binance.com", "accounts.binance.com", "binance.us"],
        "brand_color": "#F0B90B",
        "official_cert_issuer": "Cloudflare Inc ECC CA-3",
        "security_advice": "Binance exchange logins operate on accounts.binance.com with hardware 2FA.",
        "keywords": ["binance", "binance exchange", "binance us", "binance login"],
        "form_action": "https://accounts.binance.com/bapi/accounts/v1/public/auth/login"
    },
    {
        "brand_id": "metamask",
        "display_name": "MetaMask",
        "official_login_url": "https://metamask.io",
        "canonical_domains": ["metamask.io", "portfolio.metamask.io"],
        "brand_color": "#E2761B",
        "official_cert_issuer": "Cloudflare Inc ECC CA-3",
        "security_advice": "MetaMask is a client-side Web3 wallet and NEVER asks for your 12-word Secret Recovery Phrase on any website.",
        "keywords": ["metamask", "metamask.io", "secret recovery phrase", "metamask extension", "connect your wallet"],
        "form_action": "https://metamask.io/unlock"
    },
    {
        "brand_id": "steam",
        "display_name": "Steam",
        "official_login_url": "https://store.steampowered.com/login/",
        "canonical_domains": ["steampowered.com", "steamcommunity.com"],
        "brand_color": "#171A21",
        "official_cert_issuer": "DigiCert Global Root CA",
        "security_advice": "Steam Community logins operate strictly on steamcommunity.com or store.steampowered.com with Steam Guard 2FA.",
        "keywords": ["steam", "steampowered", "valve corporation", "sign in to steam", "steam guard"],
        "form_action": "https://store.steampowered.com/login/dologin/"
    },
    {
        "brand_id": "spotify",
        "display_name": "Spotify",
        "official_login_url": "https://accounts.spotify.com/login",
        "canonical_domains": ["spotify.com", "accounts.spotify.com"],
        "brand_color": "#1DB954",
        "official_cert_issuer": "DigiCert Global Root G2",
        "security_advice": "Spotify accounts authenticate at accounts.spotify.com.",
        "keywords": ["spotify", "spotify music", "sign in to spotify", "spotify premium"],
        "form_action": "https://accounts.spotify.com/api/login"
    },
    {
        "brand_id": "ebay",
        "display_name": "eBay",
        "official_login_url": "https://signin.ebay.com",
        "canonical_domains": ["ebay.com", "signin.ebay.com", "ebay.co.uk", "ebay.de"],
        "brand_color": "#E53238",
        "official_cert_issuer": "DigiCert Global Root CA",
        "security_advice": "eBay marketplace accounts sign in via signin.ebay.com.",
        "keywords": ["ebay", "ebay inc", "sign in to ebay", "ebay secure login"],
        "form_action": "https://signin.ebay.com/ws/eBayISAPI.dll?co_partnerid=2&siteid=0&UsingSSL=1"
    },
    {
        "brand_id": "stripe",
        "display_name": "Stripe",
        "official_login_url": "https://dashboard.stripe.com/login",
        "canonical_domains": ["stripe.com", "dashboard.stripe.com", "api.stripe.com"],
        "brand_color": "#635BFF",
        "official_cert_issuer": "DigiCert TLS RSA SHA256 2020 CA1",
        "security_advice": "Stripe financial dashboard access is strictly hosted at dashboard.stripe.com.",
        "keywords": ["stripe", "stripe dashboard", "stripe inc", "stripe billing", "sign in to stripe"],
        "form_action": "https://dashboard.stripe.com/ajax/sessions"
    },
    {
        "brand_id": "zoom",
        "display_name": "Zoom",
        "official_login_url": "https://zoom.us/signin",
        "canonical_domains": ["zoom.us", "zoom.com"],
        "brand_color": "#2D8CFF",
        "official_cert_issuer": "DigiCert Global Root CA",
        "security_advice": "Zoom video conferencing accounts sign in on zoom.us.",
        "keywords": ["zoom", "zoom video", "zoom meeting", "sign in to zoom", "zoom us"],
        "form_action": "https://zoom.us/signin"
    },
    {
        "brand_id": "salesforce",
        "display_name": "Salesforce",
        "official_login_url": "https://login.salesforce.com",
        "canonical_domains": ["salesforce.com", "login.salesforce.com"],
        "brand_color": "#00A1E0",
        "official_cert_issuer": "DigiCert Global Root CA",
        "security_advice": "Enterprise Salesforce CRM instances authenticate through login.salesforce.com or custom corporate MyDomain endpoints.",
        "keywords": ["salesforce", "salesforce crm", "login.salesforce.com", "force.com"],
        "form_action": "https://login.salesforce.com"
    },
    {
        "brand_id": "okta",
        "display_name": "Okta Enterprise Identity",
        "official_login_url": "https://login.okta.com",
        "canonical_domains": ["okta.com", "login.okta.com", "oktapreview.com"],
        "brand_color": "#007DC1",
        "official_cert_issuer": "DigiCert TLS RSA SHA256 2020 CA1",
        "security_advice": "Okta SSO identity authentication occurs exclusively on verified customer subdomains (*.okta.com) with MFA validation.",
        "keywords": ["okta", "okta sso", "okta identity", "sign in with okta", "okta verify"],
        "form_action": "https://login.okta.com/api/v1/authn"
    }
]


def generate_all_reference_doms_and_assets():
    """
    Creates complete production-grade DOMs (landing + login) and visual assets
    for all 38 enterprise reference brands.
    """
    os.makedirs(REF_DIR, exist_ok=True)
    os.makedirs(DATA_DIR, exist_ok=True)

    protected_manifest = []

    for brand in ALL_REFERENCE_BRANDS:
        b_id = brand["brand_id"]
        d_name = brand["display_name"]
        color = brand["brand_color"]
        form_act = brand.get("form_action", f"https://{brand['canonical_domains'][0]}/login")
        
        folder = os.path.join(REF_DIR, b_id)
        os.makedirs(folder, exist_ok=True)

        # 1. Generate Authentic Login DOM (dom.html)
        dom_file = os.path.join(folder, "dom.html")
        dom_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{d_name} - Official Secure Login</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f8fafc; color: #1e293b; margin: 0; padding: 0; }}
        .header {{ background: {color}; color: #ffffff; padding: 1.2rem 2rem; display: flex; justify-content: space-between; align-items: center; }}
        .brand-logo {{ font-size: 1.4rem; font-weight: 700; }}
        .container {{ max-width: 440px; margin: 3rem auto; background: #ffffff; padding: 2.5rem; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); }}
        h2 {{ font-size: 1.5rem; margin-bottom: 0.5rem; color: #0f172a; }}
        .subtitle {{ font-size: 0.9rem; color: #64748b; margin-bottom: 1.5rem; }}
        .form-group {{ margin-bottom: 1.2rem; }}
        label {{ display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.4rem; }}
        input[type="text"], input[type="email"], input[type="password"] {{ width: 100%; padding: 0.75rem; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 0.95rem; box-sizing: border-box; }}
        input:focus {{ outline: 2px solid {color}; border-color: transparent; }}
        .btn {{ width: 100%; padding: 0.8rem; background: {color}; color: #ffffff; border: none; border-radius: 6px; font-weight: 600; font-size: 1rem; cursor: pointer; }}
        .footer-note {{ font-size: 0.78rem; color: #94a3b8; text-align: center; margin-top: 1.5rem; }}
        .footer {{ background: #0f172a; color: #94a3b8; text-align: center; padding: 1.5rem; font-size: 0.8rem; margin-top: 4rem; }}
    </style>
</head>
<body>
    <header class="header">
        <div class="brand-logo">{d_name}</div>
        <nav>
            <a href="https://{brand['canonical_domains'][0]}/help" style="color: #ffffff; text-decoration: none; font-size: 0.85rem;">Help & Support</a>
        </nav>
    </header>
    <main class="container">
        <h2>Sign in</h2>
        <p class="subtitle">to access your {d_name} account and services</p>
        <form action="{form_act}" method="POST">
            <input type="hidden" name="csrf_token" value="auth_token_canonical_{b_id}_production" />
            <div class="form-group">
                <label for="username">Username or Email</label>
                <input type="text" id="username" name="username" placeholder="name@{brand['canonical_domains'][0]}" required />
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" placeholder="Enter your password" required />
            </div>
            <button type="submit" class="btn">Sign In to {d_name}</button>
        </form>
        <p class="footer-note">🔒 Protected by 256-bit TLS encryption & multi-factor verification.</p>
    </main>
    <footer class="footer">
        <p>&copy; 2026 {d_name} Corporation. All rights reserved. | <a href="https://{brand['canonical_domains'][0]}/privacy" style="color: #94a3b8;">Privacy Policy</a> | <a href="https://{brand['canonical_domains'][0]}/terms" style="color: #94a3b8;">Terms of Service</a></p>
    </footer>
</body>
</html>"""
        with open(dom_file, "w", encoding="utf-8") as f:
            f.write(dom_html)

        # 2. Generate Authentic Landing Page DOM (landing.html)
        landing_file = os.path.join(folder, "landing.html")
        landing_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{d_name} - Official Homepage</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #ffffff; color: #1e293b; margin: 0; }}
        .nav {{ display: flex; justify-content: space-between; align-items: center; padding: 1.5rem 3rem; background: #ffffff; border-bottom: 1px solid #e2e8f0; }}
        .hero {{ padding: 4rem 3rem; text-align: center; background: linear-gradient(180deg, #f8fafc 0%, #ffffff 100%); }}
        .hero h1 {{ font-size: 2.5rem; font-weight: 800; color: #0f172a; margin-bottom: 1rem; }}
        .hero p {{ font-size: 1.15rem; color: #475569; max-width: 600px; margin: 0 auto 2rem auto; }}
        .cta-btn {{ display: inline-block; padding: 0.85rem 1.8rem; background: {color}; color: #ffffff; text-decoration: none; border-radius: 6px; font-weight: 600; }}
        .features {{ display: grid; grid-template-columns: repeat(3, 1fr); gap: 2rem; max-width: 1000px; margin: 3rem auto; padding: 0 1rem; }}
        .feature-card {{ padding: 1.5rem; border: 1px solid #e2e8f0; border-radius: 8px; background: #ffffff; }}
        .footer {{ background: #0f172a; color: #94a3b8; text-align: center; padding: 2.5rem; font-size: 0.85rem; }}
    </style>
</head>
<body>
    <header class="nav">
        <div style="font-size: 1.5rem; font-weight: 800; color: {color};">{d_name}</div>
        <nav>
            <a href="https://{brand['canonical_domains'][0]}/products" style="margin-right: 1.5rem; color: #334155; text-decoration: none;">Products</a>
            <a href="https://{brand['canonical_domains'][0]}/solutions" style="margin-right: 1.5rem; color: #334155; text-decoration: none;">Solutions</a>
            <a href="{brand['official_login_url']}" style="color: {color}; font-weight: 600; text-decoration: none;">Log In</a>
        </nav>
    </header>
    <section class="hero">
        <h1>Welcome to {d_name}</h1>
        <p>Experience world-class security, industry-leading performance, and seamless access across all your devices.</p>
        <a href="{brand['official_login_url']}" class="cta-btn">Access {d_name} Portal</a>
    </section>
    <section class="features">
        <div class="feature-card">
            <h3>Enterprise Protection</h3>
            <p>Advanced real-time threat intelligence and hardware-backed biometric verification.</p>
        </div>
        <div class="feature-card">
            <h3>Global Reliability</h3>
            <p>99.99% uptime SLA with worldwide distributed edge nodes and low latency.</p>
        </div>
        <div class="feature-card">
            <h3>Seamless Integration</h3>
            <p>Connect your existing identity workflows with unified zero-trust architecture.</p>
        </div>
    </section>
    <footer class="footer">
        <p>&copy; 2026 {d_name} Corporation. All official services strictly hosted on {brand['canonical_domains'][0]}.</p>
    </footer>
</body>
</html>"""
        with open(landing_file, "w", encoding="utf-8") as f:
            f.write(landing_html)

        # 3. Generate Visual Reference Assets (screenshot.png & logo.png)
        scr_path = os.path.join(folder, "screenshot.png")
        if not os.path.exists(scr_path):
            img = Image.new("RGB", (1280, 800), color="#F8FAFC")
            draw = ImageDraw.Draw(img)
            # Header banner
            draw.rectangle([0, 0, 1280, 80], fill=color)
            draw.text((80, 28), d_name, fill="#FFFFFF")
            # Card
            draw.rounded_rectangle([440, 150, 840, 650], radius=8, fill="#FFFFFF", outline="#CBD5E1", width=1)
            draw.text((480, 200), f"Sign in to {d_name}", fill="#0F172A")
            draw.text((480, 270), "Username / Email", fill="#64748B")
            draw.rounded_rectangle([480, 300, 800, 345], radius=4, fill="#FFFFFF", outline="#94A3B8", width=1)
            draw.text((480, 370), "Password", fill="#64748B")
            draw.rounded_rectangle([480, 400, 800, 445], radius=4, fill="#FFFFFF", outline="#94A3B8", width=1)
            draw.rounded_rectangle([480, 490, 800, 535], radius=4, fill=color)
            draw.text((610, 505), "Sign In", fill="#FFFFFF")
            img.save(scr_path)

        logo_path = os.path.join(folder, "logo.png")
        if not os.path.exists(logo_path):
            logo = Image.new("RGB", (200, 200), color=color)
            ldraw = ImageDraw.Draw(logo)
            ldraw.text((30, 85), d_name[:8], fill="#FFFFFF")
            logo.save(logo_path)

        protected_manifest.append({
            "brand_id": b_id,
            "display_name": d_name,
            "official_login_url": brand["official_login_url"],
            "canonical_domains": brand["canonical_domains"],
            "brand_color": color,
            "official_cert_issuer": brand["official_cert_issuer"],
            "security_advice": brand["security_advice"],
            "screenshot_path": f"data/reference/{b_id}/screenshot.png",
            "logo_path": f"data/reference/{b_id}/logo.png",
            "dom_snapshot_path": f"data/reference/{b_id}/dom.html",
            "landing_snapshot_path": f"data/reference/{b_id}/landing.html",
            "embedding_cache_id": f"{b_id}_v2"
        })

    # Save protected_brands.json
    with open(PROTECTED_BRANDS_FILE, "w", encoding="utf-8") as f:
        json.dump(protected_manifest, f, indent=2)

    logger.info(f"Successfully generated and indexed {len(protected_manifest)} official reference brand DOMs and assets.")
    print(f"Generated and indexed {len(protected_manifest)} official reference brand DOMs and assets in {REF_DIR}")
    return protected_manifest


if __name__ == "__main__":
    generate_all_reference_doms_and_assets()
