import pytest
from app.dom_similarity import compute_dom_similarity, extract_tag_sequence, match_dom_against_brands

HTML_REF_PAYPAL = """
<html>
<head><title>PayPal Login</title></head>
<body>
    <header><nav><a>PayPal</a></nav></header>
    <main>
        <form action="/login" method="post">
            <input type="email" name="user"/>
            <input type="password" name="pass"/>
            <button type="submit">Log In</button>
        </form>
    </main>
</body>
</html>
"""

HTML_CLONE_PAYPAL = """
<html>
<head><title>PayPal Secure Login</title></head>
<body>
    <header><nav><a>PayPal</a></nav></header>
    <main>
        <form action="/phish_steal" method="post">
            <input type="email" name="u"/>
            <input type="password" name="p"/>
            <button type="submit">Sign In</button>
        </form>
    </main>
</body>
</html>
"""

HTML_UNRELATED_BLOG = """
<html>
<head><title>My Personal Blog</title></head>
<body>
    <article>
        <h1>Hello World</h1>
        <p>This is a personal blog post with no login form.</p>
        <img src="pic.jpg"/>
    </article>
</body>
</html>
"""

def test_dom_extraction():
    tags = extract_tag_sequence(HTML_REF_PAYPAL)
    assert "html" in tags
    assert "form" in tags
    assert any("input" in t for t in tags)

def test_identical_dom_similarity():
    score = compute_dom_similarity(HTML_REF_PAYPAL, HTML_REF_PAYPAL)
    assert score == 1.0

def test_clone_dom_similarity():
    score = compute_dom_similarity(HTML_REF_PAYPAL, HTML_CLONE_PAYPAL)
    # Phishing clone should have high DOM structural similarity
    assert score >= 0.70

def test_unrelated_dom_similarity():
    score = compute_dom_similarity(HTML_REF_PAYPAL, HTML_UNRELATED_BLOG)
    # Unrelated layout should have lower similarity score
    assert score < 0.40

def test_match_dom_against_brands():
    brand_map = {
        "paypal": HTML_REF_PAYPAL,
        "blog": HTML_UNRELATED_BLOG
    }
    score, matched = match_dom_against_brands(HTML_CLONE_PAYPAL, brand_map)
    assert matched == "paypal"
    assert score >= 0.70

def test_empty_dom_similarity():
    assert compute_dom_similarity("", HTML_REF_PAYPAL) == 0.0
    assert compute_dom_similarity(None, "") == 0.0

def test_google_vs_microsoft_dom_disambiguation():
    google_dom = """
    <html>
        <head><title>Sign in - Google Accounts</title></head>
        <body>
            <form action="https://accounts.google.com/signin" method="post">
                <h1>Sign in</h1>
                <p>Use your Google Account</p>
                <input type="email" placeholder="Email or phone" name="identifier"/>
                <button type="submit">Next</button>
            </form>
        </body>
    </html>
    """
    
    microsoft_dom = """
    <html>
        <head><title>Sign in to your Microsoft account</title></head>
        <body>
            <form action="https://login.live.com/ppsecure/post.srf" method="post">
                <h1>Sign in</h1>
                <p>Sign in to your account</p>
                <input type="email" placeholder="Email, phone, or Skype" name="loginfmt"/>
                <button type="submit">Next</button>
            </form>
        </body>
    </html>
    """
    
    brand_map = {
        "google": google_dom,
        "microsoft": microsoft_dom,
        "paypal": HTML_REF_PAYPAL
    }
    
    # Test candidate Google page correctly resolves to google
    score, matched = match_dom_against_brands(google_dom, brand_map)
    assert matched == "google"
    assert score >= 0.70
    
    # Test candidate Microsoft page correctly resolves to microsoft
    score_ms, matched_ms = match_dom_against_brands(microsoft_dom, brand_map)
    assert matched_ms == "microsoft"
    assert score_ms >= 0.70


