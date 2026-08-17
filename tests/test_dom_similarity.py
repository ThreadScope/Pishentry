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
    assert "input" in tags

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
