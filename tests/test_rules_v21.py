import io
import pytest
import analysis as a
from email.message import EmailMessage
from reports import text_report


def scan_url(url):
    return a.finish(a.url_analysis(url))


def scan_bytes(data, name):
    return a.finish(a.file_analysis(io.BytesIO(data), name, len(data)))


# --- new URL rules ---------------------------------------------------------

@pytest.mark.parametrize('url,code', [
    ('https://invoice-verify.top/login', 'risky_tld'),
    ('https://secure-login.xyz/', 'risky_tld'),
    ('https://bit.ly/3xYzAbC', 'shortener'),
    ('https://t.co/abcd', 'shortener'),
    ('https://xn--pypal-4ve.com/login', 'idn_homograph'),
])
def test_new_url_rules(url, code):
    assert any(f['code'] == code for f in scan_url(url)['findings'])


@pytest.mark.parametrize('url', [
    'https://www.python.org/', 'https://github.com/', 'https://www.gov.uk/',
    'https://news.bbc.co.uk/', 'https://kapitalbank.az/', 'https://www.paypal.com/',
])
def test_legitimate_domains_stay_clean(url):
    assert not scan_url(url)['findings'], url


def test_local_brand_is_recognised():
    found = scan_url('https://kapitalbank.secure-login.example.com/')['findings']
    assert any(f['code'] == 'brand' for f in found)


# --- deception floor -------------------------------------------------------

@pytest.mark.parametrize('url', [
    'https://www.paypal.com@203.0.113.9/login',
    'https://paypa1.com/login',
    'https://xn--pypal-4ve.com/login',
])
def test_deception_lifts_band_to_suspicious(url):
    risk = scan_url(url)['risk']
    assert risk['score'] >= 31
    assert risk['level'] in ('Suspicious', 'Dangerous')
    assert risk['deceptionFloor']


def test_weak_signal_does_not_lift_band():
    risk = scan_url('https://invoice-verify.top/login')['risk']
    assert risk['level'] == 'Low risk'
    assert risk['deceptionFloor'] == []


def test_report_explains_the_floor():
    report = text_report(scan_url('https://www.paypal.com@203.0.113.9/login'))
    assert 'Deception floor applied' in report


# --- new HTML rules --------------------------------------------------------

@pytest.mark.parametrize('markup,code', [
    (b'<meta http-equiv="refresh" content="0;url=http://203.0.113.80/go">', 'meta_refresh'),
    (b'<iframe src="http://203.0.113.81/t" width="0" height="0"></iframe>', 'hidden_iframe'),
    (b'<iframe src="http://203.0.113.82/t" style="display:none"></iframe>', 'hidden_iframe'),
    (b'<a href="data:text/html;base64,PHA+">Invoice</a>', 'data_uri'),
])
def test_new_html_rules(markup, code):
    assert any(f['code'] == code for f in scan_bytes(markup, 'page.html')['findings'])


def test_plain_markup_stays_clean():
    found = scan_bytes(b'<html><p>Meeting notes for Tuesday.</p></html>', 'notes.html')['findings']
    assert not found


# --- saved .eml messages ---------------------------------------------------

def sample_eml(with_attachment=True):
    html = ('<html><body>'
            '<form action="https://collect.example.com/submit" method="post">'
            '<input type="password" name="p"></form>'
            '<p><a href="http://203.0.113.42/secure">https://www.mybank.example/login</a></p>'
            '</body></html>')
    msg = EmailMessage()
    msg['From'] = 'Billing <billing@secure-invoice.example.com>'
    msg['Reply-To'] = 'collect@payments-review.example.net'
    msg['To'] = 'victim@example.org'
    msg['Subject'] = 'Payment verification required'
    msg.set_content('Confirm at http://203.0.113.42/secure')
    msg.add_alternative(html, subtype='html')
    if with_attachment:
        msg.add_attachment(b'MZ' + b'\x90\x00' * 8 + b' inert fixture',
                           maintype='application', subtype='octet-stream',
                           filename='receipt.pdf.exe')
    return msg.as_bytes()


def test_eml_is_parsed_not_skipped():
    result = scan_bytes(sample_eml(), 'message.eml')
    assert result['metadata']['detectedType'] == 'Saved email message'
    assert any(c['label'] == 'Email body content' and c['status'] == 'complete'
               for c in result['checks'])


def test_eml_body_and_header_findings():
    result = scan_bytes(sample_eml(), 'message.eml')
    codes = {f['code'] for f in result['findings']}
    assert {'password_form', 'link_mismatch'} <= codes
    assert 'differ' in result['metadata']['message']['senderNote']


def test_eml_attachment_is_inspected():
    codes = {f['code'] for f in scan_bytes(sample_eml(), 'message.eml')['findings']}
    assert {'double_extension', 'executable'} <= codes


def test_eml_without_attachment_counts_zero():
    result = scan_bytes(sample_eml(with_attachment=False), 'message.eml')
    assert result['metadata']['message']['attachments'] == 0
