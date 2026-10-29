import io
import zipfile
import pytest
import analysis as a
from mail_analysis import parse_mail,fetch_mail
from email.message import EmailMessage


def office(display='https://paypal.com',target='https://paypal.com.attacker.co.uk/',macro=False,embedded=False,compression=zipfile.ZIP_DEFLATED):
    out=io.BytesIO()
    with zipfile.ZipFile(out,'w',compression) as z:
        z.writestr('[Content_Types].xml','<Types/>')
        z.writestr('word/document.xml',f'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><w:body><w:hyperlink r:id="rId1"><w:r><w:t>{display}</w:t></w:r></w:hyperlink></w:body></w:document>')
        z.writestr('word/_rels/document.xml.rels',f'<Relationships><Relationship Id="rId1" Target="{target}" TargetMode="External" Type="hyperlink"/></Relationships>')
        if macro:z.writestr('word/vbaProject.bin',b'inert fixture, not VBA code')
        if embedded:z.writestr('word/embeddings/object.bin',b'inert object')
    out.seek(0);return out

@pytest.mark.parametrize('url', ['https://paypal.com','https://login.paypal.com','https://accounts.google.com','https://microsoft.com'])
def test_official_domains(url):
    assert not a.url_analysis(url)['findings']

@pytest.mark.parametrize('url,code',[
 ('https://paypa1.com','brand'),('https://paypal.com.attacker.co.uk','brand'),
 ('https://bank.example@other.test','userinfo'),('http://8.8.8.8','ip_host'),
 ('https://xn--bcher-kva.de','punycode')])
def test_url_findings(url,code):
    assert any(f['code']==code for f in a.url_analysis(url)['findings'])

@pytest.mark.parametrize('value',['ftp://example.com','not a url','http://','https://a.com:99999','https://a.com/a b'])
def test_invalid_url(value):
    with pytest.raises(ValueError):a.url_analysis(value)


def test_docx_links_macro_and_cap():
    stream=office(macro=True,embedded=True);n=len(stream.getbuffer())
    row=a.file_analysis(stream,'invoice.docm',n)
    assert {'macro','embedded','link_mismatch','brand'} <= {f['code'] for f in row['findings']}
    assert row['links']==['https://paypal.com.attacker.co.uk/']
    assert a.risk(row)['local']==70
    assert row['sha256']


def test_benign_document_low_score():
    stream=office('Company website','https://example.com')
    row=a.file_analysis(stream,'hello.docx',len(stream.getbuffer()))
    assert not row['findings'];assert a.risk(row)['score']==0


def test_unsupported_withheld_not_clean():
    row=a.file_analysis(io.BytesIO(b'\x00\x01\x02\x03'),'unknown.bin',4)
    assert a.finish(row)['risk']['score'] is None
    assert row['verdict']=='unknown'


def test_html_inert_link_and_password():
    data=b'<a href="https://other.example">https://paypal.com</a><form action="https://other.example"><input type="password"></form>'
    row=a.file_analysis(io.BytesIO(data),'message.html',len(data))
    assert {'link_mismatch','password_form'}<={f['code'] for f in row['findings']}


def test_disguised_header_and_pdf_scope():
    row=a.file_analysis(io.BytesIO(b'MZ-inert-test'),'invoice.pdf',13)
    assert row['findings'][0]['code']=='disguised_executable'
    pdf=b'%PDF-1.7 /JavaScript /Launch'
    row=a.file_analysis(io.BytesIO(pdf),'sample.pdf',len(pdf))
    assert all(c['status']!='complete' for c in row['checks'] if c['label']=='PDF marker content')
    assert {'pdf_js','pdf_launch'}<={f['code'] for f in row['findings']}


def test_risk_dedup_and_correlated_reputation():
    row=a.url_analysis('https://paypa1.com')
    a.finding(row,'brand','A second observation for same rule')
    row['providers']=[{'state':'completed','reputationPoints':90},{'state':'completed','reputationPoints':85}]
    score=a.risk(row)
    assert score['local']==25 and score['reputation']==90 and score['score']==100


def test_limits_and_bad_office():
    with pytest.raises(ValueError):a.file_analysis(io.BytesIO(), 'x', a.MAX_FILE_SIZE+1)
    row=a.file_analysis(io.BytesIO(b'PK-invalid'),'broken.docx',10)
    assert any(c['status']=='skipped' for c in row['checks'])


def test_xml_entities_not_expanded():
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as z:
        z.writestr('[Content_Types].xml','<Types/>');z.writestr('word/document.xml','<!DOCTYPE x [<!ENTITY e "danger">]><document>&e;</document>')
    stream.seek(0);row=a.file_analysis(stream,'test.docx',len(stream.getbuffer()))
    assert any(c['status']=='partial' for c in row['checks'])


def test_mail_sender_only_and_no_forged_auth():
    msg=EmailMessage();msg['Subject']='Payment review';msg['From']='Billing <billing@sender.example>';msg['Reply-To']='support@other.example';msg['Authentication-Results']='attacker; spf=pass; dkim=pass; dmarc=pass';msg.set_content('Review https://paypa1.com');msg.add_alternative('<a href="https://other.example">https://paypal.com</a>',subtype='html')
    row=parse_mail(msg.as_bytes())
    assert row['metadata']['message']['spf']=='Not independently verified'
    assert row['kind']=='imap';assert 'message' not in a.url_analysis('https://example.com')['metadata']
    assert any(f['code']=='link_mismatch' for f in row['findings'])


def test_imap_readonly_and_peek(monkeypatch):
    import mail_analysis
    msg=EmailMessage();msg.set_content('Hello');raw=msg.as_bytes()
    class Mail:
        def __init__(self,*args,**kwargs):assert kwargs['timeout']==15
        def login(self,*args):pass
        def select(self,folder,readonly):assert readonly;return 'OK',[]
        def search(self,*args):return 'OK',[b'1']
        def fetch(self,n,part):
            if part=='(RFC822.SIZE)':return 'OK',[b'1 (RFC822.SIZE '+str(len(raw)).encode()+b')']
            assert part=='(BODY.PEEK[])';return 'OK',[(b'1',raw)]
        def logout(self):pass
    monkeypatch.setattr(mail_analysis.imaplib,'IMAP4_SSL',Mail)
    assert fetch_mail({})[0]['raw']==raw
