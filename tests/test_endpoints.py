import io
from email.message import EmailMessage
import pytest
from fastapi.testclient import TestClient
import httpx
import main
import analysis
from intelligence import result
from test_analysis import office

@pytest.fixture
def client(monkeypatch):
    # No real source or mailbox is used in automated tests.
    with TestClient(main.app) as c:
        async def urls(value):
            rows=[result(n,'Exact URL' if n!='AbuseIPDB' else 'IP','completed','No record','Test transport: no record.') for n in ('VirusTotal','PhishTank','URLhaus','AbuseIPDB','Pulsedive')]
            if 'paypa1' in value:
                rows[1].update(status='Verified phishing',reputationPoints=90,hasEvidence=True,verdict='malicious')
            return rows
        async def vt(identifier,kind='urls'):
            return result('VirusTotal','File hash','completed','No record','No file report.')
        monkeypatch.setattr(main.app.state.intel,'url',urls)
        monkeypatch.setattr(main.app.state.intel,'vt',vt)
        yield c


def test_real_page_has_no_samples(client):
    h=client.get('/').text
    assert 'data-score-sample' not in h and 'id="open-example"' not in h
    assert 'id="imap-token"' in h
    assert client.get('/static/app.js').status_code==200
    assert client.get('/static/styles.css').status_code==200
    assert client.get('/health').json()['max_file_bytes']==200*1024*1024


def test_url_and_report_provenance(client):
    r=client.post('/analyze/url',json={'url':'https://paypa1.com'})
    assert r.status_code==200
    data=r.json();assert data['risk']['score']==100 and len(data['providers'])==5
    report=client.get('/reports/'+data['report_id']+'/download')
    assert report.status_code==200
    assert 'PhishTank' in report.text and 'SOURCE-BY-SOURCE RESULTS' in report.text
    assert 'SAMPLE CASE' not in report.text
    assert 'SPF' not in report.text and 'Reply-To:' not in report.text


def test_url_validation_and_batch(client):
    assert client.post('/analyze/url',json={'url':'javascript:alert(1)'}).status_code==422
    r=client.post('/analyze/urls',json={'urls':['https://example.com','https://example.com/','invalid']})
    assert r.status_code==200 and r.json()['duplicates_removed']==1 and len(r.json()['errors'])==1


def test_file_has_local_content_and_file_sources(client):
    stream=office()
    data=client.post('/analyze/file',files={'file':('test.docx',stream.getvalue())}).json()
    assert data['kind']=='file' and data['sha256']
    assert len(data['providers'])==1 and data['providers'][0]['name']=='VirusTotal'
    assert any(f['code']=='link_mismatch' for f in data['findings'])
    assert data['urlResults'][0]['kind']=='url'
    assert 'message' not in data['metadata']


def test_file_child_reputation_is_preserved(client):
    data=client.post('/analyze/file',files={'file':('links.txt',b'https://paypa1.com')}).json()
    assert data['linkedReputationPoints']==90
    assert data['risk']['reputation']==90 and data['risk']['score']==100
    assert data['providers'][0]['reputationPoints']==0  # not falsely attributed to VT file lookup


def test_empty_oversized_and_chunked_requests(client,monkeypatch):
    assert client.post('/analyze/file',files={'file':('empty.txt',b'')}).status_code==422
    assert client.post('/analyze/file',content=b'',headers={'Content-Length':str(201*1024*1024+1)}).status_code==413
    monkeypatch.setattr(analysis,'MAX_FILE_SIZE',1024)
    assert client.post('/analyze/file',files={'file':('large.txt',b'x'*1025)}).status_code==413
    def body():
        yield b'x'*(64*1024)
        yield b'x'*(64*1024)
    assert client.post('/analyze/url',content=body(),headers={'Content-Type':'application/json'}).status_code==413


def test_hash_metadata_limit_and_unknown(client):
    assert client.post('/analyze/hash',json={'sha256':'a'*64,'file_size':201*1024*1024}).status_code==422
    d=client.post('/analyze/hash',json={'sha256':'a'*64,'file_size':100}).json()
    assert d['risk']['score'] is None


def test_imap_access_and_message_isolation(client,monkeypatch):
    main.app.state.config.update(IMAP_USER='user@example.test',IMAP_PASS='unused',IMAP_SCAN_TOKEN='private-code')
    assert client.post('/analyze/imap').status_code==403
    msg=EmailMessage();msg['From']='billing@sender.example';msg['Reply-To']='support@other.example';msg['Subject']='Review';msg.set_content('https://paypa1.com')
    monkeypatch.setattr(main,'fetch_mail',lambda config:[{'raw':msg.as_bytes()}])
    d=client.post('/analyze/imap',headers={'X-IMAP-Token':'private-code'}).json()
    assert d['kind']=='imap' and len(d['messages'])==1
    assert d['metadata']['message']['from']=='billing@sender.example'
    assert d['risk']['score']>=90
    text=client.get('/reports/'+d['report_id']+'/download').text
    assert 'From:' in text and 'PhishTank' in text


def test_ai_english_evidence_and_score_immutable(client,monkeypatch):
    async def fake(a,c,config):
        from reports import AI_PROMPT,ai_context
        assert 'English' in AI_PROMPT
        assert 'test-vt' not in ai_context(a)
        return 'Assessment: the supplied evidence warrants review.',None
    monkeypatch.setattr(main,'generate_ai',fake)
    d=client.post('/analyze/url',json={'url':'https://paypa1.com'}).json()
    r=client.post('/reports/'+d['report_id']+'/ai')
    assert r.status_code==200 and r.json()['language']=='en'
    store=main.get_report(type('Request',(),{'app':main.app})(),d['report_id'])
    assert store['risk']==d['risk']
    assert 'OPTIONAL AI SUMMARY' in client.get('/reports/'+d['report_id']+'/download').text


def test_unknown_report(client):
    assert client.get('/reports/does-not-exist/download').status_code==404


def test_mail_attachment_link_reputation_propagates(client,monkeypatch):
    main.app.state.config.update(IMAP_USER='qa',IMAP_PASS='unused',IMAP_SCAN_TOKEN='private-code')
    msg=EmailMessage();msg['From']='billing@sender.example';msg['Subject']='Attached link';msg.set_content('Please see attachment.')
    msg.add_attachment(b'https://paypa1.com',maintype='text',subtype='plain',filename='links.txt')
    monkeypatch.setattr(main,'fetch_mail',lambda c:[{'raw':msg.as_bytes()}])
    data=client.post('/analyze/imap',headers={'X-IMAP-Token':'private-code'}).json()
    assert data['risk']['reputation']==90
    assert data['messages'][0]['attachments'][0]['urlResults'][0]['risk']['score']==100
