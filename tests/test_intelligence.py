import asyncio
import base64
import httpx
import pytest
from intelligence import Intelligence,NAMES

CONFIG={'VT_API_KEY':'test-vt','PHISHTANK_APP_KEY':'test-pt','URLHAUS_AUTH_KEY':'test-uh','ABUSEIPDB_API_KEY':'test-ab','PULSEDIVE_API_KEY':'test-pd'}

def run(coro):return asyncio.run(coro)

def test_all_five_sources_and_payloads():
    calls=[]
    def handler(r):
        calls.append(r)
        if 'virustotal' in r.url.host:
            assert r.method=='GET' and r.headers['x-apikey']=='test-vt'
            return httpx.Response(200,json={'data':{'attributes':{'last_analysis_stats':{'malicious':3,'undetected':50},'last_analysis_results':{'Malwarebytes':{'engine_name':'Malwarebytes','category':'malicious','result':'Test fixture detection'}}}}})
        if 'phishtank' in r.url.host:
            assert r.method=='POST';assert b'app_key=test-pt' in r.content;assert 'phishtank/' in r.headers['user-agent']
            return httpx.Response(200,json={'results':{'in_database':True,'verified':'y','valid':'y','phish_id':123}})
        if 'urlhaus' in r.url.host:
            assert r.headers['Auth-Key']=='test-uh';return httpx.Response(200,json={'query_status':'no_results'})
        if 'abuseipdb' in r.url.host:
            assert r.url.params['ipAddress']=='8.8.8.8';return httpx.Response(200,json={'data':{'abuseConfidenceScore':90}})
        if 'pulsedive' in r.url.host:
            assert r.url.path=='/api/indicator.php';return httpx.Response(200,json={'risk':'medium'})
        raise AssertionError('Unexpected host')
    async def work():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            intel=Intelligence(client,CONFIG)
            async def resolve(domain):return '8.8.8.8'
            intel.resolve=resolve
            rows=await intel.url('https://example.com/')
            assert [p['name'] for p in rows]==list(NAMES)
            assert all(p['state']=='completed' for p in rows)
            assert rows[1]['reputationPoints']==90 and rows[1]['verified']
            assert rows[2]['status']=='No record' and rows[2]['reputationPoints']==0
            assert rows[3]['reputationPoints']==18
            assert rows[0]['engines'][0]['engine_name']=='Malwarebytes'
            assert len(calls)==5
            cached=await intel.url('https://example.com/')
            assert all(row.get('cached') for row in cached)
            assert len(calls)==5
    run(work())

@pytest.mark.parametrize('verified,valid,expected',[('n','y',0),('y','n',0),('false','true',0),(True,True,90)])
def test_phishtank_validation(verified,valid,expected):
    async def work():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:httpx.Response(200,json={'results':{'in_database':True,'verified':verified,'valid':valid}}))) as c:
            row=await Intelligence(c,{}).phishtank('https://example.com')
            assert row['reputationPoints']==expected
    run(work())

@pytest.mark.parametrize('status,state',[(429,'rate_limited'),(509,'rate_limited'),(401,'error'),(403,'error'),(500,'error'),(404,'completed')])
def test_provider_status_is_not_clean(status,state):
    async def work():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:httpx.Response(status,json={}))) as c:
            row=await Intelligence(c,CONFIG).vt('x')
            assert row['state']==state and row['reputationPoints']==0
    run(work())


def test_empty_stats_and_vt_quota():
    calls=[]
    def handler(r):calls.append(r);return httpx.Response(200,json={'data':{'attributes':{'last_analysis_stats':{}}}})
    async def work():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            intel=Intelligence(c,CONFIG)
            for i in range(4):
                row=await intel.vt(str(i));assert not row['hasEvidence'] and row['verdict']=='unknown'
            limited=await intel.vt('5')
            assert limited['state']=='rate_limited' and len(calls)==4
    run(work())


def test_missing_keys_and_private_target_no_network():
    def handler(r):raise AssertionError('Should not request a provider')
    async def work():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            intel=Intelligence(c,{'PHISHTANK_ENABLED':'false'})
            rows=await intel.url('http://127.0.0.1/')
            assert all(p['state']=='skipped' for p in rows)
            assert (await intel.vt('x'))['state']=='not_configured'
            assert (await intel.phishtank('https://example.com'))['state']=='not_configured'
    run(work())


def test_concurrent_duplicate_only_one_request():
    calls=[]
    async def handler(r):
        calls.append(r);await asyncio.sleep(.01)
        return httpx.Response(404,json={})
    async def work():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            intel=Intelligence(c,CONFIG)
            rows=await asyncio.gather(*(intel.vt('same') for _ in range(5)))
            assert len(calls)==1 and all(p['state']=='completed' for p in rows)
    run(work())


def test_timeout_only_stats_do_not_establish_safety():
    async def work():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:httpx.Response(200,json={'data':{'attributes':{'last_analysis_stats':{'timeout':70}}}}))) as c:
            row=await Intelligence(c,CONFIG).vt('timeout-only','files')
            assert row['verdict']=='unknown' and not row['hasEvidence'] and row['reputationPoints']==0
    run(work())
