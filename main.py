from __future__ import annotations
from collections import OrderedDict,deque
from contextlib import asynccontextmanager
import asyncio
import base64
import copy
import hmac
import io
import os
from pathlib import Path
import secrets
import time
from dotenv import load_dotenv
import httpx
from fastapi import FastAPI,HTTPException,Request,UploadFile,File
from fastapi.responses import FileResponse,PlainTextResponse,JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel,Field
import analysis
from intelligence import Intelligence,result,NAMES
from mail_analysis import fetch_mail,parse_mail
from reports import text_report,generate_ai

load_dotenv()
BASE=Path(__file__).resolve().parent
REPORT_TTL=30*60
class BodyLimit:
    def __init__(self,app):self.app=app;self.uploads=asyncio.Semaphore(2)
    async def __call__(self,scope,receive,send):
        if scope['type']!='http':return await self.app(scope,receive,send)
        limit=analysis.MAX_FILE_SIZE+1024*1024 if scope.get('path')=='/analyze/file' else 64*1024
        headers=dict(scope.get('headers',[]))
        try:length=int(headers.get(b'content-length',b'0'))
        except ValueError:length=0
        if length>limit:
            return await JSONResponse({'detail':'Request exceeds the configured size limit (file maximum: 200 MiB).'},status_code=413)(scope,receive,send)
        total=0
        async def bounded_receive():
            nonlocal total
            message=await receive()
            if message['type']=='http.request':
                total+=len(message.get('body',b''))
                if total>limit:raise HTTPException(413,'Request exceeds the configured size limit.')
            return message
        if scope.get('path')=='/analyze/file':
            if self.uploads.locked():
                return await JSONResponse({'detail':'The server is processing two file uploads. Please retry shortly.'},status_code=429)(scope,receive,send)
            async with self.uploads:
                await self.app(scope,bounded_receive,send)
        else:
            await self.app(scope,bounded_receive,send)


@asynccontextmanager
async def lifespan(app):
    client=httpx.AsyncClient(timeout=httpx.Timeout(10,connect=5),follow_redirects=False,headers={'User-Agent':'PhishingHUB/2.0'})
    app.state.client=client;app.state.config=dict(os.environ);app.state.intel=Intelligence(client,app.state.config)
    app.state.reports=OrderedDict();app.state.ai_hits={};app.state.analysis_slots=asyncio.Semaphore(2);app.state.mail_lock=asyncio.Lock();app.state.report_tasks={}
    try:yield
    finally:await client.aclose()

app=FastAPI(title='PhishingHUB',version='2.0',lifespan=lifespan)
app.add_middleware(BodyLimit)
app.mount('/static',StaticFiles(directory=BASE/'static'),name='static')

@app.middleware('http')
async def headers(request,call_next):
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['X-Frame-Options']='SAMEORIGIN'
    response.headers['Cache-Control']='no-store' if request.url.path.startswith(('/analyze/','/reports/')) else 'no-cache'
    return response

@app.get('/')
async def index():return FileResponse(BASE/'index.html')

@app.get('/health')
async def health(request:Request):
    c=request.app.state.config
    return {'status':'ok','max_file_bytes':analysis.MAX_FILE_SIZE,'sources':{'VirusTotal':bool(c.get('VT_API_KEY')),'PhishTank':c.get('PHISHTANK_ENABLED','true').lower() not in ('false','0','no'),'URLhaus':bool(c.get('URLHAUS_AUTH_KEY')),'AbuseIPDB':bool(c.get('ABUSEIPDB_API_KEY')),'Pulsedive':bool(c.get('PULSEDIVE_API_KEY'))},'ai_configured':bool(c.get('OPENROUTER_API_KEY')),'imap_configured':all(c.get(k) for k in ('IMAP_USER','IMAP_PASS')) and bool(c.get('IMAP_SCAN_TOKEN') or open_imap(c)),'imap_open_access':open_imap(c)}

def remember(request,a):
    store=request.app.state.reports;stamp=time.monotonic()
    for key,(created,_) in list(store.items()):
        if stamp-created>REPORT_TTL:store.pop(key,None)
    while len(store)>=64:store.popitem(last=False)
    token=secrets.token_urlsafe(24);a['report_id']=token;analysis.finish(a)
    store[token]=(stamp,copy.deepcopy(a));return a

def open_imap(config):
    return str(config.get('IMAP_OPEN_ACCESS','')).strip().lower() in ('true','1','yes','on')


def get_report(request,token):
    entry=request.app.state.reports.get(token)
    if not entry or time.monotonic()-entry[0]>REPORT_TTL:raise HTTPException(404,'Report expired or unavailable. Run the check again; downloaded reports remain on your device.')
    return entry[1]

class URLRequest(BaseModel):url:str=Field(min_length=1,max_length=2048)
class URLBatch(BaseModel):urls:list[str]=Field(min_length=1,max_length=10)

async def enrich_url(request,value):
    try:a=analysis.url_analysis(value)
    except ValueError as e:raise HTTPException(422,str(e))
    a['providers']=await request.app.state.intel.url(a['target']);analysis.finish(a);return a

@app.post('/analyze/url')
async def analyze_url(request:Request,body:URLRequest):
    return remember(request,await enrich_url(request,body.url))

@app.post('/analyze/urls')
async def analyze_urls(request:Request,body:URLBatch):
    unique=[];invalid=[]
    for value in body.urls:
        try:u=analysis.normalize_url(value)
        except ValueError as e:invalid.append({'input':value[:100],'detail':str(e)});continue
        if u not in unique:unique.append(u)
    children=await asyncio.gather(*(enrich_url(request,u) for u in unique))
    a=analysis.record('batch',f'{len(children)} unique URL(s)');a['urlResults']=children;a['errors']=invalid;a['duplicates_removed']=len(body.urls)-len(invalid)-len(unique)
    for child in children:
        for f in child['findings']:analysis.finding(a,f['code'],child['target']+': '+f['evidence'],f['source'])
        a['links']+=child['links']
    a['providers']=summarize_providers(children,'Batch URL checks')
    analysis.check(a,'URL content','complete' if children else 'skipped',f'{len(children)} valid unique URLs checked; {len(invalid)} rejected.')
    return remember(request,a)

async def enrich_file(request,a):
    a['providers']=[await request.app.state.intel.vt(a['sha256'],'files')]
    # A file's links remain separate child indicators, never confused with its hash result.
    children=await asyncio.gather(*(enrich_url(request,u) for u in a['links'][:5]))
    a['urlResults']=children
    if len(a['links'])>5:a['limitations'].append('Only the first 5 unique extracted URLs received external intelligence checks.')
    a['linkedReputationPoints']=max((c['risk']['reputation'] for c in children),default=0)
    a['linkedReputationEvidence']=[{'target':c['target'],'points':c['risk']['reputation']} for c in children if c['risk']['reputation']]
    return analysis.finish(a)

@app.post('/analyze/file')
async def analyze_file(request:Request,file:UploadFile=File(...)):
    try:
        async with request.app.state.analysis_slots:
            size=0
            while chunk:=await file.read(1024*1024):
                size+=len(chunk)
                if size>analysis.MAX_FILE_SIZE:raise HTTPException(413,'File exceeds 200 MiB.')
            if not size:raise HTTPException(422,'Select a non-empty file.')
            await file.seek(0)
            a=await asyncio.to_thread(analysis.file_analysis,file.file,file.filename or 'file.bin',size)
            return remember(request,await enrich_file(request,a))
    finally:await file.close()

class HashRequest(BaseModel):
    sha256:str=Field(pattern=r'^[a-fA-F0-9]{64}$')
    file_size:int=Field(default=0,ge=0,le=analysis.MAX_FILE_SIZE)

@app.post('/analyze/hash')
async def analyze_hash(request:Request,body:HashRequest):
    a=analysis.record('file',body.sha256.lower());a['sha256']=body.sha256.lower();a['metadata']['fileSize']=body.file_size
    analysis.check(a,'File content','skipped','Hash-only request: content was not provided.')
    a['providers']=[await request.app.state.intel.vt(a['sha256'],'files')];return remember(request,a)

def summarize_providers(rows,scope):
    out=[]
    for name in NAMES:
        matching=[p for row in rows for p in row['providers'] if p['name']==name]
        completed=[p for p in matching if p['state']=='completed']
        if not matching:continue
        flagged=[p for p in completed if p.get('reputationPoints',0)]
        aggregate=result(name,scope,'completed' if completed else matching[0]['state'],f'{len(completed)}/{len(matching)} responses',f'{len(flagged)} positive risk-context result(s). See individual indicators for exact source results.')
        aggregate.update(hasEvidence=any(p.get('hasEvidence') for p in matching),reputationPoints=max([0]+[p.get('reputationPoints',0) for p in matching]),results=matching)
        out.append(aggregate)
    return out

@app.post('/analyze/imap')
async def analyze_imap(request:Request):
    c=request.app.state.config;expected=c.get('IMAP_SCAN_TOKEN','')
    # Opt-in demo switch. With IMAP_OPEN_ACCESS set, a live presentation needs no
    # typing. It is off by default on purpose: without the access code, anyone who
    # holds this URL can read the configured mailbox.
    if not open_imap(c):
        if not expected:raise HTTPException(503,'IMAP is not configured for access.')
        if not hmac.compare_digest(request.headers.get('x-imap-token','').strip(),expected.strip()):raise HTTPException(403,'Incorrect IMAP access code.')
    if not c.get('IMAP_USER') or not c.get('IMAP_PASS'):raise HTTPException(503,'IMAP credentials are not configured.')
    async with request.app.state.mail_lock:
        try:raw=await asyncio.wait_for(asyncio.to_thread(fetch_mail,c),timeout=75)
        except asyncio.TimeoutError:raise HTTPException(504,'Mailbox inspection timed out. Retry later.')
        except Exception:raise HTTPException(502,'Mailbox connection failed. Check server, credentials and provider app-password settings.')
        messages=[];skipped=[]
        for item in raw:
            if item.get('skipped'):skipped.append(item['detail']);continue
            try:a=await asyncio.to_thread(parse_mail,item['raw'])
            except Exception:
                skipped.append('One malformed message could not be inspected.');continue
            urls=await asyncio.gather(*(enrich_url(request,u) for u in a['links'][:5]))
            attachments=[]
            for child in a['attachments']:attachments.append(await enrich_file(request,child))
            a['urlResults']=urls;a['attachments']=attachments
            nested=[u for child in attachments for u in child.get('urlResults',[])]
            a['providers']=summarize_providers(urls+attachments+nested,'Email URLs / attachment hashes')
            messages.append(analysis.finish(a))
        parent=analysis.record('imap',f'{len(messages)} unread message(s) inspected');parent['messages']=messages;parent['urlResults']=[];parent['attachments']=[]
        parent['metadata']['message']=messages[0]['metadata']['message'] if len(messages)==1 else {'subject':f'{len(messages)} messages','from':'See individual messages','replyTo':'See individual messages','attachments':sum(m['metadata']['message']['attachments'] for m in messages)}
        for m in messages:
            for f in m['findings']:analysis.finding(parent,f['code'],m['target']+': '+f['evidence'],f['source'])
            parent['links']+=m['links']
            parent['urlResults']+=m['urlResults'];parent['attachments']+=m['attachments']
        parent['links']=list(dict.fromkeys(parent['links']))[:50];parent['providers']=summarize_providers(messages,'Mailbox indicators')
        analysis.check(parent,'Email body content','complete' if messages else 'skipped',f'{len(messages)} messages inspected; {len(skipped)} skipped.')
        parent['limitations']+=skipped+['No independent SPF/DKIM/DMARC verification. Header comparison is not proof of spoofing.','Each message: at most 5 external URL checks and 3 attachment inspections.']
        return remember(request,parent)

@app.get('/reports/{token}/download')
async def download_report(token:str,request:Request):
    return PlainTextResponse(text_report(get_report(request,token)),headers={'Content-Disposition':'attachment; filename="PhishingHUB-analysis-report.txt"'})

@app.post('/reports/{token}/ai')
async def ai_report(token:str,request:Request):
    a=get_report(request,token)
    if a.get('ai_summary'):return {'summary':a['ai_summary'],'generator':'AI-assisted'}
    address=request.client.host if request.client else 'unknown';stamp=time.monotonic();hits=request.app.state.ai_hits
    if len(hits)>1000:
        for key,values in list(hits.items()):
            if not values or stamp-values[-1]>=60:hits.pop(key,None)
    recent=[t for t in hits.get(address,[]) if stamp-t<60]
    if len(recent)>=5:raise HTTPException(429,'AI report limit: 5 requests per minute per client.')
    recent.append(stamp);hits[address]=recent
    if token in request.app.state.report_tasks:
        task=request.app.state.report_tasks[token]
    else:
        task=asyncio.create_task(generate_ai(a,request.app.state.client,request.app.state.config));request.app.state.report_tasks[token]=task
    try:value,error=await asyncio.shield(task)
    finally:
        if task.done():request.app.state.report_tasks.pop(token,None)
    if error:raise HTTPException(503,error)
    a['ai_summary']=value
    return {'summary':value,'generator':'AI-assisted','language':'en'}
