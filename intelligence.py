"""The five configured reputation providers. No target page is fetched."""
from __future__ import annotations
import asyncio
import base64
from collections import deque
import copy
import ipaddress
import os
import socket
import time
from urllib.parse import urlsplit
import httpx
from analysis import now

NAMES=('VirusTotal','PhishTank','URLhaus','AbuseIPDB','Pulsedive')

def truth(v):
    return v is True or str(v).lower() in ('true','yes','y','1')


def result(name,scope,state,status,detail,**extra):
    return dict(name=name,scope=scope,state=state,status=status,detail=detail,checked_at=now(),reputationPoints=0,hasEvidence=False,**extra)


def vt_points(stats):
    """Evidence-weighted integer score, never random or an infection probability.

    More distinct detections increase the signal with diminishing returns.
    Detection fraction is a bounded secondary adjustment. Versioned in reports.
    """
    m=max(0,int(stats.get('malicious',0)));s=max(0,int(stats.get('suspicious',0)))
    total=max(1,sum(max(0,int(stats.get(k,0))) for k in ('malicious','suspicious','undetected','harmless')))
    if m:return min(90,round(12+75*m/(m+8)+5*m/total))
    if s:return min(45,round(10+40*s/(s+8)+5*s/total))
    return 0


class Intelligence:
    def __init__(self,client,config=None):
        self.client=client
        self.config=config if config is not None else dict(os.environ)
        self.cache={}; self.inflight={}; self.hits=deque(); self.daily=deque(); self.slots=asyncio.Semaphore(4)
        self.pt_hits=deque()
    def key(self,name):
        return self.config.get(name,'')
    def reserve_vt(self):
        stamp=time.monotonic()
        while self.hits and stamp-self.hits[0]>=60: self.hits.popleft()
        while self.daily and stamp-self.daily[0]>=86400: self.daily.popleft()
        if len(self.hits)>=4 or len(self.daily)>=500: return False
        self.hits.append(stamp);self.daily.append(stamp);return True
    async def cached(self,name,identifier,work):
        key=(name,identifier); current=time.monotonic(); hit=self.cache.get(key)
        if hit and current-hit[0]<hit[2]:
            return {**copy.deepcopy(hit[1]),'cached':True}
        if key in self.inflight:
            return copy.deepcopy(await asyncio.shield(self.inflight[key]))
        task=asyncio.create_task(work()); self.inflight[key]=task
        try:
            row=await task
            if row['state']=='completed':
                if len(self.cache)>=256: self.cache.pop(next(iter(self.cache)))
                self.cache[key]=(time.monotonic(),copy.deepcopy(row),600 if row.get('hasEvidence') else 120)
            return row
        finally:
            self.inflight.pop(key,None)
    async def call(self,name,scope,method,url,**kwargs):
        try:
            async with self.slots:
                r=await self.client.request(method,url,**kwargs)
            if r.status_code in (429,509):
                return None,result(name,scope,'rate_limited','Rate limited',f'Provider HTTP {r.status_code}; try again later.')
            if r.status_code in (401,403):
                return None,result(name,scope,'error','Authentication / access error',f'Provider HTTP {r.status_code}; check credentials and account permissions.')
            if r.status_code==404:
                return None,result(name,scope,'completed','No record','No existing record found; this is not a safety guarantee.')
            if r.status_code!=200:
                return None,result(name,scope,'error','Provider error',f'Provider returned HTTP {r.status_code}.')
            data=r.json()
            if not isinstance(data,dict): raise ValueError('Unexpected shape')
            return data,None
        except httpx.TimeoutException:
            return None,result(name,scope,'error','Timed out','Provider did not respond within the configured timeout.')
        except (httpx.HTTPError,ValueError,TypeError):
            return None,result(name,scope,'error','Unavailable','Provider response could not be retrieved or parsed.')
    async def vt(self,identifier,kind='urls'):
        name='VirusTotal'; scope='File hash' if kind=='files' else 'Exact URL'
        async def work():
            if not self.key('VT_API_KEY'):
                return result(name,scope,'not_configured','Not configured','VT_API_KEY is not configured.')
            if not self.reserve_vt():
                return result(name,scope,'rate_limited','Local quota guard','4 requests/minute or 500/day reached in this process; provider quota may be lower if shared.')
            data,error=await self.call(name,scope,'GET',f'https://www.virustotal.com/api/v3/{kind}/{identifier}',headers={'x-apikey':self.key('VT_API_KEY')})
            if error:return error
            attrs=data.get('data',{}).get('attributes',{}); raw=attrs.get('last_analysis_stats') or {}
            stats={k:max(0,int(v)) for k,v in raw.items() if isinstance(v,(int,float))}
            malicious=stats.get('malicious',0); suspicious=stats.get('suspicious',0)
            useful=sum(stats.get(k,0) for k in ('malicious','suspicious','undetected','harmless'))
            verdict='malicious' if malicious else 'suspicious' if suspicious else 'no_indicators' if useful else 'unknown'
            row=result(name,scope,'completed','Flagged' if malicious or suspicious else 'Existing report',f'{malicious} malicious / {suspicious} suspicious engine result(s). Not a new scan.')
            row.update(stats=stats,verdict=verdict,hasEvidence=bool(useful),reputationPoints=vt_points(stats),
                       last_analysis_date=attrs.get('last_analysis_date'),engines=[{'engine_name':str(v.get('engine_name',k))[:100],'category':v.get('category','unknown'),'result':str(v.get('result') or '')[:200],'engine_update':v.get('engine_update')} for k,v in (attrs.get('last_analysis_results') or {}).items() if isinstance(v,dict)])
            return row
        return await self.cached(name,kind+':'+identifier,work)
    async def phishtank(self,url):
        name='PhishTank';scope='Exact URL'
        async def work():
            if self.key('PHISHTANK_ENABLED').lower() in ('false','0','no'):
                return result(name,scope,'not_configured','Disabled','Enable PHISHTANK_ENABLED to use this provider.')
            stamp=time.monotonic()
            while self.pt_hits and stamp-self.pt_hits[0]>=60:self.pt_hits.popleft()
            if len(self.pt_hits)>=10:return result(name,scope,'rate_limited','Local quota guard','10 PhishTank requests/minute reached; provider limits may be stricter.')
            self.pt_hits.append(stamp)
            body={'url':url,'format':'json'}
            if self.key('PHISHTANK_APP_KEY'):body['app_key']=self.key('PHISHTANK_APP_KEY')
            data,error=await self.call(name,scope,'POST','https://checkurl.phishtank.com/checkurl/',data=body,headers={'User-Agent':self.key('PHISHTANK_USER_AGENT') or 'phishtank/ArgusAI-student-project'})
            if error:return error
            d=data.get('results')
            if not isinstance(d,dict):return result(name,scope,'error','Unexpected response','PhishTank did not return a URL result.')
            in_db=truth(d.get('in_database')); verified=truth(d.get('verified'));valid=truth(d.get('valid'));confirmed=in_db and verified and valid
            status='Verified phishing' if confirmed else 'Reported, unverified' if in_db and not verified else 'Known, no current positive verdict' if in_db else 'No record'
            row=result(name,scope,'completed',status,'Exact-URL database lookup; absence is not evidence of safety.')
            row.update(verdict='malicious' if confirmed else 'unknown',hasEvidence=confirmed,reputationPoints=90 if confirmed else 0,in_database=in_db,verified=verified,valid=valid,phish_id=d.get('phish_id'),verified_at=d.get('verified_at'))
            return row
        return await self.cached(name,url,work)
    async def urlhaus(self,url):
        name='URLhaus';scope='Exact URL / malware delivery'
        async def work():
            if not self.key('URLHAUS_AUTH_KEY'):return result(name,scope,'not_configured','Not configured','URLHAUS_AUTH_KEY is required.')
            data,error=await self.call(name,scope,'POST','https://urlhaus-api.abuse.ch/v1/url/',headers={'Auth-Key':self.key('URLHAUS_AUTH_KEY')},data={'url':url})
            if error:return error
            status=data.get('query_status')
            if status=='ok':
                row=result(name,scope,'completed','Malware URL listed','URL is recorded as a malware-delivery URL; this does not establish the exact phishing technique.')
                row.update(verdict='malicious',reputationPoints=85,hasEvidence=True,url_status=data.get('url_status'),date_added=data.get('date_added'));return row
            if status in ('no_results','no_result'):
                return result(name,scope,'completed','No record','No malware-delivery URL record found; phishing can still be present.')
            return result(name,scope,'error','Provider query rejected','URLhaus did not return a recognized successful result.')
        return await self.cached(name,url,work)
    async def pulsedive(self,domain):
        name='Pulsedive';scope='Domain'
        async def work():
            if not self.key('PULSEDIVE_API_KEY'):return result(name,scope,'not_configured','Not configured','PULSEDIVE_API_KEY is not configured.')
            data,error=await self.call(name,scope,'GET','https://pulsedive.com/api/indicator.php',params={'indicator':domain,'key':self.key('PULSEDIVE_API_KEY')})
            if error:return error
            if data.get('error'):
                message=str(data['error']).lower()
                if 'not found' in message or 'not exist' in message:return result(name,scope,'completed','No record','Domain indicator not found; this does not establish safety.')
                return result(name,scope,'error','Provider query rejected','Pulsedive returned an error. Check key and account limits.')
            level=str(data.get('risk','unknown')).lower()
            if level not in ('none','low','medium','high','critical','unknown'):
                return result(name,scope,'error','Unexpected risk value','No interpretable risk result was returned.')
            row=result(name,scope,'completed',level.title()+' domain risk','Provider domain risk context, not a phishing probability.')
            row.update(risk=level,hasEvidence=level!='unknown',reputationPoints={'critical':55,'high':40,'medium':20}.get(level,0),verdict='suspicious' if level in ('medium','high','critical') else 'unknown');return row
        return await self.cached(name,domain,work)
    async def resolve(self,domain):
        try:
            addresses=await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo,domain,None),timeout=4)
            for info in addresses:
                value=info[4][0]; ip=ipaddress.ip_address(value)
                if ip.is_global and not ip.is_multicast:return value
        except (OSError,ValueError,asyncio.TimeoutError):pass
        return None
    async def abuse(self,domain):
        name='AbuseIPDB';scope='Resolved public IP'
        if not self.key('ABUSEIPDB_API_KEY'):return result(name,scope,'not_configured','Not configured','ABUSEIPDB_API_KEY is not configured.')
        ip=await self.resolve(domain)
        if not ip:return result(name,scope,'skipped','No public IP','Public IP resolution failed or resolved only private / special addresses.')
        async def work():
            data,error=await self.call(name,scope,'GET','https://api.abuseipdb.com/api/v2/check',params={'ipAddress':ip,'maxAgeInDays':'90'},headers={'Key':self.key('ABUSEIPDB_API_KEY'),'Accept':'application/json'})
            if error:return error
            value=data.get('data',{}).get('abuseConfidenceScore')
            if not isinstance(value,(int,float)) or not 0<=value<=100:return result(name,scope,'error','Invalid response','Provider did not return an IP abuse score.')
            row=result(name,scope,'completed',f'{int(value)}/100 IP abuse','IP reputation is not a phishing probability; shared hosting may affect unrelated sites.')
            row.update(ip=ip,score=int(value),hasEvidence=True,reputationPoints=round(value*.2) if value>=50 else 0);return row
        return await self.cached(name,ip,work)
    async def url(self,value):
        domain=urlsplit(value).hostname or ''
        try:private=not ipaddress.ip_address(domain).is_global
        except ValueError:private=domain.lower()=='localhost' or domain.lower().endswith('.localhost')
        if private:return [result(n,'URL','skipped','Private target','Private / localhost targets are not sent to external intelligence providers.') for n in NAMES]
        uid=base64.urlsafe_b64encode(value.encode()).decode().rstrip('=')
        results=await asyncio.gather(self.vt(uid),self.phishtank(value),self.urlhaus(value),self.abuse(domain),self.pulsedive(domain),return_exceptions=True)
        return [r if isinstance(r,dict) else result(n,'URL','error','Provider unavailable','This source failed independently; other results remain usable.') for n,r in zip(NAMES,results)]
