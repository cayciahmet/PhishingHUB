"""Bounded, non-executing local inspection and explainable risk model."""
from __future__ import annotations
from datetime import datetime, timezone
from difflib import SequenceMatcher
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit
import email
from email import policy
from email.utils import parseaddr
import io
import hashlib
import ipaddress
import re
import zipfile
from defusedxml import ElementTree as ET
import tldextract

MAX_FILE_SIZE = 200 * 1024 * 1024
MAX_XML = 2 * 1024 * 1024
MAX_XML_TOTAL = 8 * 1024 * 1024
MAX_EML = 25 * 1024 * 1024
SUFFIX = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
BRANDS = {
    'paypal': 'paypal.com', 'microsoft': 'microsoft.com', 'google': 'google.com', 'apple': 'apple.com',
    'amazon': 'amazon.com', 'netflix': 'netflix.com', 'facebook': 'facebook.com', 'instagram': 'instagram.com',
    'whatsapp': 'whatsapp.com', 'linkedin': 'linkedin.com', 'binance': 'binance.com', 'coinbase': 'coinbase.com',
    'steam': 'steampowered.com', 'booking': 'booking.com', 'telegram': 'telegram.org', 'dropbox': 'dropbox.com',
    'kapitalbank': 'kapitalbank.az', 'pashabank': 'pashabank.az', 'birbank': 'birbank.az',
    'azericard': 'azericard.com', 'azercell': 'azercell.com', 'bakcell': 'bakcell.com',
}
# Top-level domains with a persistently high abuse ratio in public phishing feeds.
RISKY_TLDS = frozenset({
    'zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click', 'link',
    'country', 'kim', 'loan', 'men', 'quest', 'rest', 'fit', 'cam', 'sbs', 'cfd',
})
# Shorteners hide the destination; no target is ever fetched, so the hop stays unknown.
SHORTENERS = frozenset({
    'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly',
    'rb.gy', 'shorturl.at', 'rebrand.ly', 't.ly', 'bl.ink', 'lnkd.in', 's.id', 'v.gd',
})
# Cyrillic / Greek / accented characters that render almost identically to ASCII.
CONFUSABLES = str.maketrans({
    chr(0x430): 'a', chr(0x435): 'e', chr(0x43E): 'o', chr(0x440): 'p', chr(0x441): 'c',
    chr(0x443): 'y', chr(0x445): 'x', chr(0x456): 'i', chr(0x455): 's', chr(0x501): 'd',
    chr(0x4CF): 'l', chr(0x432): 'b', chr(0x43C): 'm', chr(0x43D): 'h', chr(0x442): 't',
    chr(0x3B1): 'a', chr(0x3BF): 'o', chr(0x3C1): 'p', chr(0x3BD): 'v', chr(0x3B9): 'i',
    chr(0x131): 'i', chr(0x251): 'a', chr(0x261): 'g',
})
RULES = {
 'disguised_executable': (40, 'Disguised executable', 'File identity'),
 'double_extension': (20, 'Misleading double extension', 'File identity'),
 'executable': (15, 'Executable file header', 'File identity'),
 'macro': (25, 'Office macro component', 'Document content'),
 'embedded': (15, 'Embedded object', 'Document content'),
 'link_mismatch': (30, 'Displayed link differs from target', 'Link deception'),
 'brand': (25, 'Brand impersonation pattern', 'Link deception'),
 'userinfo': (15, 'URL userinfo hides destination', 'URL structure'),
 'punycode': (5, 'Internationalized hostname', 'URL structure'),
 'ip_host': (5, 'IP address used as host', 'URL structure'),
 'deep_subdomain': (5, 'Deep subdomain structure', 'URL structure'),
 'pdf_launch': (30, 'PDF launch-action marker', 'Document content'),
 'pdf_js': (20, 'PDF JavaScript marker', 'Document content'),
 'password_form': (25, 'Password input with external submission', 'Document content'),
 'external_template': (20, 'Remote Office template', 'Document content'),
 'idn_homograph': (25, 'Internationalized name resembles a brand', 'Link deception'),
 'risky_tld': (10, 'High-abuse top-level domain', 'URL structure'),
 'shortener': (10, 'Shortened URL hides its destination', 'URL structure'),
 'meta_refresh': (15, 'Automatic redirect in page markup', 'Document content'),
 'hidden_iframe': (15, 'Hidden iframe in page markup', 'Document content'),
 'data_uri': (15, 'Inline data: URI payload', 'Document content'),
}
# Rules that describe deliberate destination deception. Any one of them keeps the
# headline band at least 'Suspicious', even when no external source has an opinion.
QUOTES = chr(39) + chr(34)
DECEPTION_CODES = frozenset({'userinfo', 'brand', 'idn_homograph', 'link_mismatch', 'disguised_executable'})

def now():
    return datetime.now(timezone.utc).isoformat()


def record(kind, target):
    return dict(kind=kind, target=target, timestamp=now(), findings=[], checks=[], links=[], limitations=[], providers=[], metadata={}, sha256=None, sample=False)


def finding(a, code, evidence, source='Local static analysis'):
    points, label, group = RULES[code]
    evidence = str(evidence)[:600]
    if not any(f['code'] == code and f['evidence'] == evidence for f in a['findings']):
        a['findings'].append(dict(code=code, points=points, label=label, group=group, evidence=evidence, source=source))


def check(a, label, status, detail=''):
    a['checks'].append(dict(label=label, status=status, detail=detail))


def normalize_url(raw):
    raw = raw.strip()
    if len(raw) > 2048:
        raise ValueError('URL exceeds 2048 characters.')
    p = urlsplit(raw)
    if p.scheme.lower() not in ('http', 'https') or not p.hostname or any(c.isspace() for c in raw):
        raise ValueError('Enter an HTTP(S) URL with a valid hostname.')
    if p.port is not None and not 0 < p.port < 65536:
        raise ValueError('Invalid port.')
    # Pydantic canonicalizes IDN/IPv6 and catches malformed hosts.
    from pydantic import TypeAdapter, HttpUrl
    return str(TypeAdapter(HttpUrl).validate_python(raw))


def add_link(a, raw):
    try:
        value = normalize_url(raw)
    except (ValueError, TypeError):
        return
    if value not in a['links'] and len(a['links']) < 50:
        a['links'].append(value)


def idn_decode(host):
    """Best-effort Unicode form of a punycode host. Empty string when it will not decode."""
    labels = []
    for label in host.split('.'):
        if label.startswith('xn--'):
            try:
                labels.append(label[4:].encode('ascii').decode('punycode'))
            except (UnicodeError, ValueError):
                return ''
        else:
            labels.append(label)
    return '.'.join(labels)


def brand_like(label, brand):
    return label == brand or (len(label) >= 5 and SequenceMatcher(None, label, brand).ratio() >= .85)


def url_findings(a, value, source='Local URL rules'):
    p = urlsplit(value)
    host = (p.hostname or '').lower().rstrip('.')
    ext = SUFFIX(host)
    domain = ext.top_domain_under_public_suffix or host
    if p.username is not None or p.password is not None:
        finding(a, 'userinfo', 'Actual destination: '+host, source)
    if any(label.startswith('xn--') for label in host.split('.')):
        finding(a, 'punycode', host+'; internationalized names can be legitimate.', source)
        decoded = idn_decode(host)
        skeleton = SUFFIX(decoded).domain.translate(CONFUSABLES) if decoded else ''
        for brand, official in BRANDS.items():
            if domain != official and skeleton and brand_like(skeleton, brand):
                finding(a, 'idn_homograph', host+' decodes to '+decoded+', which resembles '+official+'.', source)
                break
    try:
        ipaddress.ip_address(host)
        finding(a, 'ip_host', host, source)
    except ValueError:
        pass
    if ext.subdomain and len(ext.subdomain.split('.')) >= 4:
        finding(a, 'deep_subdomain', host, source)
    if ext.suffix and ext.suffix.rsplit('.', 1)[-1] in RISKY_TLDS:
        finding(a, 'risky_tld', '.'+ext.suffix+' is heavily abused in phishing campaigns; this alone is not proof.', source)
    if domain in SHORTENERS or host in SHORTENERS:
        finding(a, 'shortener', host+' hides its destination; the final target was not resolved.', source)
    normalized = ext.domain.translate(str.maketrans({'1':'l', '0':'o', '3':'e', '5':'s'}))
    for brand, official in BRANDS.items():
        if domain == official:
            continue
        if official+'.' in host or brand in ext.subdomain.split('.'):
            finding(a, 'brand', f'{host} uses {brand} outside {official}. Registrable domain: {domain}', source)
        elif normalized == brand or (len(ext.domain) >= 5 and SequenceMatcher(None, ext.domain, brand).ratio() >= .85):
            finding(a, 'brand', f'{domain} resembles {official}; ownership is unverified.', source)


def url_analysis(raw):
    value = normalize_url(raw)
    a = record('url', value)
    add_link(a, value)
    url_findings(a, value)
    p = urlsplit(value); ext = SUFFIX(p.hostname or '')
    a['metadata'] = dict(hostname=p.hostname, registrableDomain=ext.top_domain_under_public_suffix or p.hostname,
        subdomain=ext.subdomain, publicSuffix=ext.suffix, scheme=p.scheme, port=p.port,
        path=p.path or '/', queryNames=list(dict.fromkeys(k.split('=')[0] for k in p.query.split('&') if k)), userinfo=p.username is not None)
    check(a, 'URL structure', 'complete', 'Hostname, public suffix, userinfo and limited brand-pattern checks.')
    check(a, 'Page behavior', 'skipped', 'The destination is never opened by this application.')
    a['limitations'] += ['No page rendering, redirect traversal or exploit execution.', 'Brand comparison uses a limited explicit list; HTTPS does not prove legitimacy.']
    return a


def host(value):
    try:
        return (urlsplit(value if '://' in value else 'https://'+value).hostname or '').removeprefix('www.').lower()
    except ValueError:
        return ''


class InertHTML(HTMLParser):
    """Parse strings without a browser, resource loading or script execution."""
    def __init__(self, a):
        super().__init__(convert_charrefs=True); self.a=a; self.anchor=None; self.text=[]; self.forms=[]
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'a':
            self.anchor=attrs.get('href',''); self.text=[]; add_link(self.a,self.anchor)
            if self.anchor.strip().lower().startswith('data:'):
                finding(self.a,'data_uri','Anchor target is an inline data: URI.')
        elif tag == 'form':
            action=attrs.get('action','')
            self.forms.append([action,False])
            if action.strip().lower().startswith('data:'):
                finding(self.a,'data_uri','Form action is an inline data: URI.')
        elif tag == 'input' and self.forms and attrs.get('type','').lower() == 'password':
            self.forms[-1][1]=True
        elif tag == 'meta' and attrs.get('http-equiv','').lower() == 'refresh':
            target=''
            for piece in attrs.get('content','').split(';'):
                piece=piece.strip()
                if piece.lower().startswith('url='):
                    target=piece[4:].strip().strip(QUOTES)
            if target:
                add_link(self.a,target)
                finding(self.a,'meta_refresh','Markup redirects on its own to: '+target[:200])
        elif tag == 'iframe':
            src=attrs.get('src','')
            if src: add_link(self.a,src)
            if src.strip().lower().startswith('data:'):
                finding(self.a,'data_uri','Iframe source is an inline data: URI.')
            style=attrs.get('style','').lower().replace(' ','')
            tiny=any(attrs.get(d,'').strip().lower().rstrip('px') in ('0','1') for d in ('width','height'))
            if tiny or any(t in style for t in ('display:none','visibility:hidden','opacity:0')):
                finding(self.a,'hidden_iframe','Iframe is hidden from the reader: '+(src or '(no src)')[:160])
    def handle_data(self, data):
        if self.anchor is not None:
            self.text.append(data)
    def handle_endtag(self, tag):
        if tag == 'a' and self.anchor is not None:
            display=''.join(self.text).strip()
            if re.match(r'^(https?://|www\.)', display, re.I) and host(display) and host(self.anchor) and host(display)!=host(self.anchor):
                finding(self.a,'link_mismatch',f'Displayed: {display} → actual: {self.anchor}')
            self.anchor=None; self.text=[]
        elif tag == 'form' and self.forms:
            action,password=self.forms.pop()
            if password and action.lower().startswith(('http://','https://')):
                finding(self.a,'password_form','Password input with absolute form action: '+action)


def office_analysis(a, stream):
    # Inspect EOCD bounds before ZipFile loads its complete directory.
    stream.seek(0,2); size=stream.tell(); stream.seek(max(0,size-65557)); tail=stream.read(65557)
    at=tail.rfind(b'PK\x05\x06')
    if at < 0 or at+22>len(tail):
        raise ValueError('ZIP directory is missing or truncated.')
    import struct
    count=struct.unpack_from('<H',tail,at+10)[0]; cd_size=struct.unpack_from('<I',tail,at+12)[0]
    if count >= 65535 or count > 5000 or cd_size > 4*1024*1024:
        raise ValueError('ZIP64 or oversized ZIP directory is outside inspection limits.')
    stream.seek(0)
    with zipfile.ZipFile(stream) as z:
        entries=z.infolist(); names=[i.filename.lower() for i in entries]
        if '[content_types].xml' not in names or not any(n.startswith(('word/','xl/','ppt/')) for n in names):
            raise ValueError('Not a recognized Office Open XML package.')
        a['metadata']['detectedType']='Office Open XML'
        check(a,'Office package content','complete','Bounded package directory inspection.')
        if any(n.endswith('vbaproject.bin') for n in names):
            finding(a,'macro','vbaProject.bin component present; code was not executed.')
        if any(re.match(r'^(word|xl|ppt)/embeddings/[^/]+',n) for n in names):
            finding(a,'embedded','Embedded-object entries present in package.')
        check(a,'Macro & embedded-object inventory','complete','Component names inspected; no decompilation or behavior analysis.')
        relevant=[e for e in entries if e.filename.lower().endswith('.rels') or e.filename.lower()=='word/document.xml']
        total=0; processed=0; relations={}; document=None
        for e in relevant[:150]:
            try:
                if e.flag_bits & 1 or e.file_size>MAX_XML or total+e.file_size>MAX_XML_TOTAL:
                    raise ValueError('Encrypted / oversized XML component skipped.')
                with z.open(e) as source:
                    data=source.read(MAX_XML+1)
                if len(data)>MAX_XML:
                    raise ValueError('Decompression limit exceeded.')
                total+=len(data); root=ET.fromstring(data)
                if e.filename.lower()=='word/document.xml':
                    document=root
                for r in root.iter():
                    if r.tag.rsplit('}',1)[-1]!='Relationship' or r.get('TargetMode')!='External':
                        continue
                    target=r.get('Target',''); add_link(a,target)
                    if e.filename.lower()=='word/_rels/document.xml.rels':
                        relations[r.get('Id')]=target
                    if r.get('Type','').endswith('/attachedTemplate'):
                        finding(a,'external_template','External template: '+target)
                processed+=1
            except Exception as error:
                a['limitations'].append(e.filename+': '+type(error).__name__)
        check(a,'Office link content','complete' if processed==len(relevant) else 'partial',f'{processed}/{len(relevant)} relevant XML components inspected.')
        if document is not None:
            for link in document.iter():
                if link.tag.rsplit('}',1)[-1]!='hyperlink': continue
                identifier=next((v for k,v in link.attrib.items() if k.rsplit('}',1)[-1]=='id'),None)
                actual=relations.get(identifier)
                display=''.join(t.text or '' for t in link.iter() if t.tag.rsplit('}',1)[-1]=='t').strip()
                if actual and re.match(r'^(https?://|www\.)',display,re.I) and host(display)!=host(actual):
                    finding(a,'link_mismatch',f'Displayed: {display} → actual: {actual}')


def eml_analysis(a, raw, depth=0):
    """Parse a saved message the same way the mailbox path does, without a mail server."""
    msg = email.message_from_bytes(raw, policy=policy.default)
    sender = str(msg.get('From', ''))[:300]
    reply = str(msg.get('Reply-To', ''))[:300]
    from_domain = parseaddr(sender)[1].split('@')[-1].lower()
    reply_domain = parseaddr(reply)[1].split('@')[-1].lower() if reply else from_domain
    a['metadata']['detectedType'] = 'Saved email message'
    a['metadata']['message'] = {
        'from': sender or '(No sender header)',
        'replyTo': reply or '(Same as sender / not supplied)',
        'subject': str(msg.get('Subject', '(No subject)'))[:300],
        'senderNote': ('From / Reply-To domains differ; this can be legitimate.'
                       if from_domain != reply_domain else 'No From / Reply-To domain mismatch observed.'),
    }
    check(a, 'From / Reply-To comparison', 'complete',
          'Header comparison only; not proof of domain ownership or spoofing.')
    check(a, 'Trusted gateway authentication', 'skipped',
          'SPF / DKIM / DMARC are not inferred from untrusted raw headers.')
    body = 0
    attachments = 0
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b''
        name = part.get_filename()
        if name or part.get_content_disposition() == 'attachment':
            attachments += 1
            if depth or attachments > 2 or not payload or len(payload) > MAX_FILE_SIZE:
                continue
            child = file_analysis(io.BytesIO(payload), name or 'attachment.bin', len(payload))
            for f in child['findings']:
                finding(a, f['code'], (name or 'attachment') + ': ' + f['evidence'], f['source'])
            for link in child['links']:
                add_link(a, link)
        elif part.get_content_type() in ('text/plain', 'text/html'):
            room = 2 * 1024 * 1024 - body
            if room <= 0:
                continue
            chunk = payload[:room]
            body += len(chunk)
            try:
                text = chunk.decode(part.get_content_charset() or 'utf-8', errors='replace')
            except LookupError:
                text = chunk.decode('utf-8', errors='replace')
            if part.get_content_type() == 'text/html':
                parser = InertHTML(a); parser.feed(text); parser.close()
            else:
                for link in re.findall(r'https?://[^\s<>"\']+', text)[:50]:
                    add_link(a, link)
    a['metadata']['message']['attachments'] = attachments
    check(a, 'Email body content', 'complete', 'Inert parsing of body parts and up to 2 attachments.')
    a['limitations'].append('Saved-message inspection: no SPF / DKIM / DMARC verification.')


def file_analysis(stream, filename, size):
    if not 0<size<=MAX_FILE_SIZE:
        raise ValueError('File must be non-empty and no larger than 200 MiB.')
    a=record('file',Path(filename.replace('\\','/')).name[:255]); a['metadata']['fileSize']=size
    stream.seek(0); digest=hashlib.sha256()
    while chunk:=stream.read(1024*1024): digest.update(chunk)
    a['sha256']=digest.hexdigest(); stream.seek(0); head=stream.read(1024); stream.seek(0)
    ext=Path(filename).suffix.lower().lstrip('.'); pe=head.startswith(b'MZ'); pdf=head.startswith(b'%PDF-'); zip_head=head.startswith(b'PK'); ole=head.startswith(bytes.fromhex('d0cf11e0'))
    a['metadata']['detectedType']='Executable MZ header' if pe else 'PDF' if pdf else 'ZIP-based container' if zip_head else 'Legacy OLE container' if ole else 'Unrecognized / text'
    check(a,'File header & name','complete',a['metadata']['detectedType'])
    if re.search(r'\.(pdf|docx?|xlsx?|pptx?|txt|jpg|png)\.(exe|scr|com|bat|cmd|js|vbs|ps1)$',filename,re.I):
        finding(a,'double_extension',filename)
    if pe and ext not in ('exe','dll','scr','sys','com'):
        finding(a,'disguised_executable','Executable header does not match .'+ext+' extension.')
    elif pe: finding(a,'executable','MZ executable header; legitimacy is not established.')
    if zip_head and ext in ('docx','docm','xlsx','xlsm','pptx','pptm'):
        try: office_analysis(a,stream)
        except Exception as error:
            check(a,'Office package content','skipped','Could not inspect bounded OOXML package: '+type(error).__name__)
            a['limitations'].append('Office package not fully inspected.')
    elif pdf:
        text=stream.read(8*1024*1024).decode('latin1')
        if re.search(r'/Launch\b',text): finding(a,'pdf_launch','/Launch found in sampled raw PDF bytes.')
        if re.search(r'/(JavaScript|JS)\b',text): finding(a,'pdf_js','JavaScript marker found in sampled raw PDF bytes.')
        for link in re.findall(r'https?://[^\s<>()"\\]+',text)[:50]: add_link(a,link)
        check(a,'PDF marker content','partial','First 8 MiB of raw bytes; compressed streams not decoded.')
        a['limitations'].append('PDF checks are marker inspection, not a full renderer or exploit detector.')
    elif ext in ('txt','html','htm','url'):
        text=stream.read(2*1024*1024).decode('utf-8',errors='replace')
        if ext in ('html','htm'):
            parser=InertHTML(a); parser.feed(text); parser.close()
        else:
            for link in re.findall(r'https?://[^\s<>"\']+',text)[:50]: add_link(a,link)
        check(a,'Text / HTML content','complete' if size<=2*1024*1024 else 'partial','Inert parsing of at most 2 MiB.')
    elif ext == 'eml':
        eml_analysis(a, stream.read(MAX_EML))
    else:
        check(a,'File content','skipped','This file type has no supported content parser.')
    for link in a['links'][:30]: url_findings(a,link,'Extracted file URL rules')
    a['limitations'] += ['No payload execution or sandbox behavior analysis.','File hashes query existing reports; unknown hashes are not automatically uploaded for a new antivirus scan.']
    return a


def risk(a):
    codes=list(dict.fromkeys(f['code'] for f in a['findings']))
    raw=sum(RULES[c][0] for c in codes if c in RULES); local=min(70,raw)
    rep=min(90,max([int(a.get('linkedReputationPoints',0))]+[int(p.get('reputationPoints',0)) for p in a['providers']]))
    meaningful=any(c['status']=='complete' and any(t in c['label'].lower() for t in ('content','url structure','office package')) for c in a['checks'])
    verified_data=any(p['state']=='completed' and p.get('hasEvidence',False) for p in a['providers'])
    score=min(100,local+rep) if meaningful or local or rep or verified_data else None
    # Deliberate destination deception is decisive on its own. Without this floor a
    # textbook phishing URL such as https://www.paypal.com@203.0.113.9/login reads as
    # 'Low risk' whenever no external source happens to hold a record for it.
    deception=sorted(c for c in codes if c in DECEPTION_CODES)
    if score is not None and deception:
        score=max(score,31)
    level='Insufficient evidence' if score is None else 'Dangerous' if score>=70 else 'Suspicious' if score>30 else 'Low risk'
    return dict(score=score,local=local,localRaw=raw,reputation=rep,level=level,codes=codes,
        deceptionFloor=deception,model='rules-v2.1')


def finish(a):
    a['risk']=risk(a)
    a['verdict']='malicious' if any(p.get('verdict')=='malicious' for p in a['providers']) else 'suspicious' if (a['risk']['score'] or 0)>30 else 'unknown' if a['risk']['score'] is None else 'no_indicators'
    return a
