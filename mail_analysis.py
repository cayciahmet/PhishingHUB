"""IMAP read-only collection; no untrusted Authentication-Results is accepted as proof."""
import email
from email import policy
from email.header import decode_header, make_header
from email.utils import parseaddr
from html import unescape
import imaplib
import io
import re
from urllib.parse import urlsplit
from analysis import record,check,finding,add_link,url_findings,file_analysis,MAX_FILE_SIZE,InertHTML

MAX_RAW_MAIL=25*1024*1024
MAX_MAILS=5

def fetch_mail(config):
    server=config.get('IMAP_SERVER','imap.gmail.com')
    mail=imaplib.IMAP4_SSL(server,timeout=15)
    try:
        mail.login(config.get('IMAP_USER',''),config.get('IMAP_PASS',''))
        status,_=mail.select('INBOX',readonly=True)
        if status!='OK':raise RuntimeError('Could not open INBOX.')
        status,ids=mail.search(None,'UNSEEN')
        if status!='OK':raise RuntimeError('Could not search unread messages.')
        numbers=(ids[0].split() if ids and ids[0] else [])[-MAX_MAILS:]
        output=[]
        for number in reversed(numbers):
            stat,info=mail.fetch(number,'(RFC822.SIZE)')
            text=b' '.join(x for x in info if isinstance(x,bytes)) if stat=='OK' else b''
            match=re.search(rb'RFC822.SIZE\s+(\d+)',text)
            if not match or int(match[1])>MAX_RAW_MAIL:
                output.append({'skipped':True,'detail':'Message size unavailable or exceeds the 25 MiB mail-inspection limit.'});continue
            stat,parts=mail.fetch(number,'(BODY.PEEK[])')
            if stat!='OK':continue
            for part in parts:
                if isinstance(part,tuple) and isinstance(part[1],bytes):
                    if len(part[1])>MAX_RAW_MAIL:output.append({'skipped':True,'detail':'Mail exceeds inspection limit.'})
                    else:output.append({'raw':part[1]})
        return output
    finally:
        try:mail.logout()
        except Exception:pass


def parse_mail(raw):
    msg=email.message_from_bytes(raw,policy=policy.default)
    subject=str(msg.get('Subject','(No subject)'))[:300]
    a=record('imap',subject)
    sender=str(msg.get('From',''))[:300];reply=str(msg.get('Reply-To',''))[:300]
    from_domain=parseaddr(sender)[1].split('@')[-1].lower();reply_domain=parseaddr(reply)[1].split('@')[-1].lower() if reply else from_domain
    a['metadata']['message']={'from':sender,'replyTo':reply or '(Same as sender / not supplied)','subject':subject,'senderNote':'From / Reply-To domains differ; this can be legitimate.' if from_domain!=reply_domain else 'No From / Reply-To domain mismatch observed.','spf':'Not independently verified','dkim':'Not independently verified','dmarc':'Not independently verified','attachments':0}
    check(a,'From / Reply-To comparison','complete','Header comparison only; not proof of domain ownership or spoofing.')
    check(a,'Trusted gateway authentication','skipped','SPF / DKIM / DMARC are not inferred from untrusted raw headers.')
    attachments=[]; body_bytes=0; body_parts=0
    for part in msg.walk():
        if part.is_multipart():continue
        payload=part.get_payload(decode=True) or b''
        filename=part.get_filename()
        if filename or part.get_content_disposition()=='attachment':
            a['metadata']['message']['attachments']+=1
            if len(attachments)>=3:continue
            if not payload:continue
            if len(payload)>MAX_FILE_SIZE:continue
            attachments.append(file_analysis(io.BytesIO(payload),filename or 'attachment.bin',len(payload)))
        elif part.get_content_type() in ('text/plain','text/html'):
            remaining=2*1024*1024-body_bytes
            if remaining<=0:continue
            snippet=payload[:remaining];body_bytes+=len(snippet);body_parts+=1
            try:text=snippet.decode(part.get_content_charset() or 'utf-8',errors='replace')
            except LookupError:text=snippet.decode('utf-8',errors='replace')
            if part.get_content_type()=='text/html':
                parser=InertHTML(a);parser.feed(text);parser.close()
            else:
                for link in re.findall(r'https?://[^\s<>"\']+',unescape(text))[:50]:add_link(a,link)
    for link in a['links'][:10]:url_findings(a,link,'Email URL rules')
    check(a,'Email body content','partial' if body_bytes>=2*1024*1024 else 'complete',f'{body_parts} text/HTML part(s) inspected; no resource loaded.')
    check(a,'Attachment content','complete' if len(attachments)==a['metadata']['message']['attachments'] else 'partial',f'{len(attachments)}/{a["metadata"]["message"]["attachments"]} attachments inspected; maximum 3.')
    a['attachments']=attachments
    # Bring scored attachment observations into the parent message, with provenance.
    for child in attachments:
        for f in child['findings']:finding(a,f['code'],child['target']+': '+f['evidence'],'Mail attachment static analysis')
    a['limitations']+=['No independent SPF/DKIM/DMARC verification.','At most 2 MiB of body content and 3 attachments inspected. Unread status is not modified.']
    return a
