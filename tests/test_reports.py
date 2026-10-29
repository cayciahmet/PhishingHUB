import asyncio
import httpx
import analysis
from reports import AI_PROMPT,ai_context,generate_ai,text_report


def test_ai_context_redacts_query_and_userinfo():
    a=analysis.finish(analysis.url_analysis('https://user:secret@example.com/login?token=veryprivate#hidden'))
    value=ai_context(a)
    assert 'veryprivate' not in value and 'user:secret' not in value and '#hidden' not in value
    assert 'Always answer in English' in AI_PROMPT


def test_ai_no_key_has_standard_report():
    a=analysis.finish(analysis.url_analysis('https://example.com'))
    async def work():
        async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:(_ for _ in ()).throw(AssertionError('No request expected')))) as c:
            value,error=await generate_ai(a,c,{})
            assert value is None and 'not configured' in error
    asyncio.run(work())
    assert 'SOURCE-BY-SOURCE RESULTS' in text_report(a)


def test_ai_fallback_uses_content_not_reasoning():
    a=analysis.finish(analysis.url_analysis('https://example.com'));calls=[]
    def handler(r):
        calls.append(r)
        if len(calls)==1:return httpx.Response(429,json={'error':'limit'})
        return httpx.Response(200,json={'choices':[{'message':{'content':'Assessment: limited indicators.', 'reasoning':'not for user'}}]})
    async def work():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            value,error=await generate_ai(a,c,{'OPENROUTER_API_KEY':'test','AI_MODEL':'primary','AI_FALLBACK_MODEL':'fallback'})
            assert value=='Assessment: limited indicators.' and error is None
    asyncio.run(work());assert len(calls)==2
