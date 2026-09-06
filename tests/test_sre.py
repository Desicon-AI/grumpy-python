import asyncio, hashlib, hmac, json, sys, unittest
from unittest.mock import Mock, patch
from seal.client import SealClient, SealASGIMiddleware
import seal.client as sdk

class InlineThread:
    def __init__(self, target, **kwargs): self.target = target
    def start(self): self.target()

class SDKTests(unittest.TestCase):
    def setUp(self):
        self.client = SealClient(); self.client.api_key='synthetic'; self.client.signing_secret='synthetic-secret'
        self.response = Mock(); self.response.json.return_value={'status':'ok'}
    def test_each_heartbeat_signs_exact_transmitted_bytes(self):
        with patch.object(sdk.requests,'post',return_value=self.response) as post:
            for now in [1000,1361]:
                with patch.object(sdk.time,'time',return_value=now): self.client._send_heartbeat()
                kwargs=post.call_args.kwargs; headers=kwargs['headers']; body=kwargs['data']
                self.assertEqual(headers['X-Seal-Timestamp'],str(now))
                expected=hmac.new(b'synthetic-secret',str(now).encode()+b'.'+body,hashlib.sha256).hexdigest()
                self.assertEqual(expected,headers['X-Seal-Signature'])
                self.assertTrue(self.client.delivery_health['heartbeat_ok'])
            self.assertEqual(post.call_count,2)
    def test_http_error_or_negative_ack_exposes_delivery_failure(self):
        with patch.object(sdk.requests,'post',return_value=self.response):
            self.response.raise_for_status.side_effect=RuntimeError('HTTP 503')
            self.client._send_heartbeat(); self.assertFalse(self.client.delivery_health['heartbeat_ok'])
            self.response.raise_for_status.side_effect=None; self.response.json.return_value={'status':'error'}
            self.client._send_heartbeat(); self.assertFalse(self.client.delivery_health['heartbeat_ok'])
            self.response.json.return_value={'status':'ok'}
            self.client._send_heartbeat(); self.assertTrue(self.client.delivery_health['heartbeat_ok'])
    def test_startup_failure_does_not_disable_heartbeat(self):
        previous=sys.excepthook
        try:
            with patch.object(self.client,'_post',side_effect=ConnectionError),patch.object(self.client,'_start_heartbeat') as start:
                self.client.init('synthetic','test'); start.assert_called_once()
        finally: sys.excepthook=previous
    def test_no_duplicate_heartbeat_thread_on_reinit(self):
        self.client._heartbeat_thread=Mock(); self.client._heartbeat_thread.is_alive.return_value=True
        with patch.object(sdk.threading,'Thread') as thread:
            self.client._start_heartbeat(); thread.assert_not_called()
    def test_credentials_removed_before_background_queue(self):
        pending=[]
        class QueuedThread:
            def __init__(self,target,**kwargs): pending.append(target)
            def start(self): pass
        scope={'method':'GET','path':'/SECRET-PATH','headers':[(b'authorization',b'SECRET-AUTH'),(b'cookie',b'SECRET-COOKIE'),(b'x-api-key',b'SECRET-KEY'),(b'user-agent',b'curl/8')]}
        with patch.object(sdk.threading,'Thread',QueuedThread),patch.object(sdk.requests,'post',return_value=self.response) as post:
            self.client._report_threat('TEST','127.0.0.1',scope,{'headers':{'cookie':'SECRET-DETAIL'},'action':'blocked'})
            scope['headers']=[(b'cookie',b'SECRET-CHANGED')]
            pending[0](); body=post.call_args.kwargs['data'].decode()
            self.assertNotIn('SECRET-',body)
            self.assertEqual(json.loads(body)['context']['headers']['user-agent'],'curl/8')
            self.assertEqual(json.loads(body)['context']['action'],'blocked')
    def test_benign_cli_and_keyword_routes_work_and_traversal_still_blocks(self):
        async def exercise():
            events=[]
            async def app(scope,receive,send): await send({'type':'http.response.start','status':200})
            async def receive(): return {'type':'http.request','body':b''}
            async def send(message): events.append(message)
            middleware=SealASGIMiddleware(app); middleware.seal=self.client
            self.client.waf_config={'maliciousScanners':{'action':'drop'},'pathTraversal':{'action':'drop'}}
            with patch.object(self.client,'_report_threat') as report:
                for ua in [b'curl/8',b'python-requests/2',b'wget/1']:
                    scope={'type':'http','method':'GET','path':'/api/select/update','query_string':b'', 'headers':[(b'user-agent',ua),(b'content-length',b'invalid')], 'client':('127.0.0.1',1)}
                    events.clear(); await middleware(scope,receive,send); self.assertEqual(events[0]['status'],200)
                report.assert_not_called()
                scope['path']='/../private'; events.clear(); await middleware(scope,receive,send)
                self.assertEqual(events[0]['status'],403); self.assertEqual(report.call_args.args[3]['action'],'blocked')
        asyncio.run(exercise())
    def test_forwarded_ip_untrusted_by_default(self):
        async def exercise():
            async def app(*args): pass
            middleware=SealASGIMiddleware(app); middleware.seal=self.client
            self.client.waf_config={'pathTraversal':{'action':'drop'}}
            async def send(message): pass
            scope={'type':'http','method':'GET','path':'/../file','headers':[(b'x-forwarded-for',b'1.2.3.4')],'client':('127.0.0.1',1)}
            with patch.object(self.client,'_report_threat') as report:
                await middleware(scope,None,send); self.assertEqual(report.call_args.args[1],'127.0.0.1')
        asyncio.run(exercise())

    def test_sandbox_auxiliary_routes_and_deployment_compatibility(self):
        self.client.ingest_url='https://example.test/custom/sandbox/ingest/'
        with patch.object(sdk.requests,'post',return_value=self.response) as post:
            self.assertTrue(self.client.register_deployment('test2'))
            self.assertEqual(post.call_args.args[0],'https://example.test/custom/ingest/deployment')
            self.client._send_heartbeat()
            self.assertEqual(post.call_args.args[0],'https://example.test/custom/ingest/heartbeat')
    def test_reinitialization_does_not_chain_exception_hook_to_itself(self):
        original=sys.excepthook
        try:
            with patch.object(self.client,'_post'),patch.object(self.client,'_start_heartbeat'):
                self.client.init('synthetic','test'); self.client.init('synthetic','test')
            self.assertEqual(self.client._original_excepthook,original)
        finally: sys.excepthook=original

if __name__=='__main__': unittest.main()
