import sys
import os
import traceback
import requests
import threading
import time
import hmac
import hashlib
import json

class SealClient:
    def __init__(self):
        self.api_key = None
        self.signing_secret = None
        self.environment = "development"
        self.app_name = "unknown_app"
        self._original_excepthook = None
        self.ingest_url = "https://sealengine.desicon.ai/api/v1/ingest"
        self.start_time = int(time.time() * 1000)
        self._heartbeat_thread = None
        self.delivery_health = {"heartbeat_ok": None, "last_heartbeat_at": None}

    def init(self, api_key: str, app_name: str, environment: str = "production", ingest_url: str = None, waf: dict = None, signing_secret: str = None, sandbox: bool = False):
        self.api_key = api_key
        self.signing_secret = signing_secret
        self.app_name = app_name
        self.environment = environment
        self.sandbox = sandbox
        if sandbox:
            self.ingest_url = "https://sealengine.desicon.ai/api/v1/sandbox/ingest"
        elif ingest_url:
            self.ingest_url = ingest_url
            
        self.waf_config = {
            "geoBlocking": { "blockedCountries": [], "action": "report" },
            "maliciousScanners": { "action": "report" },
            "trustProxyHeaders": False,
            "methodTampering": { "action": "report" },
            "payloadOverflow": { "maxPayloadSize": 5242880, "action": "report" },
            "pathTraversal": { "action": "drop" },
            "honeypot": {"action": "report"},
            "sqli": {"action": "report"},
            "xss": {"action": "report"}
        }
        if waf:
            # Deep update
            for k, v in waf.items():
                if k in self.waf_config and isinstance(v, dict):
                    self.waf_config[k].update(v)
                else:
                    self.waf_config[k] = v
        
        # Override the global exception hook
        if sys.excepthook != self._seal_excepthook:
            self._original_excepthook = sys.excepthook
        sys.excepthook = self._seal_excepthook
        
        # Startup delivery must not prevent the recurring heartbeat from starting.
        try:
            self._post("/ping", timeout=3)
        except Exception:
            pass
        self._start_heartbeat()

    def _post(self, suffix="", payload=None, timeout=5):
        body = json.dumps(payload, ensure_ascii=True) if payload is not None else ""
        headers = self._get_headers(body)
        headers["Content-Type"] = "application/json"
        endpoint = self.ingest_url.rstrip("/")
        if suffix:
            endpoint = endpoint.replace("/sandbox/ingest", "/ingest")
        response = requests.post(endpoint + suffix,
                                 data=body.encode("utf-8"), headers=headers, timeout=timeout)
        response.raise_for_status()
        return response

    def register_deployment(self, version: str = "unknown"):
        if not self.api_key:
            return False
        try:
            self._post("/deployment", {"version": version, "environment": self.environment})
            return True
        except Exception:
            return False

    def _get_headers(self, payload_str=None):
        headers = {
            "X-API-Key": self.api_key,
            "User-Agent": "Seal-Python-SDK/1.0.5"
        }
        if payload_str and self.signing_secret:
            timestamp = str(int(time.time()))
            msg = f"{timestamp}.{payload_str}".encode('utf-8')
            signature = hmac.new(self.signing_secret.encode('utf-8'), msg, hashlib.sha256).hexdigest()
            headers["X-Seal-Timestamp"] = timestamp
            headers["X-Seal-Signature"] = signature
        elif self.signing_secret:
            timestamp = str(int(time.time()))
            msg = f"{timestamp}.".encode('utf-8')
            signature = hmac.new(self.signing_secret.encode('utf-8'), msg, hashlib.sha256).hexdigest()
            headers["X-Seal-Timestamp"] = timestamp
            headers["X-Seal-Signature"] = signature
        return headers

    def _send_heartbeat(self):
        payload = {"app_name": self.app_name, "environment": self.environment,
                   "started_at": self.start_time}
        try:
            response = self._post("/heartbeat", payload)
            if response.json().get("status") != "ok":
                raise ValueError("Heartbeat was not acknowledged")
            self.delivery_health["heartbeat_ok"] = True
            self.delivery_health["last_heartbeat_at"] = time.time()
        except Exception:
            self.delivery_health["heartbeat_ok"] = False

    def _start_heartbeat(self):
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return

        def heartbeat_loop():
            while True:
                self._send_heartbeat()
                time.sleep(60)

        self._heartbeat_thread = threading.Thread(target=heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

    def _extract_code_context(self, tb):
        """Walks the stack trace to find the last file and extracts the surrounding lines."""
        try:
            # Extract the raw traceback
            extracted = traceback.extract_tb(tb)
            if not extracted:
                return "No traceback available."
            
            # Find the last frame that is actually in our project code
            last_frame = extracted[-1]
            filename = last_frame.filename
            lineno = last_frame.lineno
            
            if not os.path.exists(filename):
                return f"Could not locate {filename} on disk."
                
            with open(filename, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                
            # Grab 5 lines before and 5 lines after the error
            start_idx = max(0, lineno - 6)
            end_idx = min(len(lines), lineno + 5)
            
            context = ""
            for i in range(start_idx, end_idx):
                prefix = ">> " if i == (lineno - 1) else "   "
                context += f"{prefix}{i + 1}: {lines[i]}"
                
            return context
        except Exception as e:
            return f"Failed to extract context: {str(e)}"

    def _seal_excepthook(self, exc_type, exc_value, exc_traceback):
        tb_str = "".join(traceback.format_exception(exc_type, exc_value, exc_traceback))
        context_str = self._extract_code_context(exc_traceback)
        
        payload = {
            "app_name": self.app_name,
            "error_type": exc_type.__name__,
            "error_message": str(exc_value),
            "stack_trace": tb_str,
            "code_context": context_str,
            "environment": self.environment,
            "language": "python"
        }
        headers = self._get_headers(json.dumps(payload))
        
        try:
            print(f"\n[Seal.ai] Catching {exc_type.__name__}... shipping to SRE engine.")
            resp = self._post(payload=payload)
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "deduplicated":
                    print(f"[Seal.ai] Deduped (seen {data.get('count')} times).")
                else:
                    print(f"\n🔔 SEAL'S ANALYSIS:\n{data.get('analysis')}\n")
        except Exception as e:
            print(f"[Seal.ai] Failed to contact server: {e}")
            
        # Let it crash normally so we don't break the actual application
        if self._original_excepthook:
            self._original_excepthook(exc_type, exc_value, exc_traceback)

    def _report_threat(self, threat_type, ip, scope, details=None):
        if not self.api_key:
            return
        # Snapshot only approved metadata before starting any background work.
        allowed_headers = {"user-agent", "content-type", "content-length", "accept"}
        headers = {k.decode("utf-8", "ignore").lower(): v.decode("utf-8", "ignore")[:256]
                   for k, v in scope.get("headers", [])
                   if k.decode("utf-8", "ignore").lower() in allowed_headers}
        context = {"method": scope.get("method", ""), "headers": headers,
                   "path_hash": hashlib.sha256(scope.get("path", "").encode()).hexdigest(),
                   "action": "observed"}
        for key, value in (details or {}).items():
            if key in {"country", "content_length", "status_code", "attempts", "action"}:
                context[key] = value
        payload = {"app_name": self.app_name, "environment": self.environment,
                   "ip_address": ip, "threat_type": threat_type, "context": context, "language": "python"}

        def _send():
            try:
                self._post("/threat", payload, timeout=3)
            except Exception:
                pass
        threading.Thread(target=_send, daemon=True).start()

    def asgi_middleware(self):
        return SealASGIMiddleware

class SealASGIMiddleware:
    def __init__(self, app):
        self.app = app
        self.seal = seal
        self.auth_failures = {} # IP -> [timestamps]
        import re
        self.HONEYPOTS = ['/wp-admin', '/wp-login.php', '/.env', '/config.php', '/.git/config']
        self.SQLI_REGEX = re.compile(r"(?:\bUNION\s+(?:ALL\s+)?SELECT\b)|(?:['\"]\s*(?:OR|AND)\s+\d+\s*=\s*\d+)", re.IGNORECASE)
        self.XSS_REGEX = re.compile(r"(?:<|%3C)script[\s\S]*?(?:>|%3E)|(?:<|%3C)[\s\S]*?(?:on[a-z]+\s*=)(?:>|%3E)", re.IGNORECASE)
        self.TRAVERSAL_REGEX = re.compile(r"(?:\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e%5c)", re.IGNORECASE)
        self.SCANNER_REGEX = re.compile(r"(sqlmap|nikto|masscan|zmap|nmap)", re.IGNORECASE)
        self.ALLOWED_METHODS = [b'GET', b'POST', b'PUT', b'PATCH', b'DELETE', b'OPTIONS', b'HEAD']

    async def _send_rejection(self, send, status_code, body_message):
        await send({
            "type": "http.response.start",
            "status": status_code,
            "headers": [(b"content-type", b"text/plain")]
        })
        await send({
            "type": "http.response.body",
            "body": body_message.encode("utf-8")
        })

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        path = scope.get("path", "")
        query = scope.get("query_string", b"").decode("utf-8", "ignore")
        full_url = f"{path}?{query}" if query else path
        method = scope.get("method", b"").encode("utf-8") if isinstance(scope.get("method"), str) else scope.get("method", b"")

        client_ip = "unknown"
        headers = dict(scope.get("headers", []))
        if getattr(self.seal, "waf_config", {}).get("trustProxyHeaders") and b"x-forwarded-for" in headers:
            client_ip = headers[b"x-forwarded-for"].decode("utf-8", "ignore").split(",")[0].strip()
        elif scope.get("client"):
            client_ip = scope["client"][0]

        ua = headers.get(b"user-agent", b"").decode("utf-8", "ignore")
        cf_country = headers.get(b"cf-ipcountry", headers.get(b"x-vercel-ip-country", b"")).decode("utf-8", "ignore")
        try:
            content_length = int(headers.get(b"content-length", b"0").decode("utf-8", "ignore") or 0)
        except ValueError:
            content_length = 0
        
        waf_cfg = getattr(self.seal, 'waf_config', {})

        if not waf_cfg.get("trustProxyHeaders"):
            cf_country = ""

        # Geo-Blocking
        if waf_cfg.get("geoBlocking", {}).get("blockedCountries") and cf_country in waf_cfg["geoBlocking"]["blockedCountries"]:
            self.seal._report_threat("GEO_BLOCKED", client_ip, scope, {"country": cf_country, "action": "blocked" if waf_cfg["geoBlocking"].get("action") == "drop" else "observed"})
            if waf_cfg["geoBlocking"].get("action") == "drop":
                return await self._send_rejection(send, 403, "Access Denied from your Region")

        # Method Tampering
        if waf_cfg.get("methodTampering", {}).get("action") == "drop" and method not in self.ALLOWED_METHODS:
            self.seal._report_threat("METHOD_TAMPERING", client_ip, scope, {"action": "blocked"})
            return await self._send_rejection(send, 405, "Method Not Allowed")

        # Malicious Scanners
        if self.SCANNER_REGEX.search(ua):
            action = waf_cfg.get("maliciousScanners", {}).get("action", "report")
            self.seal._report_threat("MALICIOUS_SCANNER", client_ip, scope, {"action": "blocked" if action == "drop" else "observed"})
            if action == "drop":
                return await self._send_rejection(send, 403, "Forbidden Scanner")

        # Payload Overflow
        max_payload = waf_cfg.get("payloadOverflow", {}).get("maxPayloadSize", 5242880)
        if waf_cfg.get("payloadOverflow", {}).get("action") == "drop" and content_length > max_payload:
            self.seal._report_threat("PAYLOAD_OVERFLOW", client_ip, scope, {"content_length": content_length, "action": "blocked"})
            return await self._send_rejection(send, 413, "Payload Too Large")

        # Path Traversal
        if waf_cfg.get("pathTraversal", {}).get("action") == "drop" and self.TRAVERSAL_REGEX.search(full_url):
            self.seal._report_threat("PATH_TRAVERSAL", client_ip, scope, {"action": "blocked"})
            return await self._send_rejection(send, 403, "Forbidden Path")

        # 1. Honeypot check
        if path in self.HONEYPOTS:
            action = waf_cfg.get("honeypot", {}).get("action", "report")
            self.seal._report_threat("HONEYPOT_ACCESS", client_ip, scope, {"action": "blocked" if action == "drop" else "observed"})
            if action == "drop":
                return await self._send_rejection(send, 403, "Access denied by configured path policy")

        # 2. WAF Legacy URL Check
        is_threat = False
        threat_type = ""
        from urllib.parse import unquote
        inspected_url = unquote(full_url)
        if self.SQLI_REGEX.search(inspected_url):
            is_threat, threat_type = True, "SQL_INJECTION"
        elif self.XSS_REGEX.search(inspected_url):
            is_threat, threat_type = True, "XSS_ATTACK"

        if is_threat:
            action = waf_cfg.get("sqli" if threat_type == "SQL_INJECTION" else "xss", {}).get("action", "report")
            self.seal._report_threat(threat_type, client_ip, scope, {"action": "blocked" if action == "drop" else "observed"})
            if action == "drop":
                return await self._send_rejection(send, 403, "Request rejected by configured application policy")

        # 3. 401/403 Sliding Window Tracker
        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                status = message.get("status")
                if status in (401, 403):
                    now = time.time()
                    hits = self.auth_failures.get(client_ip, [])
                    hits.append(now)
                    recent_hits = [h for h in hits if h > now - 60]
                    self.auth_failures[client_ip] = recent_hits

                    if len(recent_hits) >= 10:
                        last_reported = self.auth_failures.get(f"reported_{client_ip}", 0)
                        if now - last_reported > 60:
                            self.seal._report_threat(
                                "BRUTE_FORCE_ATTACK", 
                                client_ip, 
                                scope, 
                                {"status_code": status, "attempts": len(recent_hits)}
                            )
                            self.auth_failures[f"reported_{client_ip}"] = now
            await send(message)

        await self.app(scope, receive, send_wrapper)

# Global singleton
seal = SealClient()
