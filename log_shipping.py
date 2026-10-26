# SPDX-FileCopyrightText: GoCortexIO
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# GoCortex Broken Bank - Log Shipping Module
# Version: 1.7.0
#
# This module provides HTTP POST-based log shipping to external SIEM platforms.
# Ships three JSON log types: netbank_application (BBWAF exploitation events),
# netbank_concierge (Concierge prompts, responses and loaded context) and
# netbank_auth (authentication events, real and simulated). The fourth
# stream, tomcat_access, is shipped by scripts/log-forwarder.py.

import os
import json
import logging
import secrets
import threading
import time
from datetime import datetime, timezone
from functools import wraps
from queue import Queue, Full

import yaml
import requests
import auth_networks
import observability.metrics as metrics

# Suppress SSL warnings for intentionally insecure configuration
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class LogShipper:
    """HTTP POST-based log shipper for SIEM integration."""
    
    # Maximum queue size to prevent unbounded memory growth
    MAX_QUEUE_SIZE = 1000
    
    def __init__(self, config_path="config/logging.yaml"):
        self.config = self._load_config(config_path)
        # LOG_SHIPPING_ENABLED overrides the file so a container can turn log
        # shipping on without editing config/logging.yaml, which is otherwise
        # the one setting that forces a file edit (every URL and token is
        # already an ${ENV} placeholder). Keeps a redeployed container's
        # configuration entirely in its environment.
        _env_enabled = os.environ.get("LOG_SHIPPING_ENABLED")
        if _env_enabled is not None:
            self.enabled = _env_enabled.strip().lower() in ("1", "true", "yes", "on")
        else:
            self.enabled = self.config.get("log_shipping", {}).get("enabled", False)
        self.endpoints = self.config.get("endpoints", {})
        self.retry_config = self.config.get("log_shipping", {}).get("retry", {})
        self.defaults = self.config.get("defaults", {})
        
        # Bounded queue for async log shipping
        self._queue = Queue(maxsize=self.MAX_QUEUE_SIZE)
        self._worker_thread = None
        self._running = False
        
        # Start worker thread if shipping is enabled
        if self.enabled:
            self._start_worker()
        
    def _load_config(self, config_path):
        """Load logging configuration from YAML file."""
        try:
            with open(config_path, 'r') as f:
                config = yaml.safe_load(f)
                return self._resolve_env_vars(config)
        except FileNotFoundError:
            logging.warning(f"Logging config not found at {config_path}, using defaults")
            return {"log_shipping": {"enabled": False}}
        except Exception as e:
            logging.error(f"Error loading logging config: {e}")
            return {"log_shipping": {"enabled": False}}
    
    def _resolve_env_vars(self, obj):
        """Recursively resolve environment variable placeholders in config."""
        if isinstance(obj, dict):
            return {k: self._resolve_env_vars(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self._resolve_env_vars(item) for item in obj]
        elif isinstance(obj, str) and obj.startswith("${") and obj.endswith("}"):
            env_var = obj[2:-1]
            return os.environ.get(env_var, "")
        return obj
    
    def _get_auth_headers(self, endpoint_config):
        """Build authentication headers based on endpoint configuration."""
        log_format = endpoint_config.get("format", "json")
        if log_format == "json":
            headers = {"Content-Type": "application/json"}
        else:
            headers = {"Content-Type": "text/plain"}
        
        auth_config = endpoint_config.get("auth", {})
        auth_type = auth_config.get("type", "none")
        
        if auth_type == "header":
            header_name = auth_config.get("header_name", "Authorization")
            header_value = auth_config.get("header_value", "")
            if header_value:
                headers[header_name] = header_value
                
        elif auth_type == "bearer":
            token = auth_config.get("token", "")
            if token:
                headers["Authorization"] = f"Bearer {token}"
                
        elif auth_type == "basic":
            import base64
            username = auth_config.get("username", "")
            password = auth_config.get("password", "")
            if username and password:
                credentials = base64.b64encode(f"{username}:{password}".encode()).decode()
                headers["Authorization"] = f"Basic {credentials}"
        
        return headers
    
    def ship_log(self, log_type, log_data):
        """Ship a log entry to the configured endpoint."""
        if not self.enabled:
            return False
            
        endpoint_config = self.endpoints.get(log_type, {})
        if not endpoint_config.get("enabled", False):
            return False
            
        url = endpoint_config.get("url", "")
        if not url:
            # Fall back to defaults if available
            base_url = self.defaults.get("base_url", "")
            path = self.defaults.get("path", "")
            if base_url and path:
                url = base_url.rstrip("/") + "/" + path.lstrip("/")
                logging.debug(f"Using default URL for {log_type}: {url}")
            else:
                logging.debug(f"No URL configured for log type: {log_type}")
                return False
        
        headers = self._get_auth_headers(endpoint_config)
        
        max_attempts = self.retry_config.get("max_attempts", 3)
        backoff = self.retry_config.get("backoff_seconds", 5)
        
        log_format = endpoint_config.get("format", "json")
        
        for attempt in range(max_attempts):
            try:
                if log_format == "json":
                    body = json.dumps(log_data)
                else:
                    body = log_data if isinstance(log_data, str) else str(log_data)
                
                response = requests.post(
                    url,
                    data=body,
                    headers=headers,
                    timeout=10,
                    verify=False
                )
                
                if response.status_code in [200, 201, 202, 204]:
                    logging.debug(f"Log shipped successfully to {log_type}: {response.status_code}")
                    if metrics.log_ship_total is not None:
                        metrics.log_ship_total.add(1, {"log_type": log_type, "result": "success"})
                    return True
                else:
                    logging.warning(f"Log shipping failed for {log_type}: {response.status_code} - {response.text[:200]}")
                    
            except requests.exceptions.RequestException as e:
                logging.warning(f"Log shipping error for {log_type} (attempt {attempt + 1}): {e}")
                
            if attempt < max_attempts - 1:
                time.sleep(backoff)

        if metrics.log_ship_total is not None:
            metrics.log_ship_total.add(1, {"log_type": log_type, "result": "error"})
        return False
    
    def _start_worker(self):
        """Start the background worker thread for processing log queue."""
        if self._worker_thread is not None and self._worker_thread.is_alive():
            return
        
        self._running = True
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self._worker_thread.start()
        logging.info("Log shipping worker thread started")
    
    def _worker_loop(self):
        """Background worker loop that processes logs from the queue."""
        while self._running:
            try:
                # Block with timeout to allow checking _running flag
                log_type, log_data = self._queue.get(timeout=1.0)
                if metrics.log_ship_queue_depth is not None:
                    metrics.log_ship_queue_depth.add(-1, {"log_type": log_type})
                self.ship_log(log_type, log_data)
                self._queue.task_done()
            except Exception:
                # Queue.get timeout or empty queue
                pass
    
    def ship_log_async(self, log_type, log_data):
        """Ship a log entry asynchronously via bounded queue (non-blocking)."""
        if not self.enabled:
            return
        
        try:
            self._queue.put_nowait((log_type, log_data))
            if metrics.log_ship_queue_depth is not None:
                metrics.log_ship_queue_depth.add(1, {"log_type": log_type})
        except Full:
            logging.warning("Log shipping queue full, dropping log entry")


# Global log shipper instance
_log_shipper = None


def get_log_shipper():
    """Get or create the global log shipper instance."""
    global _log_shipper
    if _log_shipper is None:
        _log_shipper = LogShipper()
    return _log_shipper


def log_bbwaf_event(endpoint, vulnerability, payload, request_obj):
    """
    Log a BBWAF (Broken Bank WAF) security event.
    
    This simulates a WAF/security appliance detecting and logging
    exploitation attempts against vulnerable endpoints.
    """
    shipper = get_log_shipper()
    
    log_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "vendor": "GoCortex",
        "product": "BBWAF",
        "event_type": "security_detection",
        "endpoint": endpoint,
        "vulnerability": vulnerability,
        "payload": str(payload)[:1000] if payload else "",
        "source_ip": request_obj.remote_addr or "unknown",
        "user_agent": request_obj.headers.get("User-Agent", "unknown"),
        "request_method": request_obj.method,
        "request_path": request_obj.path,
        "query_string": request_obj.query_string.decode("utf-8", errors="ignore")[:500]
    }
    
    shipper.ship_log_async("netbank_application", log_data)


# Every netbank_auth event carries every one of these keys, null where it
# does not apply, so a parser sees one shape whatever produced the event.
# The first eleven are the original fields and keep their names, positions
# and types; everything after "simulated" was added in 1.7.0 for login and
# session detection. event_type stays the constant "authentication" so
# existing parsers keep working; event_action is what tells events apart, and
# a rule that counted status as login outcomes needs event_action = "login".
AUTH_EVENT_FIELDS = (
    "timestamp", "vendor", "product", "event_type", "username", "status",
    "source_ip", "user_agent", "country", "device_type", "simulated",
    "event_action", "user_id", "account_type", "privilege", "target_user",
    "failure_reason", "auth_method", "mfa_used", "mfa_method", "mfa_result",
    "session_id", "session_issued_at", "session_expires_at",
    "geo_city", "asn", "asn_org", "device_id", "client_app", "tls_ja4",
    "url_path", "http_status",
)

# User-Agent substrings that mark a scripting runtime or attack tool rather
# than a browser. Note these are claims the client makes about itself.
_SCRIPT_UA_MARKERS = (
    "python-requests", "python-urllib", "aiohttp", "curl/", "wget/",
    "go-http-client", "httpie", "libwww-perl", "java/",
    "powershell", "axios/", "node-fetch", "scrapy", "hydra", "sqlmap",
    "nikto",
)


def build_auth_event(username, status, *, source_ip, user_agent, simulated,
                     timestamp=None, **fields):
    """
    Build one netbank_auth event with the full AUTH_EVENT_FIELDS key set.

    country, geo_city, asn and asn_org are derived from source_ip via the
    auth_networks table, device_type and client_app from user_agent, and
    event_action defaults to "login". Any keyword in AUTH_EVENT_FIELDS
    overrides the derived value.
    """
    unknown = set(fields) - set(AUTH_EVENT_FIELDS)
    if unknown:
        raise ValueError(f"Unknown netbank_auth field(s): {sorted(unknown)}")

    network = auth_networks.lookup(source_ip)
    event = dict.fromkeys(AUTH_EVENT_FIELDS)
    event.update({
        "timestamp": timestamp or datetime.now(timezone.utc).isoformat(),
        "vendor": "GoCortex",
        "product": "BrokenBank",
        "event_type": "authentication",
        "username": username,
        "status": status,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "country": network.country if network else auth_networks.HOME_COUNTRY,
        "device_type": _detect_device_type(user_agent),
        "simulated": simulated,
        "event_action": "login",
        "geo_city": network.cities[0] if network else None,
        "asn": network.asn if network else None,
        "asn_org": network.asn_org if network else None,
        "client_app": _detect_client_app(user_agent),
    })
    event.update(fields)
    return event


def log_auth_event(username, status, request_obj, simulated=False, **fields):
    """
    Log an authentication event to the netbank_auth stream.

    Args:
        username: The username attempting authentication
        status: "success" or "failure" ("signup_success" for /signup)
        request_obj: Flask request object
        simulated: True if this is generated background traffic
        **fields: Any further AUTH_EVENT_FIELDS (event_action, session_id...)
    """
    shipper = get_log_shipper()

    user_agent = request_obj.headers.get("User-Agent", "unknown") if request_obj else "unknown"
    source_ip = (request_obj.remote_addr or "unknown") if request_obj else "unknown"
    if request_obj is not None:
        fields.setdefault("url_path", request_obj.path)

    log_data = build_auth_event(
        username, status,
        source_ip=source_ip, user_agent=user_agent, simulated=simulated,
        **fields,
    )

    shipper.ship_log_async("netbank_auth", log_data)


# A real /netbank session re-reports itself at most this often while it stays
# on the address and browser that opened it. A change of either is reported
# on the request that shows it, which is what makes a replayed session cookie
# visible: the cookie is signed with a hard-coded key and never expires.
NETBANK_SESSION_REFRESH_SECONDS = 300


def log_netbank_view(flask_session, request_obj, username, account_number):
    """
    Report a real /netbank visit on the netbank_auth stream.

    /netbank grants a session with no credentials at all, so the first visit
    is logged as a login with auth_method "none". Later visits are logged as
    session_refresh against the same session_id, throttled unless the source
    address or User-Agent differs from the one the session was opened from.
    """
    now = time.time()
    source_ip = (request_obj.remote_addr or "unknown") if request_obj else "unknown"
    user_agent = request_obj.headers.get("User-Agent", "unknown") if request_obj else "unknown"

    session_id = flask_session.get("auth_session_id")
    if not session_id:
        session_id = f"sess-{secrets.token_hex(12)}"
        flask_session["auth_session_id"] = session_id
        flask_session["auth_issued_at"] = datetime.now(timezone.utc).isoformat()
        flask_session["auth_device_id"] = f"dev-{secrets.token_hex(6)}"
        flask_session["auth_ip"] = source_ip
        flask_session["auth_ua"] = user_agent
        event_action = "login"
    elif (source_ip != flask_session.get("auth_ip")
          or user_agent != flask_session.get("auth_ua")
          or now - flask_session.get("auth_last_event", 0) >= NETBANK_SESSION_REFRESH_SECONDS):
        event_action = "session_refresh"
    else:
        return
    flask_session["auth_last_event"] = now

    log_auth_event(
        username, "success", request_obj,
        event_action=event_action,
        user_id=f"cus-{account_number}",
        account_type="customer",
        privilege="retail_customer",
        auth_method="none",
        mfa_used=False,
        mfa_method="none",
        mfa_result="not_enrolled",
        session_id=session_id,
        session_issued_at=flask_session.get("auth_issued_at"),
        device_id=flask_session.get("auth_device_id"),
        http_status=200,
    )


def log_concierge_event(event_type, request_obj, *, session_id, turn_id,
                        model_name, prompt_text=None, response_text=None,
                        response_path=None, context_document_count=0,
                        context_document_labels=None, document_label=None,
                        source_url=None, body_preview=None, body_length=None):
    """
    Log a Mars Banking Initiative Concierge event to the netbank_concierge stream.

    event_type is one of:
      - "prompt"          : inbound user prompt to /concierge/chat
      - "response"        : Concierge model output for /concierge/chat
      - "context_loaded"  : indirect-injection sink fired (URL or text upload)
      - "agent_command"   : /concierge/agent executed the model's suggested
                            shell command with no validation (LLM08)

    The two chat events share a turn_id so a prompt-injection ruleset in XSIAM
    can correlate the user's payload with the model's leaked output. The
    context_loaded event captures attacker-controlled document text as it
    enters the Concierge context window.
    """
    shipper = get_log_shipper()

    user_agent = request_obj.headers.get("User-Agent", "unknown") if request_obj else "unknown"
    source_ip = request_obj.remote_addr if request_obj else "unknown"
    request_method = request_obj.method if request_obj else "unknown"
    request_path = request_obj.path if request_obj else "unknown"

    log_data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "vendor": "GoCortex",
        "product": "Concierge",
        "event_type": event_type,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "request_method": request_method,
        "request_path": request_path,
        "session_id": session_id,
        "turn_id": turn_id,
        "model_name": model_name,
        "context_document_count": context_document_count,
        "context_document_labels": list(context_document_labels or []),
    }

    if prompt_text is not None:
        log_data["prompt_text"] = str(prompt_text)
    if response_text is not None:
        log_data["response_text"] = str(response_text)
    if response_path is not None:
        log_data["response_path"] = response_path
    if document_label is not None:
        log_data["document_label"] = document_label
    if source_url is not None:
        log_data["source_url"] = source_url
    if body_length is not None:
        log_data["body_length"] = body_length
    if body_preview is not None:
        # Cap document preview at the same ~1000 char ceiling BBWAF uses for
        # payloads so a single oversized indirect-injection upload cannot
        # blow out the SIEM record.
        log_data["body_preview"] = str(body_preview)[:1000]

    shipper.ship_log_async("netbank_concierge", log_data)


def _detect_country(ip_address):
    """Country for ip_address from the auth_networks table, else the home country."""
    network = auth_networks.lookup(ip_address)
    return network.country if network else auth_networks.HOME_COUNTRY


def _detect_client_app(user_agent):
    """Classify the client from its User-Agent: browser, mobile_app, script or unknown."""
    if not user_agent or user_agent == "unknown":
        return "unknown"
    ua_lower = user_agent.lower()
    if ua_lower.startswith("brokenbankmobile/"):
        return "mobile_app"
    if any(marker in ua_lower for marker in _SCRIPT_UA_MARKERS):
        return "script"
    if ua_lower.startswith("mozilla/"):
        return "browser"
    return "unknown"


def _detect_device_type(user_agent):
    """Detect device type from user agent string."""
    if not user_agent:
        return "unknown"
    
    ua_lower = user_agent.lower()
    
    # Tablet first: iPad Safari also says "Mobile" in its User-Agent
    if any(tablet in ua_lower for tablet in ["ipad", "tablet"]):
        return "tablet"
    elif any(mobile in ua_lower for mobile in ["mobile", "android", "iphone", "ipod"]):
        return "mobile"
    else:
        return "desktop"


# Vulnerability type mapping for BBWAF logging
VULNERABILITY_MAPPING = {
    "/search": "SQL_INJECTION",
    "/comment": "CROSS_SITE_SCRIPTING",
    "/ldap": "LDAP_INJECTION",
    "/deserialize": "INSECURE_DESERIALIZATION",
    "/account/restore_preferences": "INSECURE_DESERIALIZATION",
    "/business/notifications/preview": "TEMPLATE_INJECTION",
    "/admin/logs/retention": "LOG_TAMPERING",
    "/admin/tasks/schedule": "CRON_PERSISTENCE",
    "/api/vault/secrets": "MISSING_AUTHENTICATION",
    "/api/auth/refresh": "JWT_KID_INJECTION",
    "/admin/plugins/install": "SUPPLY_CHAIN_DEPENDENCY_CONFUSION",
    "/latest/meta-data/iam/security-credentials": "CLOUD_METADATA_CREDENTIAL_THEFT",
    "/graphql": "GRAPHQL_INJECTION",
    "/fetch": "SERVER_SIDE_REQUEST_FORGERY",
    "/xml": "XML_EXTERNAL_ENTITY",
    "/redirect": "HTTP_HEADER_INJECTION",
    "/mongo": "NOSQL_INJECTION",
    "/token": "JWT_VERIFICATION_BYPASS",
    "/json": "CODE_INJECTION",
    "/template": "TEMPLATE_INJECTION",
    "/file": "PATH_TRAVERSAL",
    "/wildcard": "PATH_TRAVERSAL",
    "/download": "PATH_TRAVERSAL",
    "/admin": "BROKEN_ACCESS_CONTROL",
    "/hash": "WEAK_CRYPTOGRAPHY",
    "/encrypt": "WEAK_CRYPTOGRAPHY",
    "/ssl_test": "WEAK_TLS_CONFIGURATION",
    "/keyexchange": "UNAUTHENTICATED_KEY_EXCHANGE",
    "/transfer": "CSRF_DISABLED",
    "/credentials": "CLEARTEXT_CREDENTIALS",
    "/debug": "INFORMATION_DISCLOSURE",
    "/log": "LOG_INJECTION",
    "/exception": "IMPROPER_ERROR_HANDLING",
    "/random": "WEAK_RANDOM_GENERATION",
    "/none": "NULL_POINTER_ACCESS",
    "/email": "CLEARTEXT_TRANSMISSION",
    "/ml_model": "INSECURE_MODEL_DOWNLOAD",
    "/pytorch": "INSECURE_MODEL_LOADING",
    "/redis": "UNENCRYPTED_CONNECTION",
    "/html": "IMPROPER_OUTPUT_NEUTRALISATION",
    "/resource": "RESOURCE_EXHAUSTION",
    "/dh_exchange": "WEAK_KEY_EXCHANGE",
    "/config": "CODE_INJECTION",
    "/custom_scheme": "AUTHORISATION_BYPASS",
    "/ldap_anon": "ANONYMOUS_BINDING",
    "/ipmi": "INSECURE_CONFIGURATION",
    "/permissions": "INSECURE_FILE_PERMISSIONS",
    "/tensorflow": "INSECURE_MODEL_SECURITY",
    "/exhaust": "RESOURCE_EXHAUSTION",
    "/database": "HARDCODED_CREDENTIALS"
}


def bbwaf_logging_middleware(app):
    """
    Flask middleware to log exploitation attempts on vulnerable endpoints.
    
    This captures requests to known vulnerable endpoints and logs them
    with BBWAF branding for SIEM ingestion.
    """
    @app.before_request
    def log_vulnerable_endpoint_access():
        from flask import request
        
        path = request.path
        
        if path in VULNERABILITY_MAPPING:
            vulnerability = VULNERABILITY_MAPPING[path]
            
            if request.method == "GET":
                payload = request.query_string.decode("utf-8", errors="ignore")
            elif request.method == "POST":
                payload = request.get_data(as_text=True)[:1000]
            else:
                payload = ""
            
            log_bbwaf_event(path, vulnerability, payload, request)
    
    return app
