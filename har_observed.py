"""HAR -> auth-observed.json distillation, vendored from the scanner's crawl/ai-login.py
(har_to_observed) so this tool builds the exact observed-traffic input auth_detect.detect_auth_observed
consumes. Pure HAR parsing, no browser-use dependency. Source of truth is
az-scanner-api .../ai-auth/crawl/ai-login.py - keep in sync by hand.

observed_from_har(har_path) -> {'login_response': {...}, 'authed_requests': [...]} or {}
"""
import base64
import json
from pathlib import Path
from urllib.parse import urlsplit

# URL substrings that mark the login POST (its response body carries the issued token)
LOGIN_HINTS = ("login", "signin", "sign-in", "authenticate", "/auth", "token", "session", "oauth")

def _origin(url):
    p = urlsplit(url or "")
    return "%s://%s" % (p.scheme, p.netloc) if p.scheme else ""

def _headers_dict(hlist):
    out = {}
    for h in hlist or []:
        name = h.get("name", "")
        if not name or name.startswith(":"):   # skip HTTP/2 pseudo-headers (:method, :path, ...)
            continue
        out[name] = h.get("value", "")
    return out

def _body_text(content):
    text = content.get("text") or ""
    if content.get("encoding") == "base64" and text:
        try:
            return base64.b64decode(text).decode("utf-8", "replace")
        except Exception:
            return ""
    return text

def observed_from_har(har_path, max_authed=15):
    """Parse a browser HAR into the auth-observed.json shape: the login response (for correlation)
    plus the request headers of the same-origin JSON API calls that followed (where the auth header
    lives). Static assets / third-party JSON are dropped. Returns {} if nothing useful."""
    try:
        log = json.loads(Path(har_path).read_text())["log"]
    except Exception:
        return {}
    entries = log.get("entries", [])
    login_idx = None
    for i, e in enumerate(entries):
        req = e.get("request", {})
        if (req.get("method") or "").upper() != "POST":
            continue
        if any(hint in (req.get("url") or "").lower() for hint in LOGIN_HINTS):
            login_idx = i                      # keep the LAST login-ish POST (retries, refresh)
    obs = {}
    if login_idx is not None:
        r = entries[login_idx].get("response", {})
        obs["login_response"] = {"headers": _headers_dict(r.get("headers")),
                                 "body": _body_text(r.get("content") or {})}
    origin = _origin(entries[login_idx]["request"]["url"]) if login_idx is not None else (
        _origin(entries[0]["request"]["url"]) if entries else "")
    authed = []
    for e in entries[(login_idx + 1) if login_idx is not None else 0:]:
        req, resp = e.get("request", {}), e.get("response", {})
        mime = ((resp.get("content") or {}).get("mimeType") or "").lower()
        if "json" not in mime:                 # API calls carry the token; static assets don't
            continue
        if origin and not (req.get("url") or "").startswith(origin):
            continue                           # same-origin only (skip third-party analytics)
        authed.append({"headers": _headers_dict(req.get("headers"))})
        if len(authed) >= max_authed:
            break
    if authed:
        obs["authed_requests"] = authed
    return obs
