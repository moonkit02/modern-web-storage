"""Auth-material detection for the DAST hook (pure logic: no scanner, no network).

  detect_auth(storage_path[, observed_path])  -> auth descriptor, or None if no auth was found
                                                 what the scanner must replay to stay logged in:
                                                 {'scheme': 'header'|'bearer'|'cookie', ...}
  storage_summary(path)                        -> str; what the login actually captured (diagnostic)

Inputs  : resources/storage_state.json (Playwright cookies + localStorage) and, when present,
          resources/auth-observed.json (login request/response traffic), both from ai-login.py
Output  : one auth descriptor dict (header / bearer / cookie) or None
Used by : az_ai_auth.py (same dir), which injects the returned material into the scanner's Replacer

Env     : AUTH_EXTRA_COOKIES  'k=v; k2=v2' cookies to add/override in the cookie jar
                              (e.g. force DVWA security=low for scanning)
"""
import base64
import json
import os
import re
from pathlib import Path

# ---------- shared shape helpers (JWT + nested-JSON leaves) ----------

# A JWT is three base64url segments whose header decodes to JSON with an "alg" field.
_JWT_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")

def _is_jwt(value):
    if not isinstance(value, str) or not _JWT_RE.match(value):
        return False
    header = value.split(".", 1)[0]
    try:
        decoded = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
        return "alg" in json.loads(decoded)
    except Exception:
        return False

def _iter_json_leaves(value, key=""):
    """Yield (key, string) for every string leaf inside value, recursing into JSON-encoded
    strings (redux-persist / persisted-store blobs are double-JSON-encoded)."""
    if isinstance(value, str):
        if value.lstrip()[:1] in ("{", "["):
            try:
                yield from _iter_json_leaves(json.loads(value), key)
                return
            except Exception:
                pass
        yield key, value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _iter_json_leaves(v, k)
    elif isinstance(value, list):
        for v in value:
            yield from _iter_json_leaves(v, key)

# ---------- observed request-header ranker ----------

# Standard / hop-by-hop / fingerprinting request headers - never the app's auth header.
_STD_HEADERS = {
    "host", "connection", "user-agent", "accept", "accept-encoding", "accept-language",
    "accept-charset", "content-type", "content-length", "referer", "origin", "cookie",
    "cache-control", "pragma", "dnt", "upgrade-insecure-requests", "te", "trailer",
    "transfer-encoding", "keep-alive", "proxy-connection", "if-none-match",
    "if-modified-since", "range", "x-requested-with", "priority", "viewport-width",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform", "sec-gpc",
}

# Header-name patterns that suggest auth, best-known first. Tiebreak only.
_AUTH_NAME_PATS = ("authorization", "x-access-token", "access-token", "x-auth-token",
                   "x-auth", "x-api-key", "api-key", "apikey", "x-token", "auth-token",
                   "bearer", "token")

def _response_values(login_response):
    """Strings the login response handed back (header values + every body leaf), len>=8.
    A candidate request header that carries one of these is replaying the issued token."""
    out = set()
    if not isinstance(login_response, dict):
        return out
    for v in (login_response.get("headers") or {}).values():
        if isinstance(v, str) and len(v) >= 8:
            out.add(v)
    body = login_response.get("body")
    if isinstance(body, str) and body:
        for _, leaf in _iter_json_leaves(body):
            if len(leaf) >= 8:
                out.add(leaf)
    return out

def _constant_headers(authed_requests):
    """Non-standard headers with a SINGLE value across every request in one login session
    -> {name: value}. (A per-request-varying header like X-Request-Id is dropped.)"""
    reqs = [r.get("headers") or {} for r in (authed_requests or [])]
    reqs = [h for h in reqs if h]
    if not reqs:
        return {}
    common = set(reqs[0])
    for h in reqs[1:]:
        common &= set(h)
    out = {}
    for name in common:
        if name.lower() in _STD_HEADERS:
            continue
        values = {h[name] for h in reqs}
        if len(values) == 1:
            out[name] = next(iter(values))
    return out

def _session_scoped(sess_a, sess_b):
    """Headers constant within each login but DIFFERENT between two same-cred logins
    -> per-session token (fresh JWT / session id). Empty if the 2nd login is absent."""
    a, b = _constant_headers(sess_a), _constant_headers(sess_b)
    return {name for name in a if name in b and a[name] != b[name]}

def _header_score(name, value, resp_values, session_scoped=False):
    """Higher = more likely the auth header; 0 = not a candidate. A candidate needs a robust
    token signal (correlation / JWT / session-scoped); name only breaks ties."""
    name_lower = name.lower()
    if "csrf" in name_lower or "xsrf" in name_lower:
        return 0                                       # anti-CSRF nonce, never the auth token
    if not isinstance(value, str) or len(value) < 8:
        return 0
    score = 0
    if any(rv in value for rv in resp_values):
        score += 100                                   # correlation: replays an issued value
    if any(_is_jwt(part) for part in value.replace("Bearer ", " ").split()):
        score += 50                                    # carries a JWT (bare or "Bearer <jwt>")
    if session_scoped and len(value) >= 20:
        score += 40   # ponytail: changed across 2 logins; a per-session opaque non-auth id
                      # (rare) could false-positive here - correlation(100)/JWT(50) override it.
    if score == 0:
        return 0                                       # no robust signal -> not the auth header
    for rank, pat in enumerate(_AUTH_NAME_PATS):
        if pat in name_lower:
            score += 10 - rank                         # tiebreak, earlier pattern = better
            break
    return score

def detect_auth_observed(observed):
    """Rank observed request headers; return the winning auth header or None.
    observed: the parsed auth-observed.json dict (see module docstring)."""
    if not isinstance(observed, dict):
        return None
    resp_values = _response_values(observed.get("login_response") or {})
    sess_a = observed.get("authed_requests")
    scoped = _session_scoped(sess_a, observed.get("authed_requests_2")) if observed.get("authed_requests_2") else set()

    best = None   # (score, name, value)
    # enumerate headers present in every request of login #1; replay that login's value.
    reqs = [r.get("headers") or {} for r in (sess_a or []) if r.get("headers")]
    common = set(reqs[0]) if reqs else set()
    for h in reqs[1:]:
        common &= set(h)
    for name in sorted(common):
        if name.lower() in _STD_HEADERS:
            continue
        value = reqs[-1][name]
        score = _header_score(name, value, resp_values, name in scoped)
        if score > 0 and (best is None or score > best[0]):
            best = (score, name, value)
    if best:
        _, name, value = best
        return {"scheme": "header", "location": "request-header", "name": name, "value": value}
    return None

# ---------- storage_state (bearer by shape, else cookie jar) ----------

# Bearer-token key names (case-insensitive substring), best-known first. Excludes session-cookie
# names (PHPSESSID/JSESSIONID) so those fall through to cookie-session mode.
_BEARER_KEYS = ("access_token", "accesstoken", "id_token", "idtoken", "auth_token",
                "authtoken", "jwt", "bearer", "apitoken", "api_token", "token")

def read_cookies(path):
    """Session cookies from the storage_state as a 'k=v; k2=v2' Cookie header, '' if none.
    AUTH_EXTRA_COOKIES ('k=v; k2=v2') overrides/adds (e.g. force DVWA security=low)."""
    state = json.loads(Path(path).read_text())
    cookies = {cookie["name"]: cookie["value"] for cookie in state.get("cookies", [])}
    for pair in os.environ.get("AUTH_EXTRA_COOKIES", "").split(";"):
        if "=" in pair:
            name, value = pair.split("=", 1)
            cookies[name.strip()] = value.strip()
    return "; ".join("%s=%s" % (name, value) for name, value in cookies.items())

def _bearer_score(key, value):
    if _is_jwt(value):
        return 100                                     # self-identifying JWT
    key_lower = key.lower()
    if "csrf" in key_lower or "xsrf" in key_lower:
        return 0
    if len(value) < 20:
        return 0
    for rank, name in enumerate(_BEARER_KEYS):
        if name in key_lower:
            return 50 - rank
    return 0

def _detect_from_storage(path):
    """Bearer token from localStorage, else fall back to the whole cookie jar."""
    state = json.loads(Path(path).read_text())
    best = None
    def consider(location, key, value):
        nonlocal best
        score = _bearer_score(key, value)
        if score > 0 and (best is None or score > best[0]):
            best = (score, location, key, value)

    # Scan localStorage only: a JWT there is sent as an auth header (bearer). A JWT in a cookie is
    # covered by the always-on cookie-jar replay, so it is not scored here.
    for origin in state.get("origins", []):
        for entry in origin.get("localStorage", []):
            for leaf_key, leaf_value in _iter_json_leaves(entry["value"], entry["name"]):
                consider("localStorage", leaf_key, leaf_value)

    if best:
        _, location, key, value = best
        return {"scheme": "bearer", "location": location, "key": key, "token": value}

    cookie_header = read_cookies(path)
    return {"scheme": "cookie", "cookie_header": cookie_header} if cookie_header else None

# ---------- entry point ----------

def detect_auth(storage_path, observed_path=None):
    """Return what the scanner must replay to stay authenticated: try the observed request headers first,
    then fall back to the stored session (see module docstring for the full contract).
    observed_path defaults to auth-observed.json beside storage_path."""
    if observed_path is None:
        observed_path = Path(storage_path).with_name("auth-observed.json")
    observed_path = Path(observed_path)
    if observed_path.exists():
        try:
            hit = detect_auth_observed(json.loads(observed_path.read_text()))
            if hit:
                return hit
        except Exception:
            pass   # bad/absent capture -> fall through to storage_state
    return _detect_from_storage(storage_path)

def storage_summary(path):
    """What the login captured - for the 'creds given but no token' diagnostic."""
    try:
        state = json.loads(Path(path).read_text())
    except Exception as e:
        return "no readable storage_state (%s)" % e
    ls_keys = [entry["name"] for origin in state.get("origins", []) for entry in origin.get("localStorage", [])]
    cookie_names = [cookie["name"] for cookie in state.get("cookies", [])]
    if not ls_keys and not cookie_names:
        return "storage_state empty (login did not establish a browser session)"
    return "localStorage keys=%s; cookies=%s" % (ls_keys or [], cookie_names or [])

if __name__ == "__main__":
    tmp = Path(os.environ.get("TMPDIR", "/tmp"))
    _jwt = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode() + ".eyJ1IjoxfQ.sig"

    # --- observed request-header ranker (pure, no browser) ---
    # correlation wins: an opaque token issued in the login response body, replayed in a custom
    # request header a scanner would never guess by name.
    obs = {"login_response": {"headers": {}, "body": json.dumps({"data": {"session": "OPAQUE" + "z" * 30}})},
           "authed_requests": [{"headers": {"User-Agent": "x", "X-Whatever": "OPAQUE" + "z" * 30}},
                               {"headers": {"User-Agent": "x", "X-Whatever": "OPAQUE" + "z" * 30}}]}
    a = detect_auth_observed(obs)
    assert a and a["scheme"] == "header" and a["name"] == "X-Whatever", a

    # in-memory JWT in Authorization, storage_state totally empty, no response body captured
    obs = {"login_response": {"headers": {}, "body": ""},
           "authed_requests": [{"headers": {"Authorization": "Bearer " + _jwt, "Accept": "*/*"}},
                               {"headers": {"Authorization": "Bearer " + _jwt, "Accept": "*/*"}}]}
    a = detect_auth_observed(obs)
    assert a and a["name"] == "Authorization" and a["value"] == "Bearer " + _jwt, a

    # constant opaque non-auth header (X-Trace-Id: correlation id) must NOT be picked - no
    # correlation, no JWT. This is the false positive the appeared-after signal used to cause.
    obs = {"authed_requests": [{"headers": {"X-Trace-Id": "z" * 40, "Accept": "*/*"}},
                               {"headers": {"X-Trace-Id": "z" * 40, "Accept": "*/*"}}]}
    assert detect_auth_observed(obs) is None, "opaque non-token header must not be picked"

    # csrf header must never win even if it correlates with the response
    obs = {"login_response": {"headers": {}, "body": json.dumps({"csrf": "c" * 40})},
           "authed_requests": [{"headers": {"X-CSRF-Token": "c" * 40}},
                               {"headers": {"X-CSRF-Token": "c" * 40}}]}
    assert detect_auth_observed(obs) is None, "csrf must not be picked"

    # two-login diff: opaque session token, no response body, no JWT. Login #1 and #2 carry
    # DIFFERENT values in X-Session (constant within each) -> session-scoped -> picked.
    # A header identical across both logins (X-Config) is boilerplate -> ignored.
    obs = {"authed_requests":   [{"headers": {"X-Session": "A" * 40, "X-Config": "static"}},
                                 {"headers": {"X-Session": "A" * 40, "X-Config": "static"}}],
           "authed_requests_2": [{"headers": {"X-Session": "B" * 40, "X-Config": "static"}},
                                 {"headers": {"X-Session": "B" * 40, "X-Config": "static"}}]}
    a = detect_auth_observed(obs)
    assert a and a["name"] == "X-Session" and a["value"] == "A" * 40, a   # replays login #1

    # single login (no 2nd) + opaque token = no signal -> None (unchanged; diff needs 2 logins)
    obs = {"authed_requests": [{"headers": {"X-Session": "A" * 40}},
                               {"headers": {"X-Session": "A" * 40}}]}
    assert detect_auth_observed(obs) is None, "opaque token needs correlation/JWT or a 2nd login"

    # --- storage_state source ---
    p = tmp / "auth_detect2_state.json"
    p.write_text(json.dumps({"origins": [{"localStorage": [{"name": "token", "value": _jwt}]}]}))
    a = detect_auth(p)   # no auth-observed.json beside it -> falls to storage
    assert a["scheme"] == "bearer" and a["location"] == "localStorage" and a["token"] == _jwt, a

    p.write_text(json.dumps({"origins": [{"localStorage": [{"name": "access_token", "value": "x" * 30}]}]}))
    a = detect_auth(p)
    assert a["scheme"] == "bearer" and a["key"] == "access_token", a

    p.write_text(json.dumps({
        "origins": [{"localStorage": [
            {"name": "persist:reducers",
             "value": json.dumps({"userReducer": json.dumps({"isLoggedIn": True, "accessToken": _jwt})})}]}],
        "cookies": [{"name": "chat_session_id", "value": "3" * 32}]}))
    a = detect_auth(p)
    assert a["scheme"] == "bearer" and a["key"] == "accessToken" and a["token"] == _jwt, a

    p.write_text(json.dumps({"cookies": [{"name": "PHPSESSID", "value": "abc"}]}))
    a = detect_auth(p)
    assert a["scheme"] == "cookie" and "PHPSESSID=abc" in a["cookie_header"], a

    p.write_text(json.dumps({"cookies": [{"name": "JSESSIONID", "value": "d" * 32}]}))
    assert detect_auth(p)["scheme"] == "cookie", "JSESSIONID is a session, not a bearer"

    # JWT stored IN A COOKIE is cookie-auth, not a bearer header:
    # the browser replays it as a cookie. Must be whole-cookie replay, not Authorization: Bearer.
    p.write_text(json.dumps({"cookies": [{"name": "cloud.session.token", "value": _jwt},
                                         {"name": "dsc", "value": "e" * 32}]}))
    a = detect_auth(p)
    assert a["scheme"] == "cookie" and "cloud.session.token=%s" % _jwt in a["cookie_header"], a

    p.write_text(json.dumps({"origins": [{"localStorage": [{"name": "csrf_token", "value": "y" * 30}]}]}))
    assert detect_auth(p) is None, "csrf token must not be picked"

    # --- header source wins over storage when both are present (in-memory token app) ---
    p.write_text(json.dumps({"origins": [], "cookies": []}))   # empty storage
    obsp = p.with_name("auth-observed.json")
    obsp.write_text(json.dumps({
        "login_response": {"headers": {}, "body": json.dumps({"token": _jwt})},
        "authed_requests": [{"headers": {"Authorization": "Bearer " + _jwt}},
                            {"headers": {"Authorization": "Bearer " + _jwt}}]}))
    a = detect_auth(p)
    assert a["scheme"] == "header" and a["name"] == "Authorization", a
    obsp.unlink()

    assert "csrf" not in storage_summary(p)   # storage is empty here
    p.unlink()
    print("auth_detect2 selfcheck ok")
