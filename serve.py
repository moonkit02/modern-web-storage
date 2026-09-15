#!/usr/bin/env python3
"""Tiny test backend for index.html: given {url, storage_state}, run the token-scrape
(auth_detect.py) and replay the session in Playwright to crawl a few authenticated URLs.

Run with the Playwright venv so `from playwright.sync_api ...` works:
    ../.venv-pw/bin/python serve.py      # then open http://127.0.0.1:8099

ponytail: stdlib http.server, one Playwright crawl per request (blocking). This is a
manual test harness, not a service - no threading/queue until it's actually a service.
"""
import json
import os
import subprocess
import sys
import tempfile
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
# auth_detect.py (the token-scrape). Prefer the copy vendored in this repo; fall back to the
# scanner's ai-auth folder when running inside the mono-repo.
try:
    import auth_detect  # noqa: E402
except ModuleNotFoundError:
    sys.path.insert(0, str(HERE.parent / "az-scanner-api/serverless/scanner/containers/dast/ai-auth"))
    import auth_detect  # noqa: E402

MAX_PAGES = 8
PORT = 8099
CDP_PORT = 9222
CHROME = next((c for c in [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
] if os.path.exists(c)), None)
_chrome_proc = None
_capture_url = ""       # the url capture_start opened -> its host selects the right tab at dump time
_capture_profile = None  # fresh temp profile per launch (removed on the next launch)


def capture_start(url):
    """Launch a REAL Chrome with the CDP port open, at url, in a FRESH empty profile so no
    previously-signed-in account carries over. It's real Chrome (not automation-flagged Chromium);
    trust is established when the user logs in (incl. MFA) during this capture."""
    global _chrome_proc, _capture_url, _capture_profile
    import shutil
    import tempfile
    if CHROME is None:
        raise RuntimeError("Google Chrome not found - use capture_session.py instead")
    _capture_url = url or ""
    if _chrome_proc and _chrome_proc.poll() is None:
        return  # already open
    if _capture_profile and os.path.isdir(_capture_profile):
        shutil.rmtree(_capture_profile, ignore_errors=True)  # clean the previous run's profile
    _capture_profile = tempfile.mkdtemp(prefix="az-capture-")
    _chrome_proc = subprocess.Popen([
        CHROME, "--remote-debugging-port=%d" % CDP_PORT,
        "--user-data-dir=" + _capture_profile, "--no-first-run",
        "--no-default-browser-check", url or "about:blank",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def _same_site(cookie_domain, host):
    """True if a cookie for cookie_domain would be sent to host, i.e. they share the same site
    by domain suffix. Used to keep only the target site's cookies and drop every other site."""
    d = (cookie_domain or "").lstrip(".").lower()
    h = (host or "").lower()
    if not d or not h or "." not in d:
        return d == h
    return d == h or h.endswith("." + d) or d.endswith("." + h)

def _scope_state(state, host):
    """Keep only cookies/localStorage that belong to the target host; drop every other site so a
    Website B open in the same browser is never captured. Returns (scoped_state, kept, dropped)."""
    if not host:
        return state, len(state.get("cookies", [])), 0  # no target -> cannot scope, keep as-is
    cookies = state.get("cookies", [])
    kept = [c for c in cookies if _same_site(c.get("domain", ""), host)]
    origins = [o for o in state.get("origins", []) if _same_site(urlparse(o.get("origin", "")).netloc, host)]
    return {"cookies": kept, "origins": origins}, len(kept), len(cookies) - len(kept)

def capture_dump(target_hint=""):
    """Attach to that Chrome over CDP and dump storage_state (cookies + localStorage), scoped to
    the target site only. target_hint = the url the user typed; it selects which site to keep.
    Use 127.0.0.1, not localhost: Chrome binds CDP on IPv4 only, localhost may resolve to ::1."""
    import time
    import urllib.request
    from playwright.sync_api import sync_playwright
    endpoint = "http://127.0.0.1:%d" % CDP_PORT
    for _ in range(10):  # Chrome needs a beat to open the debug port
        try:
            urllib.request.urlopen(endpoint + "/json/version", timeout=1)
            break
        except Exception:
            time.sleep(0.5)
    with sync_playwright() as p:
        b = p.chromium.connect_over_cdp(endpoint)
        ctx = b.contexts[0]
        state = ctx.storage_state()
        # target = the origin of the tab you logged in on (real host, www and all). A persistent
        # profile can restore stale tabs, so prefer the tab whose host matches the url we launched;
        # else the first live http(s) tab; else the session's localStorage origin.
        want = urlparse(_capture_url).netloc
        origins = []
        for pg in ctx.pages:
            u = urlparse(pg.url)
            if u.scheme in ("http", "https"):
                origins.append((u.netloc, "%s://%s/" % (u.scheme, u.netloc)))
        target = next((o for host, o in origins if host == want), "")
        if not target and origins:
            target = origins[0][1]
        if not target and state.get("origins"):
            target = state["origins"][0].get("origin", "") + "/"
        b.close()  # disconnect only; leaves your Chrome open
    # Scope to the target site: prefer the url the user typed, else the tab we detected above.
    host = urlparse(target_hint).netloc or urlparse(target).netloc
    scoped, kept, dropped = _scope_state(state, host)
    return scoped, target, kept, dropped


ZAP_API = os.environ.get("ZAP_API", "http://127.0.0.1:8090")


def _zap(path, **params):
    import urllib.request
    from urllib.parse import urlencode
    return json.load(urllib.request.urlopen(ZAP_API + path + "?" + urlencode(params), timeout=120))


def _clean(urls, max_repeat=2):
    """Drop spider path-loop URLs and de-dup, order preserved. A segment repeating 3+ times
    (/assets/public/assets/public/...) is the SPA-returns-200-for-any-path loop signature.
    Generic: keyed on the repeat, not on any target's path. ponytail: max_repeat=2 tolerates a
    legit twice-repeated segment; raise it if a real site nests deeper."""
    out, seen = [], set()
    for u in urls:
        counts = {}
        loop = False
        for s in filter(None, urlparse(u).path.split("/")):
            counts[s] = counts.get(s, 0) + 1
            if counts[s] > max_repeat:
                loop = True
                break
        if loop or u in seen:
            continue
        seen.add(u)
        out.append(u)
    return out


def _zap_inject_auth(storage_state):
    """Detect the auth in a captured session and inject it into ZAP as Replacer header rules, so
    every ZAP request is authenticated. Shared by the crawl and the scan. Returns the descriptor."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(storage_state, f); spath = f.name
    auth = auth_detect.detect_auth(spath)
    for d in ("zc-hdr", "zc-cookie", "zc-custom"):   # drop any rule a previous run left
        try: _zap("/JSON/replacer/action/removeRule/", description=d)
        except Exception: pass
    if auth and auth["scheme"] == "bearer":
        tok = auth["token"]
        _zap("/JSON/replacer/action/addRule/", description="zc-hdr", enabled="true",
             matchType="REQ_HEADER", matchRegex="false", matchString="Authorization", replacement="Bearer " + tok)
        _zap("/JSON/replacer/action/addRule/", description="zc-cookie", enabled="true",
             matchType="REQ_HEADER", matchRegex="false", matchString="Cookie", replacement="token=" + tok)
    elif auth and auth["scheme"] == "cookie":
        _zap("/JSON/replacer/action/addRule/", description="zc-cookie", enabled="true",
             matchType="REQ_HEADER", matchRegex="false", matchString="Cookie", replacement=auth["cookie_header"])
    elif auth and auth["scheme"] == "header":
        _zap("/JSON/replacer/action/addRule/", description="zc-custom", enabled="true",
             matchType="REQ_HEADER", matchRegex="false", matchString=auth["name"], replacement=auth["value"])
    return auth

def zap_crawl(url, storage_state):
    """Real ZAP traditional spider (HTTP, no JS) with the captured session injected as Replacer
    header rules. Returns the URL set ZAP discovered. Needs the ZAP daemon (see README)."""
    import time
    # Fresh session: ZAP's spider only reports NEWLY seen URLs, so a repeat scan of a site already
    # in the tree returns nothing. Wipe the tree first (Replacer auth rules survive this).
    _zap("/JSON/core/action/newSession/", overwrite="true")
    auth = _zap_inject_auth(storage_state)

    # Bound the spider so the SPA path-loop can't run away and starve real finds (/ftp/*).
    # The bare daemon inherits the image's config (maxDepth may be 0 = unlimited); set our own.
    _zap("/JSON/spider/action/setOptionMaxDepth/", Integer="5")
    _zap("/JSON/spider/action/setOptionMaxDuration/", Integer="4")  # minutes, hard stop
    sid = _zap("/JSON/spider/action/scan/", url=url, maxChildren="10", recurse="true")["scan"]
    for _ in range(120):  # up to ~4 min
        if _zap("/JSON/spider/view/status/", scanId=sid)["status"] == "100":
            break
        time.sleep(2)
    results = _zap("/JSON/spider/view/results/", scanId=sid)["results"]
    return _clean(results), (auth or None)

def zap_scan(target, storage_state, urls, max_urls=40):
    """Passive scan a chosen URL list through the az-dast ZAP daemon: inject the session, fetch each
    URL authenticated (accessUrl), let the passive rules run, return the alerts. No attack traffic.
    urls = whichever crawl's list the user picked. Returns (alerts_grouped, auth, scanned_count)."""
    import time
    _zap("/JSON/core/action/newSession/", overwrite="true")  # fresh tree so only this run's URLs count
    auth = _zap_inject_auth(storage_state)
    _zap("/JSON/pscan/action/enableAllScanners/")
    _zap("/JSON/core/action/deleteAllAlerts/")               # only these URLs' alerts remain
    urls = [u for u in urls if u][:max_urls]                 # bound the work
    for u in urls:
        try: _zap("/JSON/core/action/accessUrl/", url=u, followRedirects="true")
        except Exception: pass                               # a dead stub URL must not abort the scan
    for _ in range(240):                                     # wait for the passive queue to drain
        if int(_zap("/JSON/pscan/view/recordsToScan/")["recordsToScan"]) == 0:
            break
        time.sleep(0.5)
    alerts = _zap("/JSON/core/view/alerts/", baseurl=target)["alerts"]
    grouped = {}                                             # collapse duplicates: (name, risk) -> count
    for a in alerts:
        key = (a["alert"], a["risk"])
        grouped[key] = grouped.get(key, 0) + 1
    out = [{"alert": n, "risk": r, "count": c} for (n, r), c in grouped.items()]
    order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    out.sort(key=lambda x: (order.get(x["risk"], 9), -x["count"]))
    return out, (auth or None), len(urls)


def crawl(url, storage_state, max_pages=8, max_depth=2, max_children=20, max_duration=60):
    """Replay the captured session; BFS same-origin links. Returns (visited_urls, logged_in_guess).
    Spider-style bounds (like ZAP): max_pages total pages, max_depth link hops from the start,
    max_children links followed per page, max_duration seconds hard stop."""
    import time
    from playwright.sync_api import sync_playwright

    host = urlparse(url).netloc
    visited, queue, out = set(), [(url, 0)], []   # queue holds (url, depth)
    logged_in = None
    deadline = time.time() + max_duration
    with sync_playwright() as p:
        # Real Chrome + visible + automation flag off: far less bot-detectable than headless
        # Chromium. Anti-bot sites (Shopee/DataDome) redirect a headless crawler to a
        # /verify/traffic wall even with a valid session. This helps; enterprise WAFs may still block.
        launch = {"headless": False, "args": ["--disable-blink-features=AutomationControlled"]}
        if CHROME:
            launch["channel"] = "chrome"
        browser = p.chromium.launch(**launch)
        ctx = browser.new_context(storage_state=storage_state)
        page = ctx.new_page()
        try:
            while queue and len(out) < max_pages and time.time() < deadline:
                u, depth = queue.pop(0)
                if u in visited:
                    continue
                visited.add(u)
                try:
                    page.goto(u, wait_until="domcontentloaded", timeout=20000)
                    page.wait_for_timeout(1500)  # let SPA render its routerLinks
                except Exception:
                    continue
                if urlparse(page.url).netloc != host:
                    continue  # a same-origin link that redirected offsite (e.g. open-redirect)
                out.append(page.url)
                if logged_in is None:  # judge on the landing page only
                    low = page.url.lower()
                    has_pw = page.query_selector("input[type='password']") is not None
                    logged_in = not (("login" in low or "signin" in low) or has_pw)
                if depth >= max_depth:
                    continue  # reached the depth limit; don't enqueue this page's links
                try:
                    hrefs = page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                except Exception:
                    hrefs = []
                added = 0
                for h in hrefs:
                    if added >= max_children:
                        break  # cap links followed per page
                    if urlparse(h).netloc == host and h not in visited and all(h != q for q, _ in queue):
                        queue.append((h, depth + 1))
                        added += 1
        finally:
            browser.close()
    return out, bool(logged_in)


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        body = body if isinstance(body, bytes) else body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._send(200, (HERE / "index.html").read_bytes(), "text/html; charset=utf-8")
        else:
            self._send(404, b"not found", "text/plain")

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def do_POST(self):
        if self.path == "/capture/start":
            try:
                capture_start(self._body().get("url", ""))
                self._send(200, json.dumps({"ok": True, "port": CDP_PORT}))
            except Exception as e:
                self._send(500, json.dumps({"error": str(e)}))
            return
        if self.path == "/capture/dump":
            try:
                state, target, kept, dropped = capture_dump(self._body().get("url", ""))
                # token-scrape the just-captured session so we can warn on an empty/anon capture
                with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                    json.dump(state, f); spath = f.name
                self._send(200, json.dumps({
                    "storage_state": state,
                    "target_url": target,
                    "kept_cookies": kept,
                    "dropped_cookies": dropped,
                    "auth": auth_detect.detect_auth(spath),
                    "summary": auth_detect.storage_summary(spath),
                }))
            except Exception as e:
                self._send(500, json.dumps({"error": "%s: %s" % (type(e).__name__, e)}))
            return
        if self.path == "/crawl-zap":
            try:
                req = self._body()
                url, storage = req.get("url"), req.get("storage_state")
                if not url or not isinstance(storage, dict):
                    self._send(400, json.dumps({"error": "need url and storage_state object"}))
                    return
                results, auth = zap_crawl(url, storage)
                self._send(200, json.dumps({"crawled": results, "auth": auth, "engine": "zap-spider"}))
            except Exception as e:
                self._send(502, json.dumps({"error": "ZAP unreachable or failed (%s: %s). Start the daemon: "
                                            "see modern-web-storage/README.md" % (type(e).__name__, e)}))
            return
        if self.path == "/scan":
            try:
                req = self._body()
                url, storage, urls = req.get("url"), req.get("storage_state"), req.get("urls")
                if not url or not isinstance(storage, dict) or not isinstance(urls, list) or not urls:
                    self._send(400, json.dumps({"error": "need url, storage_state object, and a non-empty urls list"}))
                    return
                alerts, auth, n = zap_scan(url, storage, urls)
                self._send(200, json.dumps({"alerts": alerts, "auth": auth, "scanned": n, "mode": "passive"}))
            except Exception as e:
                self._send(502, json.dumps({"error": "ZAP unreachable or failed (%s: %s). Start the daemon: "
                                            "see modern-web-storage/README.md" % (type(e).__name__, e)}))
            return
        if self.path != "/crawl":
            self._send(404, json.dumps({"error": "unknown path"}))
            return
        try:
            n = int(self.headers.get("Content-Length", 0))
            req = json.loads(self.rfile.read(n) or b"{}")
            url, storage = req.get("url"), req.get("storage_state")
            if not url or not isinstance(storage, dict):
                self._send(400, json.dumps({"error": "need url and storage_state object"}))
                return
            # token-scrape wants a file path
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                json.dump(storage, f)
                spath = f.name
            auth = auth_detect.detect_auth(spath)
            summary = auth_detect.storage_summary(spath)
            # spider-style bounds from the UI (fall back to the defaults if absent/blank)
            def _int(key, default):
                try: return max(1, int(req.get(key)))
                except (TypeError, ValueError): return default
            crawled, logged_in = crawl(
                url, storage,
                max_pages=_int("max_pages", 8), max_depth=_int("max_depth", 2),
                max_children=_int("max_children", 20), max_duration=_int("max_duration", 60))
            self._send(200, json.dumps({
                "auth": auth, "summary": summary,
                "logged_in": logged_in, "crawled": crawled,
            }))
        except Exception as e:
            self._send(500, json.dumps({"error": "%s: %s" % (type(e).__name__, e)}))

    def log_message(self, *a):  # quieter console
        pass


def _selfcheck():
    got = _clean([
        "http://x/ftp/coupons.bak",
        "http://x/assets/public/assets/public/assets/public/i.png",  # loop -> drop
        "http://x/assets/public/i.png",                              # legit -> keep
        "http://x/ftp/coupons.bak",                                  # dup -> drop
    ])
    assert got == ["http://x/ftp/coupons.bak", "http://x/assets/public/i.png"], got
    print("ok", got)


if __name__ == "__main__":
    if "--selfcheck" in sys.argv:
        _selfcheck()
    else:
        print("Session Crawl Test on http://127.0.0.1:%d  (Ctrl-C to stop)" % PORT)
        HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
