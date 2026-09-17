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


PROD_IMAGE = os.environ.get("PROD_IMAGE", "az-dast:testing")
# Passive-relevant slice of entrypoint.sh's ZAP_CONFIGS (keep in sync). Active-scan/AJAX keys are
# left out on purpose: baseline mode never active-scans, and the AJAX spider needs a browser that
# crashes under amd64 emulation on this Mac.
PROD_ZAP_CONFIG = (
    "-config http.response.max_size=1048576 "
    "-config http.exclude_response_regex=.*\\.(jpg|jpeg|png|gif|svg|woff|woff2|ico|pdf|css|js|ttf|eot|otf|mp4|webm|ogg|mov|avi|mkv|flv|wmv|m4v) "
    "-config timeoutInSecs=10 "
    "-config database.persistent=false "
    "-config passiveScan.maxAlertsPerRule=3 "
    "-config spider.maxDepth=10 "
    "-config spider.maxChildren=30 "
    "-config spider.maxDuration=1800"
)

def _run_az_dast(url, storage_state, timeout=1200):
    """The one place a scan actually runs: docker run the real az-dast image through its prod driver
    (zap-baseline.py + the prod hook). storage_state=None runs logged-out; a dict is injected the prod
    way (SESSION_FILE -> az_ai_auth.py inside the image). Baseline = spider + passive, no active scan.
    Returns {urls, alerts, exit_code, log_tail}. Skips only the entrypoint's S3-upload tail (cloud
    creds) and the AJAX spider (its browser crashes under amd64 emulation on this Mac)."""
    name = "az-dast-" + os.urandom(4).hex()
    sess = None
    cmd = ["docker", "run", "-d", "--name", name, "--platform", "linux/amd64", "-m", "4g"]
    if storage_state is not None:
        sess = HERE / (".session-%s.json" % name)          # project dir is a Docker-shared path
        sess.write_text(json.dumps(storage_state))
        cmd += ["-v", "%s:/app/resources/session.json:ro" % sess,
                "-e", "SESSION_FILE=/app/resources/session.json", "-e", "AI_AUTH_DIR=/app"]
    cmd += ["--entrypoint", "zap-baseline.py", PROD_IMAGE,
            "-t", url, "-I", "-d", "-J", "report.json",
            "--hook", "/zap/wrk/hook/az-custom-hook.py",
            "-z", PROD_ZAP_CONFIG]
    try:
        run = subprocess.run(cmd, capture_output=True, text=True)
        if run.returncode != 0:
            raise RuntimeError("docker run failed: " + (run.stderr.strip() or run.stdout.strip()))
        code = subprocess.run(["docker", "wait", name], capture_output=True, text=True, timeout=timeout).stdout.strip()
        got = subprocess.run(["docker", "logs", name], capture_output=True, text=True)
        logs = got.stdout + got.stderr
        report = HERE / (".report-%s.json" % name)
        cp = subprocess.run(["docker", "cp", name + ":/zap/wrk/report.json", str(report)], capture_output=True, text=True)
        data = json.loads(report.read_text()) if cp.returncode == 0 and report.exists() else {}
        report.unlink(missing_ok=True)
        # crawled URLs: the hook dumps them to the log on a session run; union with the report's URIs
        log_urls = {ln.strip() for ln in logs.splitlines()
                    if ln.strip().startswith(("http://", "https://")) and " " not in ln.strip()}
        urls = _clean(sorted(log_urls | set(_report_uris(data))))
        return {"urls": urls, "alerts": _report_alerts(data),
                "exit_code": code, "log_tail": "\n".join(logs.splitlines()[-25:])}
    finally:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True)
        if sess is not None:
            sess.unlink(missing_ok=True)

def _report_uris(data):
    """Every URL ZAP recorded a finding on, from the baseline JSON report's alert instances."""
    return [inst["uri"] for site in data.get("site", []) for a in site.get("alerts", [])
            for inst in a.get("instances", []) if inst.get("uri")]

def _report_alerts(data):
    """Group the baseline JSON report into [{alert, risk, count}], most-severe first."""
    grouped = {}
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            risk = (a.get("riskdesc", "") or "").split(" ")[0] or "Informational"
            key = (a.get("alert") or a.get("name", "?"), risk)
            grouped[key] = grouped.get(key, 0) + int(a.get("count") or len(a.get("instances", [])) or 1)
    out = [{"alert": n, "risk": r, "count": c} for (n, r), c in grouped.items()]
    order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
    out.sort(key=lambda x: (order.get(x["risk"], 9), -x["count"]))
    return out

def _detect_auth(storage_state):
    """Detect the session's auth scheme for display only (the container does the real injection)."""
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(storage_state, f); spath = f.name
    try:
        return auth_detect.detect_auth(spath)
    finally:
        os.unlink(spath)

def zap_crawl(url, storage_state):
    """zap_crawl(url, storage_state) -> docker run the prod img -> read the crawled URL list from its
    report/log -> return (urls, auth_for_display). The image crawls the target with the session
    injected via SESSION_FILE. Baseline passive-scans too; here we keep only the URLs."""
    r = _run_az_dast(url, storage_state)
    return r["urls"], (_detect_auth(storage_state) or None)

def zap_scan(url, storage_state, no_auth=False):
    """zap_scan(...) -> docker run the same prod img -> read the passive alerts from its report ->
    return (alerts, auth_for_display, scanned_url_count). no_auth=True runs with no session, so the
    two runs compare logged-in vs logged-out findings on the same target."""
    r = _run_az_dast(url, None if no_auth else storage_state)
    auth = None if no_auth else (_detect_auth(storage_state) or None)
    return r["alerts"], auth, len(r["urls"])

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
                self._send(200, json.dumps({"crawled": results, "auth": auth, "engine": "az-dast-baseline"}))
            except Exception as e:
                self._send(502, json.dumps({"error": "az-dast container run failed (%s: %s)" % (type(e).__name__, e)}))
            return
        if self.path == "/scan":
            try:
                req = self._body()
                url, storage = req.get("url"), req.get("storage_state")
                no_auth = bool(req.get("no_auth"))           # no-auth run needs no session
                if not url or (not no_auth and not isinstance(storage, dict)):
                    self._send(400, json.dumps({"error": "need url, and (unless no_auth) a storage_state object"}))
                    return
                alerts, auth, n = zap_scan(url, storage, no_auth=no_auth)
                self._send(200, json.dumps({"alerts": alerts, "auth": auth, "scanned": n, "mode": "passive"}))
            except Exception as e:
                self._send(502, json.dumps({"error": "az-dast container run failed (%s: %s)" % (type(e).__name__, e)}))
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
