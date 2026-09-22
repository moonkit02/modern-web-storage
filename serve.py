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
import re
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
import har_observed  # noqa: E402  # vendored HAR -> observed-traffic distiller

PORT = 8099
_pw = None              # persistent Playwright (single-threaded server -> reuse across requests)
_cap_ctx = None         # the live capture context, kept OPEN between start and dump
_capture_url = ""       # the url capture_start opened -> its host selects the right tab at dump time
_capture_profile = None  # fresh temp profile per launch (removed on the next launch)
_capture_har = None     # login HAR for this capture -> distilled to observed traffic at dump


def capture_start(url, browser="chrome"):
    """Launch a browser via Playwright in a FRESH profile, at url, RECORDING a login HAR. Playwright
    drives the browser, so storage_state (incl. localStorage) is captured reliably, and the HAR gives
    the observed-traffic auth path. browser selects the engine: 'chrome' (system Google Chrome),
    'firefox', or 'webkit' (Safari's engine) - firefox/webkit need `playwright install firefox webkit`.
    The context is left OPEN until capture_dump; the single-threaded server keeps this on one thread."""
    global _pw, _cap_ctx, _capture_url, _capture_profile, _capture_har
    import shutil
    import tempfile
    from playwright.sync_api import sync_playwright
    _capture_url = url or ""
    if _cap_ctx is not None:
        try:
            _cap_ctx.close()  # discard a prior half-finished capture
        except Exception:
            pass
        _cap_ctx = None
    if _capture_profile and os.path.isdir(_capture_profile):
        shutil.rmtree(_capture_profile, ignore_errors=True)  # clean the previous run's profile
    if _pw is None:
        _pw = sync_playwright().start()
    _capture_profile = tempfile.mkdtemp(prefix="az-capture-")
    _capture_har = os.path.join(_capture_profile, "login.har")
    headless = os.environ.get("CAPTURE_HEADLESS", "").lower() in ("1", "true", "yes")  # headed by default
    opts = {"headless": headless, "record_har_path": _capture_har, "record_har_mode": "full"}
    b = (browser or "chrome").lower()
    if b in ("firefox", "ff"):
        engine = _pw.firefox
    elif b in ("webkit", "safari"):
        engine = _pw.webkit
    else:  # chrome / chromium: use the installed Google Chrome, and blunt the automation flag
        engine = _pw.chromium
        opts["channel"] = "chrome"
        opts["args"] = ["--disable-blink-features=AutomationControlled", "--no-first-run", "--no-default-browser-check"]
    try:
        _cap_ctx = engine.launch_persistent_context(_capture_profile, **opts)
    except Exception as e:
        _cap_ctx = None
        raise RuntimeError("could not launch %s (%s). For firefox/webkit first run: "
                           "playwright install firefox webkit" % (b, e))
    pg = _cap_ctx.pages[0] if _cap_ctx.pages else _cap_ctx.new_page()
    pg.goto(url or "about:blank", wait_until="domcontentloaded")


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
    origins = [o for o in state.get("origins", []) if _same_site(urlparse(o.get("origin", "")).hostname, host)]
    return {"cookies": kept, "origins": origins}, len(kept), len(cookies) - len(kept)

def capture_dump(target_hint=""):
    """Read storage_state off the LIVE capture context (localStorage intact - Playwright drove it),
    distil the login HAR to observed traffic, then close the context (which flushes the HAR).
    target_hint = the url the user typed; it selects which site to keep. Returns the scoped state
    (with an '_observed' blob when the login HAR yielded an auth header) plus the target and counts."""
    global _cap_ctx
    if _cap_ctx is None:
        raise RuntimeError("no capture in progress - click 'Open login browser' first")
    state = _cap_ctx.storage_state()
    # belt-and-suspenders: read localStorage straight off each live page and merge, keyed by origin,
    # in case storage_state() misses it. target = the tab whose host matches the launched url.
    by_origin = {o.get("origin"): o for o in state.get("origins", [])}
    want = urlparse(_capture_url).netloc
    origins = []
    for pg in _cap_ctx.pages:
        u = urlparse(pg.url)
        if u.scheme not in ("http", "https"):
            continue
        origins.append((u.netloc, "%s://%s/" % (u.scheme, u.netloc)))
        try:
            ls = pg.evaluate("() => Object.entries(window.localStorage).map(([name, value]) => ({name, value}))")
        except Exception:
            ls = None
        if ls:
            by_origin["%s://%s" % (u.scheme, u.netloc)] = {
                "origin": "%s://%s" % (u.scheme, u.netloc), "localStorage": ls}
    state["origins"] = list(by_origin.values())
    target = next((o for host, o in origins if host == want), "") or (origins[0][1] if origins else "")
    if not target and state.get("origins"):
        target = state["origins"][0].get("origin", "") + "/"
    # close to flush the HAR, then distil it to the observed-traffic auth input
    har = _capture_har
    try:
        _cap_ctx.close()
    except Exception:
        pass
    _cap_ctx = None
    observed = har_observed.observed_from_har(har) if har and os.path.exists(har) else {}
    # Scope to the target site by hostname (not netloc): a ported dev target (host.docker.internal:8077)
    # would otherwise never match a cookie's port-less domain, dropping the whole session.
    host = urlparse(target_hint).hostname or urlparse(target).hostname
    scoped, kept, dropped = _scope_state(state, host)
    if observed.get("authed_requests"):
        scoped["_observed"] = observed  # rides in the state blob; _run_az_dast splits it out to mount
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

# Static-asset extensions, same set the prod ZAP config excludes from response processing.
_ASSET_RE = re.compile(
    r"\.(jpg|jpeg|png|gif|svg|ico|webp|bmp|woff|woff2|ttf|eot|otf|css|js|mjs|map|pdf|"
    r"mp4|webm|ogg|mov|avi|mkv|flv|wmv|m4v|mp3|wav)$", re.I)

def _is_asset(u):
    return bool(_ASSET_RE.search(urlparse(u).path))

def _filter_crawl(urls, target):
    """Keep only target-host, non-asset URLs. Returns (kept, external_excluded, asset_excluded).
    External = a different host than the target (third-party CDNs like cdnjs.cloudflare.com); asset =
    same host but a static file. Both are counted so nothing is silently dropped."""
    host = urlparse(target).hostname
    kept, external, asset = [], 0, 0
    for u in urls:
        if urlparse(u).hostname != host:
            external += 1
        elif _is_asset(u):
            asset += 1
        else:
            kept.append(u)
    return kept, external, asset


PROD_IMAGE = os.environ.get("PROD_IMAGE", "az-dast:testing")
PROD_PLATFORM = os.environ.get("PROD_PLATFORM", "")   # empty = image's native arch; e.g. linux/amd64
# Passive-relevant slice of entrypoint.sh's ZAP_CONFIGS (keep in sync).
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
# AJAX-spider keys, also from entrypoint.sh. Only added for a full crawl (-j). In this image -j drives
# ZAP 2.17's Client Spider (Chromium). Under amd64 emulation on this Mac it starts but stalls at 0%
# (Chrome can't drive), so it adds ~no URLs and just runs to its time limit; it works on a real amd64 host.
PROD_AJAX_CONFIG = (
    " -config ajaxSpider.maxDuration=15 "
    "-config ajaxSpider.maxCrawlDepth=10 "
    "-config ajaxSpider.numberOfBrowsers=4 "
    "-config ajaxSpider.randomInputs=true "
    "-config ajaxSpider.browserId=chrome-headless "
    "-config selenium.chromeDriver=/usr/bin/chromedriver "
    "-config selenium.chromeBinary=/usr/local/bin/chromium-nosandbox"
)

def _run_az_dast(url, storage_state, ajax=False, timeout=1800):
    """The one place a scan actually runs: docker run the real az-dast image through its prod driver
    (zap-baseline.py + the prod hook). storage_state=None runs logged-out; a dict is injected the prod
    way (SESSION_FILE -> az_ai_auth.py inside the image). ajax=True adds the AJAX spider (-j) for a
    full prod crawl (spider + AJAX). No active scan either way. Returns {urls, alerts, exit_code,
    log_tail}. Skips only the entrypoint's S3-upload tail (needs cloud creds)."""
    name = "az-dast-" + os.urandom(4).hex()
    sess = None
    obs_file = None
    mem = "6g" if ajax else "4g"                            # AJAX runs several browsers; give it room
    # Default to the image's native arch. On an arm64 host use an arm64 build (Dockerfile.arm64) so
    # Chromium runs natively; set PROD_PLATFORM=linux/amd64 only when running the amd64 image.
    cmd = ["docker", "run", "-d", "--name", name, "-m", mem]
    if PROD_PLATFORM:
        cmd += ["--platform", PROD_PLATFORM]
    if storage_state is not None:
        st = dict(storage_state)
        observed = st.pop("_observed", None)               # rides in the blob; write it as its own file
        sess = HERE / (".session-%s.json" % name)          # project dir is a Docker-shared path
        sess.write_text(json.dumps(st))
        cmd += ["-v", "%s:/app/resources/session.json:ro" % sess,
                "-e", "SESSION_FILE=/app/resources/session.json", "-e", "AI_AUTH_DIR=/app"]
        if observed:
            # az_ai_auth.detect_auth reads auth-observed.json beside the session file, so mount it
            # there. Lets the container use the observed auth header (in-memory JWT that is not in
            # localStorage/cookies); harmless when the storage path already found the token.
            obs_file = HERE / (".observed-%s.json" % name)
            obs_file.write_text(json.dumps(observed))
            cmd += ["-v", "%s:/app/resources/auth-observed.json:ro" % obs_file]
    cmd += ["--entrypoint", "zap-baseline.py", PROD_IMAGE,
            "-t", url, "-I", "-d", "-J", "report.json",
            "--hook", "/zap/wrk/hook/az-custom-hook.py"]
    cmd += ["-j"] if ajax else []                           # -j = add the AJAX spider (full crawl)
    cmd += ["-z", PROD_ZAP_CONFIG + (PROD_AJAX_CONFIG if ajax else "")]
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
        if obs_file is not None:
            obs_file.unlink(missing_ok=True)

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

def zap_crawl(url, storage_state, ajax=False, no_auth=False):
    """zap_crawl(url, storage_state) -> docker run the prod img -> read the crawled URL list from its
    report/log -> return (urls, auth_for_display). The image crawls the target with the session
    injected via SESSION_FILE. ajax=True runs the full prod crawl (spider + AJAX). no_auth=True runs
    logged-out (no session), so the same crawl can be compared with vs without auth."""
    r = _run_az_dast(url, None if no_auth else storage_state, ajax=ajax)
    auth = None if no_auth else (_detect_auth(storage_state) or None)
    return r["urls"], auth

def zap_scan(url, storage_state, no_auth=False):
    """zap_scan(...) -> docker run the same prod img -> read the passive alerts from its report ->
    return (alerts, auth_for_display, scanned_url_count). no_auth=True runs with no session, so the
    two runs compare logged-in vs logged-out findings on the same target."""
    r = _run_az_dast(url, None if no_auth else storage_state)
    auth = None if no_auth else (_detect_auth(storage_state) or None)
    return r["alerts"], auth, len(r["urls"])


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
                body = self._body()
                capture_start(body.get("url", ""), body.get("browser", "chrome"))
                self._send(200, json.dumps({"ok": True}))
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
                no_auth = bool(req.get("no_auth"))       # no-auth run needs no session
                if not url or (not no_auth and not isinstance(storage, dict)):
                    self._send(400, json.dumps({"error": "need url and storage_state object"}))
                    return
                ajax = bool(req.get("ajax"))             # full crawl = spider + AJAX
                results, auth = zap_crawl(url, storage, ajax=ajax, no_auth=no_auth)
                # show only the target's own pages: drop third-party hosts and static assets,
                # reporting how many of each were hidden so the count is transparent
                kept, external_excluded, asset_excluded = _filter_crawl(results, url)
                self._send(200, json.dumps({"crawled": kept, "auth": auth,
                                            "external_excluded": external_excluded,
                                            "asset_excluded": asset_excluded,
                                            "total_touched": len(results),
                                            "engine": "az-dast-full" if ajax else "az-dast-baseline"}))
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
        self._send(404, json.dumps({"error": "unknown path"}))

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
