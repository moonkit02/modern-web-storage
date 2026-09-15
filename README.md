# modern-web-storage

Session Crawl and Scan Test. Capture a logged-in browser session (real Chrome), crawl the target
two ways to compare which URL set is more usable, then passive-scan the chosen list through the
`az-dast` ZAP image. Built to check whether that image is ready to scan a modern, authenticated site.

## Flow
```
login (real Chrome)  ->  capture storage_state.json (scoped to the target site)
  ->  crawl two ways:  Playwright pre-flight  |  ZAP traditional spider
  ->  compare the two URL lists, pick the more usable one
  ->  passive-scan that list through the az-dast image (no attack traffic)
```

## Files
- `serve.py`   backend: capture, both crawls, passive scan, drives ZAP over its REST API
- `index.html` the page
- `auth_detect.py` token-scrape / auth-scheme detection (vendored from the az-dast scanner)

## Prerequisites
1. Python with Playwright and a Chromium build:
       python3 -m venv .venv-pw
       .venv-pw/bin/pip install playwright
       .venv-pw/bin/playwright install chromium
   (The commands below assume the venv is one level up, at `../.venv-pw`. Adjust the path if not.)
2. Google Chrome installed (the capture uses your real Chrome, not headless Chromium).
3. Docker, and the `az-dast` image built from the scanner repo (only needed for the ZAP crawl and
   the scan). Build it, then run it as a bare ZAP daemon:
       docker build -t az-dast:testing <path-to>/serverless/scanner/containers/dast
       docker run -d --name zapd --platform linux/amd64 -m 4g -p 8090:8090 \
         --entrypoint zap.sh az-dast:testing \
         -daemon -host 0.0.0.0 -port 8090 \
         -config api.disablekey=true \
         -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
   Verify: `curl http://127.0.0.1:8090/JSON/core/view/version/`  ->  {"version":"2.17.0"}

## Run
    ../.venv-pw/bin/python serve.py        # http://127.0.0.1:8099
    # override the ZAP endpoint if needed:  ZAP_API=http://host:port ../.venv-pw/bin/python serve.py

## The two crawls
- Playwright pre-flight: real browser, renders JS, follows on-load `a[href]`. Reaches a SPA's real
  authenticated routes. Bounds are adjustable in the page (pages, depth, children per page, duration).
- ZAP traditional spider: HTTP only, no JS. Good on server-rendered sites; on a SPA it returns mostly
  static and stub URLs. Needs the ZAP daemon above.

Pick whichever list looks more usable, then "Initiate passive scan" runs the passive rules on that
list through ZAP. Passive only: it analyses responses, sends no attack traffic.

## Notes and limits
- ZAP crawl and scan start a fresh ZAP session each run, so results do not carry over between runs.
- Traditional spider does not render JS. For a SPA the Playwright list is the usable one.
- Anti-bot / device-trust sites can still challenge a transplanted session; capture works, the crawl
  may be blocked.
- The scan reuses a long-running `zapd`. Real production scans start their own fresh ZAP per run.

## WARNING
Captured `storage_state.json` files are LIVE credentials. They are gitignored (`*.json`). Never commit
or share them. Delete them after use.
