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
3. Docker, and the `az-dast` image built from the scanner repo (needed for the az-dast crawl and the
   scan). Just build it - no daemon to start:
       docker build -t az-dast:testing <path-to>/serverless/scanner/containers/dast
   Every ZAP action runs the real image: `serve.py` does `docker run az-dast:testing` through its prod
   driver (`zap-baseline.py` + the prod hook), reads the report it produces, and returns the result.
   Override the image tag with `PROD_IMAGE=...` if yours differs.

## Run
    ../.venv-pw/bin/python serve.py        # http://127.0.0.1:8099

## The two crawls
- Playwright pre-flight: real browser, renders JS, follows on-load `a[href]`. Reaches a SPA's real
  authenticated routes. Bounds are adjustable in the page (pages, depth, children per page, duration).
  Runs client-side, independent of the image.
- az-dast crawl: `docker run` the real image; it crawls (and passive-scans) the target itself with
  the session injected the prod way (`SESSION_FILE`). HTTP only, no JS; on a SPA it returns mostly
  static and stub URLs. Slow (minutes).

The passive scan buttons also `docker run` the real image: "with auth" injects the captured session,
"no auth" runs logged-out - run both to compare logged-in vs logged-out findings on the same target.
Passive only (baseline mode): it analyses responses, sends no attack traffic.

## Notes and limits
- Each crawl/scan is its own `docker run` (fresh container, fresh ZAP session), so nothing carries
  over between runs. The image's crawl always passive-scans too; the crawl view just keeps the URLs.
- Two deviations from the prod `entrypoint.sh`, both infra not scan-logic: no S3-upload/API-notify
  tail (needs cloud creds), and no AJAX spider (`-j`) - its Chromium crashes under amd64 emulation on
  this Mac. Traditional spider + passive rules still run.
- Anti-bot / device-trust sites can still challenge a transplanted session; capture works, the crawl
  may be blocked.

## WARNING
Captured `storage_state.json` files are LIVE credentials. They are gitignored (`*.json`). Never commit
or share them. Delete them after use.
