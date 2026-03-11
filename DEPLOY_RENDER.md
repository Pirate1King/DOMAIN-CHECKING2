# Render Deploy

If `Page Audit` fails on Render with:

`BrowserType.launch: Executable doesn't exist ...`

then Playwright was installed but Chromium was not bundled into the deploy artifact.

## Recommended Render settings

- Build Command:

```bash
./render-build.sh
```

- Start Command:

```bash
python3 ui_app.py
```

- Environment Variable:

```text
PLAYWRIGHT_BROWSERS_PATH=0
```

- Optional Environment Variable for Geo Audit:

```text
NETWORK_PROFILES=[{"name":"vn-viettel","label":"VN / Viettel","country":"VN","carrier":"Viettel","asn":"AS7552","proxy_url":"http://user:pass@proxy-viettel.example.com:10001"},{"name":"vn-vnpt","label":"VN / VNPT","country":"VN","carrier":"VNPT","asn":"AS45899","proxy_url":"http://user:pass@proxy-vnpt.example.com:10002"},{"name":"th-true","label":"TH / True","country":"TH","carrier":"True","asn":"AS38040","proxy_url":"http://user:pass@proxy-true.example.com:10003"}]
```

## Why this works

`PLAYWRIGHT_BROWSERS_PATH=0` tells Playwright to install the browser inside the Python package path instead of `~/.cache`.

On Render, that is important because home-directory caches are not the safest place to rely on between build and runtime.

## Manual alternative

If you do not want to use `render-build.sh`, set the Build Command to:

```bash
python3 -m pip install -r requirements.txt && PLAYWRIGHT_BROWSERS_PATH=0 python3 -m playwright install chromium
```

## Geo Audit notes

- `Geo Audit` always includes a `Direct` profile.
- Extra profiles come from `NETWORK_PROFILES`.
- Each profile may define:
  - `name`
  - `label`
  - `country`
  - `carrier`
  - `asn`
  - `proxy_url`
- `proxy_url` must use a real numeric port.
  Valid example:

```text
http://user:pass@proxy-viettel.example.com:10001
```

Invalid example:

```text
http://user:pass@host:port
```

## Quick test after deploy

1. Open `Geo Audit`.
2. Confirm the profile dropdown shows:
   - `Direct`
   - your custom profiles from `NETWORK_PROFILES`
3. Run `Direct` with `https://example.com/`.
4. Verify:
   - `observed_ip` is filled
   - screenshots open
   - status is `200`
5. Run one proxy profile with the same URL.
6. Verify:
   - `observed_country` / `observed_org` changes as expected
   - badges show `match` or `mismatch`
   - `asn` badge follows the parsed `ASxxxx` value from the observed org
