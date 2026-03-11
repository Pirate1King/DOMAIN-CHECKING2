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

## Why this works

`PLAYWRIGHT_BROWSERS_PATH=0` tells Playwright to install the browser inside the Python package path instead of `~/.cache`.

On Render, that is important because home-directory caches are not the safest place to rely on between build and runtime.

## Manual alternative

If you do not want to use `render-build.sh`, set the Build Command to:

```bash
python3 -m pip install -r requirements.txt && PLAYWRIGHT_BROWSERS_PATH=0 python3 -m playwright install chromium
```
