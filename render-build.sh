#!/usr/bin/env bash
set -euo pipefail

python3 -m pip install -r requirements.txt
PLAYWRIGHT_BROWSERS_PATH=0 python3 -m playwright install chromium
