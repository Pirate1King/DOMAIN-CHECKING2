import json
import mimetypes
import os
import re
import threading
import time
import uuid
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse
from urllib.error import URLError
from urllib.request import ProxyHandler, Request, build_opener, install_opener, urlopen

from check_domains import build_output_header, process_domain


HTML_PATH = Path(__file__).with_name("ui.html")
ARTIFACT_ROOT = Path(__file__).with_name("artifacts")
JOBS = {}
JOBS_LOCK = threading.Lock()
DOMAIN_WORKERS = 4
AUDIT_WORKERS = 2
EGRESS_IP_SOURCES = (
    ("https://api.ipify.org?format=json", "ipify_json"),
    ("https://api.ipify.org", "ipify_text"),
    ("https://ifconfig.me/ip", "ifconfig_text"),
)
IPINFO_SOURCES = (
    ("https://ipinfo.io/json", "ipinfo"),
    ("https://api.ipify.org?format=json", "ipify_json"),
)


class Handler(BaseHTTPRequestHandler):
    def _send(self, status, body, content_type):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path.startswith("/artifacts/"):
            self._handle_artifact()
            return
        if self.path.startswith("/geo/profiles"):
            self._handle_geo_profiles()
            return
        if self.path.startswith("/egress-ip"):
            self._handle_egress_ip()
            return
        if self.path.startswith("/geo/status"):
            self._handle_geo_status()
            return
        if self.path.startswith("/audit/status"):
            self._handle_audit_status()
            return
        if self.path.startswith("/status"):
            self._handle_status()
            return
        if self.path not in ("/", "/ui.html", "/index.html"):
            self._send(404, "Not Found", "text/plain; charset=utf-8")
            return
        html = HTML_PATH.read_text(encoding="utf-8")
        self._send(200, html, "text/html; charset=utf-8")

    def do_POST(self):
        if self.path == "/notify":
            self._handle_notify()
            return
        if self.path == "/geo/run":
            self._handle_geo_run()
            return
        if self.path == "/audit/run":
            self._handle_audit_run()
            return
        if self.path != "/run":
            self._send(404, "Not Found", "text/plain; charset=utf-8")
            return
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="ignore")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            self._send(400, "Invalid JSON", "text/plain; charset=utf-8")
            return
        domains = payload.get("domains", [])
        if not isinstance(domains, list):
            self._send(400, "Invalid domains", "text/plain; charset=utf-8")
            return
        domains = extract_domains(domains)
        # Always bypass http->https-only redirects by default.
        ignore_https_redirect = True
        scan_subpages = bool(payload.get("scan_subpages", False))
        scan_wrapped = bool(payload.get("scan_wrapped", False))
        if scan_subpages:
            scan_wrapped = False
        job_id = start_job(
            domains,
            ignore_https_redirect=ignore_https_redirect,
            scan_subpages=scan_subpages,
            scan_wrapped=scan_wrapped,
        )
        body = json.dumps({"job_id": job_id})
        self._send(200, body, "application/json; charset=utf-8")

    def _handle_audit_run(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="ignore")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            self._send(400, "Invalid JSON", "text/plain; charset=utf-8")
            return
        urls = payload.get("urls", [])
        if not isinstance(urls, list):
            self._send(400, "Invalid urls", "text/plain; charset=utf-8")
            return
        urls = extract_urls(urls)
        if not urls:
            self._send(400, "Missing landing page URLs", "text/plain; charset=utf-8")
            return
        ok, error_message = audit_dependency_status()
        if not ok:
            self._send(400, error_message, "text/plain; charset=utf-8")
            return
        job_id = start_audit_job(urls)
        body = json.dumps({"job_id": job_id})
        self._send(200, body, "application/json; charset=utf-8")

    def _handle_geo_run(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="ignore")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            self._send(400, "Invalid JSON", "text/plain; charset=utf-8")
            return
        urls = payload.get("urls", [])
        profile_name = str(payload.get("profile", "")).strip()
        if not isinstance(urls, list):
            self._send(400, "Invalid urls", "text/plain; charset=utf-8")
            return
        urls = extract_urls(urls)
        if not urls:
            self._send(400, "Missing landing page URLs", "text/plain; charset=utf-8")
            return
        profiles = get_network_profiles()
        if profile_name not in profiles:
            self._send(400, "Invalid network profile", "text/plain; charset=utf-8")
            return
        ok, error_message = audit_dependency_status()
        if not ok:
            self._send(400, error_message, "text/plain; charset=utf-8")
            return
        job_id = start_audit_job(urls, kind="geo_audit", profile_name=profile_name)
        body = json.dumps({"job_id": job_id})
        self._send(200, body, "application/json; charset=utf-8")

    def _handle_notify(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="ignore")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            self._send(400, "Invalid JSON", "text/plain; charset=utf-8")
            return

        webhook_url = str(payload.get("webhook_url", "")).strip()
        message = str(payload.get("message", "")).strip()
        chat_payload = payload.get("chat_payload")
        if not webhook_url or (not message and not isinstance(chat_payload, dict)):
            self._send(400, "Missing webhook_url and content", "text/plain; charset=utf-8")
            return
        if not webhook_url.startswith("https://chat.googleapis.com/"):
            self._send(400, "Invalid Google Chat webhook URL", "text/plain; charset=utf-8")
            return

        outgoing = chat_payload if isinstance(chat_payload, dict) else {"text": message}
        try:
            req = Request(
                webhook_url,
                data=json.dumps(outgoing).encode("utf-8"),
                headers={"Content-Type": "application/json; charset=UTF-8"},
                method="POST",
            )
            with urlopen(req, timeout=20) as resp:
                code = getattr(resp, "status", 200)
            body = json.dumps({"ok": True, "status": code})
            self._send(200, body, "application/json; charset=utf-8")
        except URLError as exc:
            self._send(502, f"Notify failed: {exc}", "text/plain; charset=utf-8")

    def do_OPTIONS(self):
        self._send(204, "", "text/plain; charset=utf-8")

    def _handle_status(self):
        query = self.path.split("?", 1)
        if len(query) < 2:
            self._send(400, "Missing job id", "text/plain; charset=utf-8")
            return
        params = query[1].split("&")
        job_id = ""
        for param in params:
            if param.startswith("job="):
                job_id = param.split("=", 1)[1]
                break
        if not job_id:
            self._send(400, "Missing job id", "text/plain; charset=utf-8")
            return
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                self._send(404, "Job not found", "text/plain; charset=utf-8")
                return
            rows = [row for row in job["rows"] if row is not None]
            details = [detail for detail in job["details"] if detail is not None]
            payload = {
                "header": job["header"],
                "rows": rows,
                "details": details,
                "total": job["total"],
                "started": job.get("started", 0),
                "current_domain": job.get("current_domain", ""),
                "completed": job.get("completed", 0),
                "done": job["done"],
                "error": job["error"],
            }
        body = json.dumps(payload)
        self._send(200, body, "application/json; charset=utf-8")

    def _handle_audit_status(self):
        query = self.path.split("?", 1)
        if len(query) < 2:
            self._send(400, "Missing job id", "text/plain; charset=utf-8")
            return
        params = query[1].split("&")
        job_id = ""
        for param in params:
            if param.startswith("job="):
                job_id = param.split("=", 1)[1]
                break
        if not job_id:
            self._send(400, "Missing job id", "text/plain; charset=utf-8")
            return
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job or job.get("kind") != "audit":
                self._send(404, "Job not found", "text/plain; charset=utf-8")
                return
            items = [item for item in job["items"] if item is not None]
            payload = {
                "items": items,
                "total": job["total"],
                "started": job.get("started", 0),
                "current_url": job.get("current_url", ""),
                "completed": job.get("completed", 0),
                "done": job["done"],
                "error": job["error"],
            }
        body = json.dumps(payload)
        self._send(200, body, "application/json; charset=utf-8")

    def _handle_geo_status(self):
        query = self.path.split("?", 1)
        if len(query) < 2:
            self._send(400, "Missing job id", "text/plain; charset=utf-8")
            return
        params = query[1].split("&")
        job_id = ""
        for param in params:
            if param.startswith("job="):
                job_id = param.split("=", 1)[1]
                break
        if not job_id:
            self._send(400, "Missing job id", "text/plain; charset=utf-8")
            return
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job or job.get("kind") != "geo_audit":
                self._send(404, "Job not found", "text/plain; charset=utf-8")
                return
            items = [item for item in job["items"] if item is not None]
            payload = {
                "items": items,
                "total": job["total"],
                "started": job.get("started", 0),
                "current_url": job.get("current_url", ""),
                "completed": job.get("completed", 0),
                "done": job["done"],
                "error": job["error"],
                "profile": job.get("profile_name", ""),
                "network": job.get("network_info", {}),
            }
        body = json.dumps(payload)
        self._send(200, body, "application/json; charset=utf-8")

    def _handle_geo_profiles(self):
        profiles = list_network_profiles()
        body = json.dumps({"profiles": profiles})
        self._send(200, body, "application/json; charset=utf-8")

    def _handle_egress_ip(self):
        payload = resolve_egress_ip()
        status = 200 if payload.get("ip") else 502
        body = json.dumps(payload)
        self._send(status, body, "application/json; charset=utf-8")

    def _handle_artifact(self):
        raw_rel = self.path.split("/artifacts/", 1)[1]
        rel_path = Path(unquote(raw_rel))
        file_path = (ARTIFACT_ROOT / rel_path).resolve()
        artifact_root = ARTIFACT_ROOT.resolve()
        if artifact_root not in file_path.parents and file_path != artifact_root:
            self._send(403, "Forbidden", "text/plain; charset=utf-8")
            return
        if not file_path.is_file():
            self._send(404, "Not Found", "text/plain; charset=utf-8")
            return
        content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        data = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    port = int(os.environ.get("PORT", "8000"))
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"Open http://0.0.0.0:{port} in your browser.")
    server.serve_forever()


def extract_domains(raw_domains):
    found = []
    seen = set()
    domain_re = re.compile(r"(?:^|[^A-Za-z0-9.-])([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?:[^A-Za-z0-9.-]|$)")
    for item in raw_domains:
        if not item:
            continue
        text = str(item)
        for match in domain_re.finditer(text):
            domain = match.group(1)
            if domain not in seen:
                seen.add(domain)
                found.append(domain)
    return found


def extract_urls(raw_urls):
    found = []
    seen = set()
    for item in raw_urls:
        if item is None:
            continue
        text = str(item).strip()
        if not text:
            continue
        for piece in re.split(r"[\r\n]+", text):
            candidate = piece.strip()
            if not candidate:
                continue
            if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", candidate):
                candidate = f"https://{candidate}"
            if candidate not in seen:
                seen.add(candidate)
                found.append(candidate)
    return found


def resolve_egress_ip():
    last_error = ""
    for url, source in EGRESS_IP_SOURCES:
        try:
            req = Request(url, headers={"User-Agent": "DOMAIN-CHECKING/1.0"})
            with urlopen(req, timeout=10) as resp:
                raw = resp.read().decode("utf-8", errors="ignore").strip()
        except Exception as exc:
            last_error = str(exc)
            continue
        if source.endswith("_json"):
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                last_error = "invalid_json_response"
                continue
            ip = str(payload.get("ip", "")).strip()
        else:
            ip = raw.splitlines()[0].strip() if raw else ""
        if ip:
            return {"ip": ip, "source": source, "error": ""}
    return {"ip": "", "source": "", "error": last_error or "unavailable"}


def get_network_profiles():
    raw = os.environ.get("NETWORK_PROFILES", "").strip()
    profiles = {
        "direct": {
            "name": "direct",
            "label": "Direct",
            "country": "",
            "carrier": "",
            "asn": "",
            "proxy_url": "",
        }
    }
    if not raw:
        return profiles
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return profiles
    if not isinstance(payload, list):
        return profiles
    for item in payload:
        if not isinstance(item, dict):
            continue
        name = sanitize_slug(item.get("name") or item.get("label") or "")
        if not name or name in profiles:
            continue
        profiles[name] = {
            "name": name,
            "label": str(item.get("label") or name).strip(),
            "country": str(item.get("country") or "").strip(),
            "carrier": str(item.get("carrier") or "").strip(),
            "asn": str(item.get("asn") or "").strip(),
            "proxy_url": str(item.get("proxy_url") or "").strip(),
        }
    return profiles


def list_network_profiles():
    return [
        {
            "name": item["name"],
            "label": item["label"],
            "country": item["country"],
            "carrier": item["carrier"],
            "asn": item["asn"],
            "has_proxy": bool(item["proxy_url"]),
        }
        for item in get_network_profiles().values()
    ]


def build_proxy_handler(proxy_url):
    if not proxy_url:
        return None
    return ProxyHandler({"http": proxy_url, "https": proxy_url})


def build_playwright_proxy(proxy_url):
    if not proxy_url:
        return None
    parsed = urlparse(proxy_url)
    server = f"{parsed.scheme}://{parsed.hostname}:{parsed.port}" if parsed.hostname and parsed.port else proxy_url
    payload = {"server": server}
    if parsed.username:
        payload["username"] = parsed.username
    if parsed.password:
        payload["password"] = parsed.password
    return payload


def resolve_network_identity(profile):
    proxy_url = str((profile or {}).get("proxy_url") or "").strip()
    last_error = ""
    opener = None
    if proxy_url:
        opener = build_opener(build_proxy_handler(proxy_url))
    for url, source in IPINFO_SOURCES:
        try:
            req = Request(url, headers={"User-Agent": "DOMAIN-CHECKING/1.0"})
            if opener is not None:
                with opener.open(req, timeout=12) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore").strip()
            else:
                with urlopen(req, timeout=12) as resp:
                    raw = resp.read().decode("utf-8", errors="ignore").strip()
        except Exception as exc:
            last_error = str(exc)
            continue
        if source == "ipinfo":
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                last_error = "invalid_ipinfo"
                continue
            return {
                "ip": str(payload.get("ip") or "").strip(),
                "country": str(payload.get("country") or "").strip(),
                "org": str(payload.get("org") or "").strip(),
                "city": str(payload.get("city") or "").strip(),
                "source": source,
                "error": "",
            }
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            last_error = "invalid_json_response"
            continue
        ip = str(payload.get("ip", "")).strip()
        if ip:
            return {"ip": ip, "country": "", "org": "", "city": "", "source": source, "error": ""}
    return {"ip": "", "country": "", "org": "", "city": "", "source": "", "error": last_error or "unavailable"}


def start_job(domains, ignore_https_redirect=False, scan_subpages=False, scan_wrapped=False):
    job_id = uuid.uuid4().hex
    header = build_output_header(["domain"])
    with JOBS_LOCK:
        JOBS[job_id] = {
            "header": header,
            "rows": [None] * len(domains),
            "details": [None] * len(domains),
            "total": len(domains),
            "started": 0,
            "current_domain": "",
            "active_domains": [],
            "completed": 0,
            "done": False,
            "error": "",
            "ignore_https_redirect": ignore_https_redirect,
            "scan_subpages": scan_subpages,
            "scan_wrapped": scan_wrapped,
        }

    thread = threading.Thread(
        target=run_job,
        args=(job_id, domains, ignore_https_redirect, scan_subpages, scan_wrapped),
        daemon=True,
    )
    thread.start()
    return job_id


def start_audit_job(urls, kind="audit", profile_name="direct"):
    job_id = uuid.uuid4().hex
    profiles = get_network_profiles()
    profile = profiles.get(profile_name, profiles["direct"])
    with JOBS_LOCK:
        JOBS[job_id] = {
            "kind": kind,
            "items": [None] * len(urls),
            "total": len(urls),
            "started": 0,
            "current_url": "",
            "active_urls": [],
            "completed": 0,
            "done": False,
            "error": "",
            "profile_name": profile["name"],
            "network_info": {},
        }
    thread = threading.Thread(
        target=run_audit_job,
        args=(job_id, urls, profile),
        daemon=True,
    )
    thread.start()
    return job_id


def run_job(job_id, domains, ignore_https_redirect=False, scan_subpages=False, scan_wrapped=False):
    header = build_output_header(["domain"])
    try:
        tasks = [(idx, domain) for idx, domain in enumerate(domains) if domain]
        if tasks:
            worker_count = min(DOMAIN_WORKERS, len(tasks))
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if not job:
                    return
                job["started"] = 0
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                pending = list(tasks)
                future_map = {}
                active_domains = set()
                started_count = 0
                while pending or future_map:
                    with JOBS_LOCK:
                        job = JOBS.get(job_id)
                        if not job:
                            return
                        job["active_domains"] = sorted(active_domains)
                        job["started"] = started_count
                        job["current_domain"] = ", ".join(job["active_domains"][:3])

                    while pending and len(future_map) < worker_count:
                        idx, domain = pending.pop(0)
                        future = executor.submit(
                            process_domain,
                            domain,
                            header,
                            ignore_https_redirect=ignore_https_redirect,
                            scan_subpages=scan_subpages,
                            scan_wrapped=scan_wrapped,
                        )
                        future_map[future] = (idx, domain)
                        active_domains.add(domain)
                        started_count += 1
                        with JOBS_LOCK:
                            job = JOBS.get(job_id)
                            if not job:
                                return
                            job["active_domains"] = sorted(active_domains)
                            job["started"] = started_count
                            job["current_domain"] = ", ".join(job["active_domains"][:3])

                    if not future_map:
                        time.sleep(0.2)
                        continue

                    done_futures, _pending_futures = wait(
                        list(future_map.keys()),
                        timeout=0.25,
                        return_when=FIRST_COMPLETED,
                    )
                    if not done_futures:
                        continue

                    for future in done_futures:
                        idx, domain = future_map.pop(future)
                        row, detail = future.result()
                        active_domains.discard(domain)
                        with JOBS_LOCK:
                            job = JOBS.get(job_id)
                            if not job:
                                return
                            job["rows"][idx] = row
                            job["details"][idx] = detail
                            job["completed"] = int(job.get("completed", 0)) + 1
                            job["active_domains"] = sorted(active_domains)
                            job["current_domain"] = ", ".join(job["active_domains"][:3])
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if job:
                job["current_domain"] = ""
                job["active_domains"] = []
                job["done"] = True
    except Exception as exc:
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if job:
                job["done"] = True
                job["error"] = str(exc)


def audit_dependency_status():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
    except Exception:
        return False, "Page Audit requires Playwright. Install: pip install playwright && python3 -m playwright install chromium"
    return True, ""


def run_audit_job(job_id, urls, profile):
    try:
        network_info = resolve_network_identity(profile)
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                return
            job["network_info"] = network_info
        tasks = [(idx, url) for idx, url in enumerate(urls) if url]
        if tasks:
            worker_count = min(AUDIT_WORKERS, len(tasks))
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if not job:
                    return
                job["started"] = 0
            with ThreadPoolExecutor(max_workers=worker_count) as executor:
                pending = list(tasks)
                future_map = {}
                active_urls = set()
                started_count = 0
                while pending or future_map:
                    while pending and len(future_map) < worker_count:
                        idx, url = pending.pop(0)
                        future = executor.submit(audit_landing_page, url, job_id, idx, profile, network_info)
                        future_map[future] = (idx, url)
                        active_urls.add(url)
                        started_count += 1
                        with JOBS_LOCK:
                            job = JOBS.get(job_id)
                            if not job:
                                return
                            job["active_urls"] = sorted(active_urls)
                            job["started"] = started_count
                            job["current_url"] = ", ".join(job["active_urls"][:2])

                    if not future_map:
                        time.sleep(0.2)
                        continue

                    done_futures, _pending_futures = wait(
                        list(future_map.keys()),
                        timeout=0.25,
                        return_when=FIRST_COMPLETED,
                    )
                    if not done_futures:
                        continue

                    for future in done_futures:
                        idx, url = future_map.pop(future)
                        item = future.result()
                        active_urls.discard(url)
                        with JOBS_LOCK:
                            job = JOBS.get(job_id)
                            if not job:
                                return
                            job["items"][idx] = item
                            job["completed"] = int(job.get("completed", 0)) + 1
                            job["active_urls"] = sorted(active_urls)
                            job["current_url"] = ", ".join(job["active_urls"][:2])

        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if job:
                job["current_url"] = ""
                job["active_urls"] = []
                job["done"] = True
    except Exception as exc:
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if job:
                job["done"] = True
                job["error"] = str(exc)


def sanitize_slug(value):
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "")).strip("-._")
    return slug or "page"


def artifact_url(job_id, filename):
    return f"/artifacts/{job_id}/{filename}"


def audit_landing_page(url, job_id, row_idx, profile=None, network_info=None):
    from playwright.sync_api import Error as PlaywrightError
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright

    artifact_dir = ARTIFACT_ROOT / job_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    slug = sanitize_slug(Path(url).name or f"page-{row_idx + 1}")
    desktop_name = f"{row_idx + 1:03d}-{slug}-desktop.png"
    mobile_name = f"{row_idx + 1:03d}-{slug}-mobile.png"
    desktop_path = artifact_dir / desktop_name
    mobile_path = artifact_dir / mobile_name

    result = {
        "input_url": url,
        "final_url": "",
        "http_status": 0,
        "response_ms": 0,
        "load_ms": 0,
        "cta_total": 0,
        "clickable_cta": 0,
        "blocked_cta": 0,
        "broken_images": 0,
        "top_broken_images": 0,
        "request_failures": 0,
        "console_errors": 0,
        "blank_risk": False,
        "overlay_blocked_cta": 0,
        "overlay_risk": False,
        "hero_media_present": True,
        "desktop_shot": "",
        "mobile_shot": "",
        "notes": "",
        "error": "",
        "profile_name": str((profile or {}).get("name") or "direct"),
        "profile_label": str((profile or {}).get("label") or "Direct"),
        "expected_country": str((profile or {}).get("country") or ""),
        "expected_carrier": str((profile or {}).get("carrier") or ""),
        "expected_asn": str((profile or {}).get("asn") or ""),
        "observed_ip": str((network_info or {}).get("ip") or ""),
        "observed_country": str((network_info or {}).get("country") or ""),
        "observed_org": str((network_info or {}).get("org") or ""),
        "observed_city": str((network_info or {}).get("city") or ""),
    }

    with sync_playwright() as p:
        launch_args = {"headless": True}
        pw_proxy = build_playwright_proxy(str((profile or {}).get("proxy_url") or "").strip())
        if pw_proxy:
            launch_args["proxy"] = pw_proxy
        browser = p.chromium.launch(**launch_args)
        try:
            desktop_meta = audit_viewport(
                browser,
                url,
                {"width": 1440, "height": 1600},
                desktop_path,
                is_mobile=False,
            )
            result.update({
                "final_url": desktop_meta["final_url"],
                "http_status": desktop_meta["http_status"],
                "response_ms": desktop_meta["response_ms"],
                "load_ms": desktop_meta["load_ms"],
                "cta_total": desktop_meta["cta_total"],
                "clickable_cta": desktop_meta["clickable_cta"],
                "blocked_cta": desktop_meta["blocked_cta"],
                "broken_images": desktop_meta["broken_images"],
                "top_broken_images": desktop_meta["top_broken_images"],
                "request_failures": desktop_meta["request_failures"],
                "console_errors": desktop_meta["console_errors"],
                "blank_risk": desktop_meta["blank_risk"],
                "overlay_blocked_cta": desktop_meta["overlay_blocked_cta"],
                "overlay_risk": desktop_meta["overlay_risk"],
                "hero_media_present": desktop_meta["hero_media_present"],
                "desktop_shot": artifact_url(job_id, desktop_name),
            })

            mobile_meta = audit_viewport(
                browser,
                url,
                {"width": 430, "height": 1200},
                mobile_path,
                is_mobile=True,
            )
            result["mobile_shot"] = artifact_url(job_id, mobile_name)
            if mobile_meta["broken_images"] > result["broken_images"]:
                result["broken_images"] = mobile_meta["broken_images"]
            if mobile_meta["top_broken_images"] > result["top_broken_images"]:
                result["top_broken_images"] = mobile_meta["top_broken_images"]
            if mobile_meta["console_errors"] > result["console_errors"]:
                result["console_errors"] = mobile_meta["console_errors"]
            if mobile_meta["request_failures"] > result["request_failures"]:
                result["request_failures"] = mobile_meta["request_failures"]
            if mobile_meta["blank_risk"]:
                result["blank_risk"] = True
            if mobile_meta["overlay_blocked_cta"] > result["overlay_blocked_cta"]:
                result["overlay_blocked_cta"] = mobile_meta["overlay_blocked_cta"]
            if mobile_meta["overlay_risk"]:
                result["overlay_risk"] = True
            if not mobile_meta["hero_media_present"]:
                result["hero_media_present"] = False
        except PlaywrightTimeoutError as exc:
            result["error"] = f"timeout: {exc}"
        except PlaywrightError as exc:
            result["error"] = str(exc)
        finally:
            browser.close()

    notes = []
    if result["error"]:
        notes.append("audit_failed")
    if result["load_ms"] >= 5000:
        notes.append("slow_page")
    if result["blocked_cta"] > 0:
        notes.append("cta_blocked")
    if result["overlay_risk"]:
        notes.append("overlay_blocking")
    if result["cta_total"] == 0:
        notes.append("no_visible_cta")
    if result["broken_images"] > 0:
        notes.append("broken_media")
    if result["top_broken_images"] > 0:
        notes.append("hero_media_broken")
    if not result["hero_media_present"]:
        notes.append("hero_media_missing")
    if result["blank_risk"]:
        notes.append("blank_risk")
    if result["console_errors"] > 0:
        notes.append("console_error")
    if result["expected_country"] and result["observed_country"] and result["expected_country"].lower() != result["observed_country"].lower():
        notes.append("country_mismatch")
    if result["expected_asn"] and result["observed_org"] and result["expected_asn"].lower() not in result["observed_org"].lower():
        notes.append("asn_mismatch")
    if result["expected_carrier"] and result["observed_org"] and result["expected_carrier"].lower() not in result["observed_org"].lower():
        notes.append("carrier_mismatch")
    result["notes"] = ", ".join(notes)
    return result


def audit_viewport(browser, url, viewport, screenshot_path, is_mobile=False):
    context = browser.new_context(
        viewport=viewport,
        is_mobile=is_mobile,
        user_agent=(
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 "
            "(KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
            if is_mobile
            else "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
        ),
    )
    page = context.new_page()
    console_errors = []
    request_failures = []
    page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)
    page.on("requestfailed", lambda req: request_failures.append(req.url))
    started_at = time.perf_counter()
    response = page.goto(url, wait_until="load", timeout=30000)
    response_ms = int((time.perf_counter() - started_at) * 1000)
    try:
        page.wait_for_load_state("networkidle", timeout=4000)
    except Exception:
        pass
    nav_metrics = page.evaluate(
        """() => {
          const nav = performance.getEntriesByType('navigation')[0];
          if (!nav) return { loadMs: 0 };
          return {
            loadMs: Math.round(nav.loadEventEnd || nav.duration || 0),
          };
        }"""
    )
    page_metrics = page.evaluate(
        """() => {
          const visible = (el) => {
            const style = window.getComputedStyle(el);
            const rect = el.getBoundingClientRect();
            return (
              style &&
              style.display !== 'none' &&
              style.visibility !== 'hidden' &&
              rect.width > 18 &&
              rect.height > 18
            );
          };
          const clickable = (el) => {
            if (!visible(el)) return false;
            if (el.disabled) return false;
            const style = window.getComputedStyle(el);
            if (style.pointerEvents === 'none') return false;
            const rect = el.getBoundingClientRect();
            const cx = Math.min(window.innerWidth - 1, Math.max(1, rect.left + Math.min(rect.width / 2, rect.width - 2)));
            const cy = Math.min(window.innerHeight - 1, Math.max(1, rect.top + Math.min(rect.height / 2, rect.height - 2)));
            const top = document.elementFromPoint(cx, cy);
            return !top || top === el || el.contains(top) || top.contains(el);
          };
          const blockerFor = (el) => {
            if (!visible(el)) return null;
            const rect = el.getBoundingClientRect();
            const cx = Math.min(window.innerWidth - 1, Math.max(1, rect.left + Math.min(rect.width / 2, rect.width - 2)));
            const cy = Math.min(window.innerHeight - 1, Math.max(1, rect.top + Math.min(rect.height / 2, rect.height - 2)));
            const top = document.elementFromPoint(cx, cy);
            if (!top || top === el || el.contains(top) || top.contains(el)) return null;
            return top;
          };
          const ctas = Array.from(document.querySelectorAll('a[href], button, input[type="submit"], [role="button"]'))
            .filter((el) => visible(el))
            .slice(0, 50);
          const clickableCount = ctas.filter((el) => clickable(el)).length;
          const overlayBlocked = ctas.filter((el) => {
            const blocker = blockerFor(el);
            if (!blocker) return false;
            const blockerStyle = window.getComputedStyle(blocker);
            return blockerStyle.position === 'fixed' || blockerStyle.position === 'sticky';
          }).length;
          const brokenImages = Array.from(document.images).filter((img) => img.complete && img.naturalWidth === 0).length;
          const topBrokenImages = Array.from(document.images).filter((img) => {
            const rect = img.getBoundingClientRect();
            return img.complete && img.naturalWidth === 0 && rect.top < window.innerHeight;
          }).length;
          const heroCandidates = Array.from(document.querySelectorAll('[class*="hero"], [id*="hero"], [class*="banner"], [id*="banner"]'))
            .filter((el) => visible(el) && el.getBoundingClientRect().top < window.innerHeight * 1.2)
            .slice(0, 12);
          const heroMediaPresent = heroCandidates.length === 0 ? true : heroCandidates.some((el) => {
            const style = window.getComputedStyle(el);
            if (style.backgroundImage && style.backgroundImage !== 'none') return true;
            const media = el.querySelector('img, video, canvas, svg, picture img');
            return Boolean(media && visible(media));
          });
          const bodyText = (document.body && document.body.innerText ? document.body.innerText.trim() : '');
          return {
            ctaTotal: ctas.length,
            clickableCta: clickableCount,
            brokenImages,
            topBrokenImages,
            overlayBlocked,
            overlayRisk: overlayBlocked > 0,
            heroMediaPresent,
            blankRisk: bodyText.length < 40 && brokenImages === 0,
          };
        }"""
    )
    page.screenshot(path=str(screenshot_path), full_page=True)
    meta = {
        "final_url": page.url,
        "http_status": int(getattr(response, "status", 0) or 0),
        "response_ms": response_ms,
        "load_ms": int(nav_metrics.get("loadMs") or response_ms),
        "cta_total": int(page_metrics.get("ctaTotal") or 0),
        "clickable_cta": int(page_metrics.get("clickableCta") or 0),
        "blocked_cta": max(0, int(page_metrics.get("ctaTotal") or 0) - int(page_metrics.get("clickableCta") or 0)),
        "broken_images": int(page_metrics.get("brokenImages") or 0),
        "top_broken_images": int(page_metrics.get("topBrokenImages") or 0),
        "request_failures": len(request_failures),
        "console_errors": len(console_errors),
        "blank_risk": bool(page_metrics.get("blankRisk")),
        "overlay_blocked_cta": int(page_metrics.get("overlayBlocked") or 0),
        "overlay_risk": bool(page_metrics.get("overlayRisk")),
        "hero_media_present": bool(page_metrics.get("heroMediaPresent", True)),
    }
    context.close()
    return meta


if __name__ == "__main__":
    main()
