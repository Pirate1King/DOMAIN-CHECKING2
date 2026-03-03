import json
import os
import re
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from check_domains import build_output_header, process_domain


HTML_PATH = Path(__file__).with_name("ui.html")
JOBS = {}
JOBS_LOCK = threading.Lock()


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
        if self.path.startswith("/status"):
            self._handle_status()
            return
        if self.path not in ("/", "/ui.html"):
            self._send(404, "Not Found", "text/plain; charset=utf-8")
            return
        html = HTML_PATH.read_text(encoding="utf-8")
        self._send(200, html, "text/html; charset=utf-8")

    def do_POST(self):
        if self.path == "/notify":
            self._handle_notify()
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
        ignore_https_redirect = bool(payload.get("ignore_https_redirect"))
        job_id = start_job(domains, ignore_https_redirect=ignore_https_redirect)
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
        if not webhook_url or not message:
            self._send(400, "Missing webhook_url or message", "text/plain; charset=utf-8")
            return
        if not webhook_url.startswith("https://chat.googleapis.com/"):
            self._send(400, "Invalid Google Chat webhook URL", "text/plain; charset=utf-8")
            return

        try:
            req = Request(
                webhook_url,
                data=json.dumps({"text": message}).encode("utf-8"),
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
            payload = {
                "header": job["header"],
                "rows": job["rows"],
                "details": job["details"],
                "total": job["total"],
                "done": job["done"],
                "error": job["error"],
            }
        body = json.dumps(payload)
        self._send(200, body, "application/json; charset=utf-8")


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


def start_job(domains, ignore_https_redirect=False):
    job_id = uuid.uuid4().hex
    header = build_output_header(["domain"])
    with JOBS_LOCK:
        JOBS[job_id] = {
            "header": header,
            "rows": [],
            "details": [],
            "total": len(domains),
            "done": False,
            "error": "",
            "ignore_https_redirect": ignore_https_redirect,
        }

    thread = threading.Thread(
        target=run_job, args=(job_id, domains, ignore_https_redirect), daemon=True
    )
    thread.start()
    return job_id


def run_job(job_id, domains, ignore_https_redirect=False):
    header = build_output_header(["domain"])
    try:
        for domain in domains:
            if not domain:
                continue
            row, detail = process_domain(
                domain, header, ignore_https_redirect=ignore_https_redirect
            )
            with JOBS_LOCK:
                job = JOBS.get(job_id)
                if not job:
                    return
                job["rows"].append(row)
                job["details"].append(detail)
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if job:
                job["done"] = True
    except Exception as exc:
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if job:
                job["done"] = True
                job["error"] = str(exc)


if __name__ == "__main__":
    main()
