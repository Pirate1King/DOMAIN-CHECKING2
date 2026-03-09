import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
import html
import json
import re
import socket
import subprocess
import sys
import tempfile
import time
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlparse, urlsplit, urlunsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, ProxyHandler, urlopen


TRACKING_TOKEN = "a=mswl"
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)
BROWSER_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Upgrade-Insecure-Requests": "1",
}
TIMEOUT_SECS = 15
MAX_REDIRECTS = 5
ANALYZE_WORKERS = 8
MAX_WRAPPER_PROBES = 18
MAX_SUBPAGE_PROBES = 24
WRAPPER_TIMEOUT_SECS = 3
WRAPPER_WORKERS = 8
SUBPAGE_WORKERS = 6
WRAPPER_USE_LOCATION_FALLBACK = True
PAGE_RETRY_DELAY_SECS = 0.6
DOH_CACHE = {}
DOH_ENDPOINTS = (
    "https://dns.google/resolve?name={name}&type=A",
    "https://cloudflare-dns.com/dns-query?name={name}&type=A",
)
WRAPPED_URL_KEYS = {
    "url",
    "u",
    "target",
    "redirect",
    "redirect_url",
    "redirect_uri",
    "next",
    "to",
    "dest",
    "destination",
    "out",
    "link",
    "href",
    "goto",
    "jump",
    "r",
    "rd",
    "ref",
}
URLISH_ATTR_KEYS = {
    "href",
    "src",
    "srcset",
    "data-src",
    "data-srcset",
    "data-href",
    "data-url",
    "data-link",
    "data-target",
    "action",
    "formaction",
    "poster",
    "content",
}
EVENT_ATTR_KEYS = {
    "onclick",
    "onmousedown",
    "onmouseup",
    "ontouchstart",
    "ontouchend",
}
URL_REGEX = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
QUOTED_RELATIVE_URL_REGEX = re.compile(r"""['"]((?:https?:)?//[^'"\s<>]+|/[^'"\s<>]+)['"]""", re.IGNORECASE)
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
MOBILE_HINT_RE = re.compile(
    r"(^|[^a-z0-9])(mobile|mobi|sp|sm-only|only-mobile|on-mobile|for-mobile|m-cta|cta-m|show-for-medium)($|[^a-z0-9])",
    re.IGNORECASE,
)
DESKTOP_HINT_RE = re.compile(
    r"(^|[^a-z0-9])(desktop|pc|only-desktop|on-desktop|for-desktop|d-cta|cta-d|lg-only|xl-only|hide-for-medium)($|[^a-z0-9])",
    re.IGNORECASE,
)
STATIC_EXTENSIONS = (
    ".css",
    ".js",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".rar",
    ".7z",
    ".mp4",
    ".mp3",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
)


class HrefCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self._current = None
        self._stack = []
        self._node_seq = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs_dict = {key.lower(): value for key, value in attrs if key}
        self._stack.append(
            {
                "tag": tag,
                "id": attrs_dict.get("id", ""),
                "class": attrs_dict.get("class", ""),
            }
        )
        if tag == "a":
            href = attrs_dict.get("href") or ""
            self._current = {
                "tag": "a",
                "href": href,
                "text_parts": [],
                "attrs": attrs_dict,
                "img_alts": [],
                "img_srcs": [],
                "parent": self._find_parent_context(),
                "device_context": self._find_device_context(),
            }
        elif tag == "img" and self._current is not None:
            alt = attrs_dict.get("alt")
            src = attrs_dict.get("src")
            if alt:
                self._current["img_alts"].append(alt)
            if src:
                self._current["img_srcs"].append(src)
        else:
            self._capture_non_anchor_candidate(tag, attrs_dict)

    def handle_endtag(self, tag):
        if self._stack:
            self._stack.pop()
        if tag.lower() != "a" or self._current is None:
            return
        text = " ".join(part.strip() for part in self._current["text_parts"] if part.strip())
        attrs = self._current["attrs"]
        context = []
        if text:
            context.append(f"text={text}")
        if attrs.get("aria-label"):
            context.append(f"aria-label={attrs.get('aria-label')}")
        if attrs.get("title"):
            context.append(f"title={attrs.get('title')}")
        if attrs.get("id"):
            context.append(f"id={attrs.get('id')}")
        if attrs.get("class"):
            context.append(f"class={attrs.get('class')}")
        if self._current["img_alts"]:
            context.append(f"img_alt={','.join(self._current['img_alts'])}")
        if self._current["img_srcs"]:
            context.append(f"img_src={','.join(self._current['img_srcs'][:2])}")
        parent = self._current.get("parent")
        if parent:
            context.append(f"parent={parent}")
        self._node_seq += 1
        self.links.append(
            {
                "node_id": self._node_seq,
                "tag": self._current.get("tag", "a"),
                "href": self._current["href"],
                "attrs": dict(attrs),
                "context": "; ".join(context) if context else "no_text",
                "device_context": self._current.get("device_context", ""),
            }
        )
        self._current = None

    def handle_data(self, data):
        if self._current is not None and data:
            self._current["text_parts"].append(data)

    def _find_parent_context(self):
        for item in reversed(self._stack[:-1]):
            if item.get("id") or item.get("class"):
                return self._format_stack_item(item)
        return ""

    def _find_device_context(self, limit=6):
        items = []
        for item in self._stack[:-1]:
            if not (item.get("id") or item.get("class")):
                continue
            rendered = self._format_stack_item(item)
            if rendered:
                items.append(rendered)
        if not items:
            return ""
        return " > ".join(items[-limit:])

    def _format_stack_item(self, item):
        tag = item.get("tag", "")
        ident = item.get("id")
        cls = item.get("class")
        parts = [tag] if tag else []
        if ident:
            parts.append(f"#{ident}")
        if cls:
            cls_clean = ".".join(cls.split())
            parts.append(f".{cls_clean}")
        return "".join(parts)

    def _capture_non_anchor_candidate(self, tag, attrs_dict):
        if not attrs_dict:
            return
        has_relevant_attr = False
        for key, value in attrs_dict.items():
            if not value:
                continue
            key_low = str(key).lower()
            low = str(value).lower()
            if "http" in low or TRACKING_TOKEN in low:
                has_relevant_attr = True
                break
            if key_low.startswith("data-") or key_low in EVENT_ATTR_KEYS:
                has_relevant_attr = True
                break
            if key_low in URLISH_ATTR_KEYS:
                has_relevant_attr = True
                break
            if key_low == "style" and "url(" in low:
                has_relevant_attr = True
                break
        if not has_relevant_attr:
            return

        context_parts = [f"tag={tag}"]
        if attrs_dict.get("id"):
            context_parts.append(f"id={attrs_dict.get('id')}")
        if attrs_dict.get("class"):
            context_parts.append(f"class={attrs_dict.get('class')}")
        parent = self._find_parent_context()
        if parent:
            context_parts.append(f"parent={parent}")
        self._node_seq += 1
        self.links.append(
            {
                "node_id": self._node_seq,
                "tag": tag,
                "href": "",
                "attrs": dict(attrs_dict),
                "context": "; ".join(context_parts),
                "device_context": self._find_device_context(),
            }
        )


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _proxy_handler(proxy_url=""):
    proxy = str(proxy_url or "").strip()
    if not proxy:
        return ProxyHandler({})
    return ProxyHandler({"http": proxy, "https": proxy})


def _open_url(url, allow_redirects=True, timeout_secs=TIMEOUT_SECS, proxy_url=""):
    handlers = [_proxy_handler(proxy_url)]
    if not allow_redirects:
        handlers.append(NoRedirect())
    opener = build_opener(*handlers)
    req = Request(url, headers=BROWSER_HEADERS)
    return opener.open(req, timeout=timeout_secs)


def is_dns_error(exc):
    text = str(exc).lower()
    hints = (
        "nodename nor servname provided",
        "name or service not known",
        "temporary failure in name resolution",
        "getaddrinfo failed",
        "could not resolve host",
    )
    return any(hint in text for hint in hints)


def resolve_hostname_doh(hostname):
    host = str(hostname or "").strip().lower().strip(".")
    if not host:
        return []
    cached = DOH_CACHE.get(host)
    if cached is not None:
        return list(cached)

    resolved = []
    for endpoint in DOH_ENDPOINTS:
        try:
            req = Request(
                endpoint.format(name=quote(host)),
                headers={
                    "User-Agent": USER_AGENT,
                    "Accept": "application/dns-json, application/json",
                },
            )
            with urlopen(req, timeout=5) as resp:
                payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
        except Exception:
            continue
        for answer in payload.get("Answer", []) or []:
            if int(answer.get("type") or 0) != 1:
                continue
            value = str(answer.get("data") or "").strip()
            if value and value not in resolved:
                resolved.append(value)
        if resolved:
            break

    DOH_CACHE[host] = tuple(resolved)
    return list(resolved)


def parse_location_from_headers(header_text):
    blocks = [block for block in str(header_text or "").split("\r\n\r\n") if block.strip()]
    if not blocks:
        blocks = [block for block in str(header_text or "").split("\n\n") if block.strip()]
    for line in reversed(blocks[-1].splitlines() if blocks else []):
        if line.lower().startswith("location:"):
            return line.split(":", 1)[1].strip()
    return ""


def fetch_url_via_curl(url, allow_redirects=True, timeout_secs=TIMEOUT_SECS, resolved_ip=None, proxy_url=""):
    parsed = urlparse(url)
    host = (parsed.hostname or "").strip()
    if not host:
        return None
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    resolve_targets = [resolved_ip] if resolved_ip else [None]
    last_error = ""
    for ip in resolve_targets:
        with tempfile.NamedTemporaryFile() as header_file, tempfile.NamedTemporaryFile() as body_file:
            cmd = [
                "curl",
                "-sS",
                "--http1.1",
                "--max-time",
                str(int(timeout_secs)),
                "--connect-timeout",
                str(max(2, min(int(timeout_secs), 5))),
                "-A",
                USER_AGENT,
                "-H",
                f"Accept: {BROWSER_HEADERS['Accept']}",
                "-H",
                f"Accept-Language: {BROWSER_HEADERS['Accept-Language']}",
                "-H",
                "Cache-Control: no-cache",
                "-H",
                "Pragma: no-cache",
                "-H",
                "Upgrade-Insecure-Requests: 1",
                "-D",
                header_file.name,
                "-o",
                body_file.name,
                "-w",
                "%{http_code}\n%{url_effective}",
            ]
            proxy = str(proxy_url or "").strip()
            if proxy:
                cmd.extend(["-x", proxy])
            if ip:
                cmd.extend(["--resolve", f"{host}:{port}:{ip}"])
            if allow_redirects:
                cmd.append("-L")
            cmd.append(url)

            try:
                proc = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=max(timeout_secs + 2, 5),
                    check=False,
                )
            except Exception as exc:
                last_error = str(exc)
                continue

            if proc.returncode != 0:
                last_error = (proc.stderr or proc.stdout or "").strip() or f"curl_exit:{proc.returncode}"
                continue

            header_text = header_file.read().decode("utf-8", errors="ignore")
            body = body_file.read()
            lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
            try:
                status = int(lines[-2]) if len(lines) >= 2 else 0
            except ValueError:
                status = 0
            final_url = lines[-1] if lines else url
            return {
                "status": status,
                "final_url": final_url,
                "body": body,
                "error": "",
                "location": parse_location_from_headers(header_text),
            }

    if last_error:
        return {
            "status": 0,
            "final_url": url,
            "body": b"",
            "error": last_error,
            "location": "",
        }
    return None


def fetch_url_via_curl_resolve(url, allow_redirects=True, timeout_secs=TIMEOUT_SECS, proxy_url=""):
    parsed = urlparse(url)
    host = (parsed.hostname or "").strip()
    if not host:
        return None
    resolved_ips = resolve_hostname_doh(host)
    if not resolved_ips:
        return None
    last_failure = None
    for ip in resolved_ips:
        result = fetch_url_via_curl(
            url,
            allow_redirects=allow_redirects,
            timeout_secs=timeout_secs,
            resolved_ip=ip,
            proxy_url=proxy_url,
        )
        if result is None:
            continue
        if result.get("status"):
            return result
        last_failure = result
    return last_failure


def fetch_url(url, allow_redirects=True, timeout_secs=TIMEOUT_SECS, proxy_url=""):
    try:
        resp = _open_url(url, allow_redirects=allow_redirects, timeout_secs=timeout_secs, proxy_url=proxy_url)
        status = resp.getcode()
        final_url = resp.geturl()
        body = resp.read()
        return {
            "status": status,
            "final_url": final_url,
            "body": body,
            "error": "",
            "location": resp.headers.get("Location", ""),
        }
    except HTTPError as exc:
        try:
            body = exc.read()
        except Exception:
            body = b""
        response = {
            "status": exc.code,
            "final_url": exc.geturl() or url,
            "body": body,
            "error": "",
            "location": exc.headers.get("Location", ""),
        }
        if exc.code in (403, 429):
            fallback = fetch_url_via_curl(
                url,
                allow_redirects=allow_redirects,
                timeout_secs=timeout_secs,
                proxy_url=proxy_url,
            )
            if fallback is not None and int(fallback.get("status") or 0) > int(response["status"] or 0):
                return fallback
        return response
    except (URLError, socket.timeout, ValueError) as exc:
        if is_dns_error(exc):
            fallback = fetch_url_via_curl_resolve(
                url,
                allow_redirects=allow_redirects,
                timeout_secs=timeout_secs,
                proxy_url=proxy_url,
            )
            if fallback is not None:
                return fallback
        return {
            "status": 0,
            "final_url": url,
            "body": b"",
            "error": str(exc),
            "location": "",
        }


def pick_homepage(domain):
    if domain.startswith("http://") or domain.startswith("https://"):
        return [domain]
    return [f"https://{domain}", f"http://{domain}"]


def fetch_homepage(domain, proxy_url=""):
    candidates = []
    last_error = ""
    for candidate in pick_homepage(domain):
        result = fetch_url(candidate, allow_redirects=True, proxy_url=proxy_url)
        result["page_url"] = candidate
        candidates.append(result)
        if result.get("error"):
            last_error = result["error"]
    best = choose_best_page_result(candidates)
    if best:
        return best
    return {
        "status": 0,
        "final_url": "",
        "body": b"",
        "error": last_error or "unreachable",
        "location": "",
        "page_url": "",
    }


def page_status_score(status):
    if status == 200:
        return 700
    if 200 <= status < 300:
        return 600 - abs(status - 200)
    if 300 <= status < 400:
        return 500 - status
    if status in (401, 403):
        return 250
    if 400 <= status < 500:
        return 200
    if 500 <= status < 600:
        return 100
    return 0


def choose_best_page_result(results):
    best = None
    best_score = -1
    for item in results or []:
        score = page_status_score(int(item.get("status") or 0))
        if score > best_score:
            best = item
            best_score = score
    return best


def should_retry_page_status(status):
    if status == 0:
        return True
    if status in (403, 404):
        return True
    if 500 <= status < 600:
        return True
    return False


def fetch_homepage_with_retry(domain, proxy_url=""):
    first = fetch_homepage(domain, proxy_url=proxy_url)
    if not should_retry_page_status(first["status"]):
        return first
    # Retry once for unstable/borderline status to reduce false alarms.
    time.sleep(PAGE_RETRY_DELAY_SECS)
    second = fetch_homepage(domain, proxy_url=proxy_url)
    best = choose_best_page_result([first, second])
    return best or second


def extract_direct_tracking_links_from_html(html_bytes, base_url, source_type="direct", subpage_from=""):
    try:
        html_text = html_bytes.decode("utf-8", errors="ignore")
    except Exception:
        html_text = ""
    parser = HrefCollector()
    parser.feed(html_text)
    links = []
    seen = set()
    for item in parser.links:
        href = item.get("href", "") or ""
        node_id = int(item.get("node_id") or 0)
        attrs = item.get("attrs", {}) or {}
        candidates = [href]
        candidates.extend(str(v) for v in attrs.values() if v)
        for raw in candidates:
            for found in extract_tracking_from_raw(raw, base_url):
                key = (
                    found.lower(),
                    node_id,
                    (item.get("context", "") or "").strip().lower(),
                    (href or "").strip().lower(),
                )
                if key in seen:
                    continue
                seen.add(key)
                links.append(
                    {
                        "url": found,
                        "node_id": node_id,
                        "context": item.get("context", "no_text"),
                        "device_context": item.get("device_context", ""),
                        "href": href,
                        "source_url": normalize_candidate_url(href, base_url),
                        "wrapped_from": "",
                        "subpage_from": subpage_from,
                        "source_type": source_type,
                    }
                )
    return links


def extract_tracking_links(html_bytes, base_url, scan_subpages=False, scan_wrapped=True, proxy_url=""):
    links = extract_direct_tracking_links_from_html(
        html_bytes,
        base_url,
        source_type="direct",
        subpage_from="",
    )
    seen = {tracking_identity_key(item) for item in links}
    try:
        html_text = html_bytes.decode("utf-8", errors="ignore")
    except Exception:
        html_text = ""
    if scan_subpages:
        subpage_candidates = build_probe_candidates(html_text, base_url, mode="subpage", proxy_url=proxy_url)
        for wrapped_item in probe_candidates(subpage_candidates, mode="subpage"):
            found = wrapped_item.get("url", "")
            via_type = wrapped_item.get("via_type", "")
            subpage_from = wrapped_item.get("subpage_from", "")
            context_for_entry = wrapped_item.get("context", "no_text")
            href_for_entry = wrapped_item.get("href", "")
            source_url_for_entry = wrapped_item.get("source_url", "")
            device_context_for_entry = wrapped_item.get("device_context", "")
            node_for_entry = int(wrapped_item.get("node_id") or 0)
            key = tracking_identity_key(
                {
                    "url": found,
                    "node_id": node_for_entry,
                    "context": context_for_entry,
                    "device_context": device_context_for_entry,
                    "href": href_for_entry,
                    "source_url": source_url_for_entry,
                    "wrapped_from": "",
                    "subpage_from": subpage_from,
                    "source_type": via_type or "subpage_direct",
                }
            )
            if key in seen:
                continue
            seen.add(key)
            links.append(
                {
                    "url": found,
                    "node_id": node_for_entry,
                    "context": f"{context_for_entry}; subpage_from={subpage_from or source_url_for_entry}",
                    "device_context": device_context_for_entry,
                    "href": href_for_entry,
                    "source_url": source_url_for_entry,
                    "wrapped_from": "",
                    "subpage_from": subpage_from,
                    "source_type": via_type or "subpage_direct",
                }
            )
    elif scan_wrapped:
        wrapper_candidates = build_probe_candidates(html_text, base_url, mode="wrapped", proxy_url=proxy_url)
        for wrapped_item in probe_candidates(wrapper_candidates, mode="wrapped"):
            found = wrapped_item.get("url", "")
            via_type = wrapped_item.get("via_type", "")
            wrapped_from = wrapped_item.get("wrapped_from", "")
            context_for_entry = wrapped_item.get("context", "no_text")
            href_for_entry = wrapped_item.get("href", "")
            source_url_for_entry = wrapped_item.get("source_url", "")
            device_context_for_entry = wrapped_item.get("device_context", "")
            node_for_entry = int(wrapped_item.get("node_id") or 0)
            key = tracking_identity_key(
                {
                    "url": found,
                    "node_id": node_for_entry,
                    "context": context_for_entry,
                    "device_context": device_context_for_entry,
                    "href": href_for_entry,
                    "source_url": source_url_for_entry,
                    "wrapped_from": wrapped_from,
                    "subpage_from": "",
                    "source_type": via_type or "wrapped_redirect",
                }
            )
            if key in seen:
                continue
            seen.add(key)
            links.append(
                {
                    "url": found,
                    "node_id": node_for_entry,
                    "context": f"{context_for_entry}; wrapped_from={wrapped_from}",
                    "device_context": device_context_for_entry,
                    "href": href_for_entry,
                    "source_url": source_url_for_entry,
                    "wrapped_from": wrapped_from,
                    "subpage_from": "",
                    "source_type": via_type or "wrapped_redirect",
                }
            )
    return links


def dedupe_tracking_links(links):
    out = []
    seen = set()
    for item in links or []:
        key = tracking_identity_key(item)
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def tracking_identity_key(item):
    return (
        str(item.get("url") or "").strip().lower(),
        int(item.get("node_id") or 0),
        str(item.get("context") or "").strip().lower(),
        str(item.get("device_context") or "").strip().lower(),
        str(item.get("href") or "").strip().lower(),
        str(item.get("source_url") or "").strip().lower(),
        str(item.get("wrapped_from") or "").strip().lower(),
        str(item.get("subpage_from") or "").strip().lower(),
        str(item.get("source_type") or "").strip().lower(),
    )


def extract_url_candidates(raw, base_url):
    text = html.unescape(str(raw or "")).strip()
    if not text:
        return []
    candidates = [text]
    candidates.extend(URL_REGEX.findall(text))
    candidates.extend(extract_quoted_url_candidates(text))
    out = []
    seen = set()
    for val in candidates:
        normalized = normalize_candidate_url(val, base_url)
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
    return out


def extract_quoted_url_candidates(text):
    out = []
    seen = set()
    for found in QUOTED_RELATIVE_URL_REGEX.findall(str(text or "")):
        value = str(found or "").strip()
        if not value:
            continue
        low = value.lower()
        if low.startswith(("javascript:", "mailto:", "tel:", "#")):
            continue
        if value in seen:
            continue
        seen.add(value)
        out.append(value)
    return out


def is_likely_wrapper_candidate(candidate_url, item, base_url):
    url = (candidate_url or "").lower()
    context = (item.get("context") or "").lower()
    href = (item.get("href") or "").lower()
    if TRACKING_TOKEN in url:
        return False
    parsed = urlparse(candidate_url)
    if parsed.scheme not in ("http", "https"):
        return False
    if parsed.fragment:
        return False
    path = (parsed.path or "").lower()
    if path and any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
        return False

    hints = (
        "dang-ky",
        "dangky",
        "register",
        "signup",
        "sign-up",
        "login",
        "banner",
        "cta",
        "button",
        "redirect",
        "out",
        "goto",
        "jump",
        "click",
        "ref",
    )
    for token in hints:
        if token in url or token in context or token in href:
            return True

    if is_same_host(base_url, candidate_url):
        # Keep same-host candidates with path/query for wrapped-link coverage.
        path = (parsed.path or "").strip()
        if path and path != "/":
            return True
        if parsed.query:
            return True

    if any(key + "=" in url for key in WRAPPED_URL_KEYS):
        return True
    if "%2f%2f" in url or "http%3a" in url or "https%3a" in url:
        return True
    return False


def wrapper_candidate_score(candidate_url, item, base_url):
    score = 0
    url = (candidate_url or "").lower()
    context = (item.get("context") or "").lower()
    href = (item.get("href") or "").lower()

    if is_same_host(base_url, candidate_url):
        score += 10

    strong_tokens = (
        "dang-ky",
        "register",
        "signup",
        "login",
        "cta",
        "banner",
        "button",
        "redirect",
        "out",
        "goto",
        "jump",
        "click",
    )
    for token in strong_tokens:
        if token in url:
            score += 4
        if token in context:
            score += 2
        if token in href:
            score += 1

    if any(key + "=" in url for key in WRAPPED_URL_KEYS):
        score += 5
    if "%2f%2f" in url or "http%3a" in url or "https%3a" in url:
        score += 5
    return score


def is_likely_subpage_candidate(candidate_url, item, base_url):
    url = (candidate_url or "").lower()
    if TRACKING_TOKEN in url:
        return False
    parsed = urlparse(candidate_url)
    if parsed.scheme not in ("http", "https"):
        return False
    if parsed.fragment:
        return False
    path = (parsed.path or "").lower()
    if path and any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
        return False
    if not is_same_host(base_url, candidate_url):
        return False
    if path and path != "/":
        return True
    return bool(parsed.query)


def subpage_candidate_score(candidate_url, item, base_url):
    score = 0
    url = (candidate_url or "").lower()
    context = (item.get("context") or "").lower()
    href = (item.get("href") or "").lower()
    if is_same_host(base_url, candidate_url):
        score += 12
    if any(token in url for token in ("banner", "button", "cta", "register", "signup", "login")):
        score += 6
    if any(token in context for token in ("banner", "button", "cta", "register", "signup", "login")):
        score += 3
    if any(token in href for token in ("banner", "button", "cta", "register", "signup", "login")):
        score += 2
    parsed = urlparse(candidate_url)
    if parsed.query:
        score += 2
    if parsed.path and parsed.path != "/":
        score += 2
    return score


def is_same_host(base_url, candidate_url):
    src = _normalize_host(base_url)
    dst = _normalize_host(candidate_url)
    return bool(src and dst and src == dst)


def build_probe_candidates(html_text, base_url, mode="wrapped", proxy_url=""):
    parser = HrefCollector()
    parser.feed(html_text or "")
    candidates = []
    seen = set()
    for item in parser.links:
        href = item.get("href", "") or ""
        node_id = int(item.get("node_id") or 0)
        attrs = item.get("attrs", {}) or {}
        raw_values = [href]
        raw_values.extend(str(v) for v in attrs.values() if v)
        for raw in raw_values:
            for candidate_url in extract_url_candidates(raw, base_url):
                if mode == "wrapped":
                    if not is_likely_wrapper_candidate(candidate_url, item, base_url):
                        continue
                    score = wrapper_candidate_score(candidate_url, item, base_url)
                else:
                    if not is_likely_subpage_candidate(candidate_url, item, base_url):
                        continue
                    score = subpage_candidate_score(candidate_url, item, base_url)
                key = (candidate_url.lower(), node_id, mode)
                if key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    {
                        "url": candidate_url,
                        "node_id": node_id,
                        "context": item.get("context", "no_text"),
                        "href": href,
                        "source_url": normalize_candidate_url(href, base_url),
                        "device_context": item.get("device_context", ""),
                        "proxy_url": proxy_url,
                        "score": score,
                    }
                )
    candidates.sort(key=lambda x: x.get("score", 0), reverse=True)
    return candidates


def discover_wrapped_tracking_links(candidate):
    url = candidate.get("url", "")
    proxy_url = candidate.get("proxy_url", "")
    if not url:
        return []
    no_redirect = fetch_url(
        url,
        allow_redirects=False,
        timeout_secs=WRAPPER_TIMEOUT_SECS,
        proxy_url=proxy_url,
    )
    status = int(no_redirect.get("status") or 0)
    if status not in (301, 302, 303, 307, 308):
        return []
    loc = (no_redirect.get("location") or "").strip()
    if not loc:
        return []
    loc_abs = urljoin(url, loc)
    found = []
    for tracking_url in extract_tracking_from_raw(loc_abs, url):
        found.append(
            {
                "url": tracking_url,
                "via_type": "wrapped_redirect",
                "wrapped_from": url,
                "context": candidate.get("context", "no_text"),
                "href": candidate.get("href", ""),
                "source_url": candidate.get("source_url", "") or url,
                "device_context": candidate.get("device_context", ""),
                "node_id": candidate.get("node_id", 0),
            }
        )
    return found


def discover_subpage_tracking_links(candidate):
    url = candidate.get("url", "")
    proxy_url = candidate.get("proxy_url", "")
    if not url:
        return []
    followed = fetch_url(
        url,
        allow_redirects=True,
        timeout_secs=WRAPPER_TIMEOUT_SECS,
        proxy_url=proxy_url,
    )
    body = followed.get("body") or b""
    final_url = (followed.get("final_url") or url).strip()
    source_url = candidate.get("source_url", "") or url
    if final_url and source_url and not is_same_host(source_url, final_url):
        return []
    if not body:
        return []
    found = []
    for sub_item in extract_direct_tracking_links_from_html(
        body,
        final_url,
        source_type="subpage_direct",
        subpage_from=final_url,
    ):
        found.append(
            {
                "url": sub_item.get("url", ""),
                "via_type": "subpage_direct",
                "subpage_from": sub_item.get("subpage_from", final_url),
                "context": sub_item.get("context", "no_text"),
                "href": sub_item.get("href", ""),
                "source_url": sub_item.get("source_url", "") or final_url,
                "device_context": sub_item.get("device_context", "") or candidate.get("device_context", ""),
                "node_id": sub_item.get("node_id", 0),
            }
        )
    return found


def probe_candidates(candidates, mode="wrapped"):
    if not candidates:
        return []
    workers = SUBPAGE_WORKERS if mode == "subpage" else WRAPPER_WORKERS
    probe_fn = discover_subpage_tracking_links if mode == "subpage" else discover_wrapped_tracking_links
    out = []
    seen = set()
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {executor.submit(probe_fn, candidate): candidate for candidate in candidates}
        for future in as_completed(future_map):
            try:
                items = future.result() or []
            except Exception:
                items = []
            for item in items:
                key = (
                    str(item.get("url") or "").strip().lower(),
                    int(item.get("node_id") or 0),
                    str(item.get("context") or "").strip().lower(),
                    str(item.get("device_context") or "").strip().lower(),
                    str(item.get("href") or "").strip().lower(),
                    str(item.get("source_url") or "").strip().lower(),
                    str(item.get("wrapped_from") or "").strip().lower(),
                    str(item.get("subpage_from") or "").strip().lower(),
                    str(item.get("via_type") or "").strip().lower(),
                )
                if key in seen:
                    continue
                seen.add(key)
                out.append(item)
    return out


def extract_tracking_from_raw(raw_value, base_url):
    if not raw_value:
        return []
    text = html.unescape(str(raw_value))
    candidates = []
    if text:
        candidates.append(text.strip())
    candidates.extend(URL_REGEX.findall(text))
    candidates.extend(extract_quoted_url_candidates(text))

    results = []
    visited = set()
    queue = [c for c in candidates if c]
    while queue:
        current = queue.pop(0).strip()
        if not current or current in visited:
            continue
        visited.add(current)

        normalized = normalize_candidate_url(current, base_url)
        if not normalized:
            continue

        if TRACKING_TOKEN in normalized.lower():
            results.append(normalized)

        try:
            parsed = urlparse(normalized)
        except Exception:
            continue
        if parsed.scheme not in ("http", "https"):
            continue

        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            if key.lower() not in WRAPPED_URL_KEYS and TRACKING_TOKEN not in value.lower():
                continue
            decoded = value
            for _ in range(2):
                decoded_next = unquote(decoded)
                if decoded_next == decoded:
                    break
                decoded = decoded_next
            decoded = html.unescape(decoded).strip()
            if not decoded:
                continue
            queue.append(decoded)
            queue.extend(URL_REGEX.findall(decoded))

    return results


def normalize_candidate_url(raw, base_url):
    value = html.unescape(str(raw).strip())
    value = CONTROL_CHAR_RE.sub("", value)
    if not value:
        return ""
    if value.startswith(("javascript:", "mailto:", "tel:", "#")):
        return ""
    if value.startswith("//"):
        parsed_base = urlparse(base_url)
        scheme = parsed_base.scheme or "https"
        return f"{scheme}:{value}"
    parsed = urlparse(value)
    if parsed.scheme in ("http", "https"):
        return sanitize_http_url(value)
    if value.startswith("/"):
        return sanitize_http_url(urljoin(base_url, value))
    return ""


def sanitize_http_url(url):
    try:
        parts = urlsplit(str(url).strip())
    except Exception:
        return ""
    if parts.scheme not in ("http", "https"):
        return ""
    if not parts.netloc:
        return ""
    path = quote(parts.path or "/", safe="/%:@+~!$&'()*;,=-._")
    query = quote(parts.query or "", safe="=&%:@+~!$'()*,;/?-._")
    fragment = ""
    clean = urlunsplit((parts.scheme, parts.netloc, path, query, fragment))
    if CONTROL_CHAR_RE.search(clean):
        return ""
    return clean


def follow_redirects(url, proxy_url=""):
    current = url
    chain = []
    for _ in range(MAX_REDIRECTS):
        result = fetch_url(current, allow_redirects=False, proxy_url=proxy_url)
        status = result["status"]
        location = result["location"]
        if status in (301, 302, 303, 307, 308) and location:
            next_url = urljoin(current, location)
            chain.append((status, current, next_url))
            current = next_url
            continue
        return result, current, chain
    return {
        "status": 0,
        "final_url": current,
        "body": b"",
        "error": "too many redirects",
        "location": "",
    }, current, chain


def check_tracking_link(url, proxy_url=""):
    initial = fetch_url(url, allow_redirects=False, proxy_url=proxy_url)
    status = initial["status"]
    location = initial["location"]
    if status in (301, 302, 303, 307, 308) and location:
        final_result, final_url, _chain = follow_redirects(url, proxy_url=proxy_url)
        final_status = final_result["status"]
        return False, f"{status}-> {final_status}", final_url
    if status == 0:
        return False, "error", url
    if status >= 400:
        return False, str(status), url
    return True, str(status), url


def analyze_tracking_link(url, proxy_url=""):
    initial = fetch_url(url, allow_redirects=False, proxy_url=proxy_url)
    initial_status = initial["status"]
    location = initial["location"]
    if initial_status in (301, 302, 303, 307, 308) and location:
        final_result, final_url, chain = follow_redirects(url, proxy_url=proxy_url)
        return {
            "is_redirect": True,
            "initial_status": initial_status,
            "final_status": final_result["status"],
            "final_url": final_url,
            "redirect_chain": format_redirect_chain(chain, final_result["status"], final_url),
        }
    return {
        "is_redirect": False,
        "initial_status": initial_status,
        "final_status": initial_status,
        "final_url": url,
        "redirect_chain": "",
    }


def format_redirect_chain(chain, final_status, final_url):
    if not chain:
        return ""
    parts = []
    for status, from_url, to_url in chain:
        parts.append(f"{from_url} --{status}--> {to_url}")
    parts.append(f"{final_url} --{final_status}--> END")
    return " || ".join(parts)


def is_scheme_only_change(original_url, final_url):
    try:
        o = urlparse(original_url)
        f = urlparse(final_url)
        return (
            o.scheme in ("http", "https")
            and f.scheme in ("http", "https")
            and o.scheme != f.scheme
            and o.netloc == f.netloc
            and o.path == f.path
            and o.params == f.params
            and o.query == f.query
            and o.fragment == f.fragment
        )
    except Exception:
        return False


def is_http_to_https_same_host(original_url, final_url):
    try:
        o = urlparse(original_url)
        f = urlparse(final_url)
        if o.scheme != "http" or f.scheme != "https":
            return False
        return _normalize_host(original_url) == _normalize_host(final_url)
    except Exception:
        return False


def _normalize_host(raw_url):
    try:
        host = (urlparse(raw_url).hostname or "").lower().strip(".")
    except Exception:
        host = ""
    if host.startswith("www."):
        host = host[4:]
    return host


def is_different_domain_redirect(original_url, final_url):
    src = _normalize_host(original_url)
    dst = _normalize_host(final_url)
    if not src or not dst:
        return False
    return src != dst


def detect_device_hint(link):
    parts = [
        str(link.get("context") or ""),
        str(link.get("device_context") or ""),
        str(link.get("href") or ""),
        str(link.get("source_url") or ""),
        str(link.get("wrapped_from") or ""),
        str(link.get("subpage_from") or ""),
    ]
    text = " ".join(parts).lower()
    has_mobile = bool(MOBILE_HINT_RE.search(text))
    has_desktop = bool(DESKTOP_HINT_RE.search(text))
    if has_mobile and not has_desktop:
        return "mobile"
    return ""


def extract_context_text(context):
    match = re.search(r"(?:^|;\s*)text=([^;]+)", str(context or ""), re.IGNORECASE)
    if not match:
        return ""
    return match.group(1).strip().lower()


def tracking_variant_group_key(link):
    return (
        str(link.get("url") or "").strip().lower(),
        extract_context_text(link.get("context", "")),
        str(link.get("source_type") or "").strip().lower(),
        str(link.get("wrapped_from") or "").strip().lower(),
        str(link.get("subpage_from") or "").strip().lower(),
    )


def assign_ui_variant_hints(tracking_links):
    grouped = {}
    hints = {}
    for link in tracking_links or []:
        key = tracking_identity_key(link)
        grouped.setdefault(tracking_variant_group_key(link), []).append((key, link))

    for items in grouped.values():
        if len(items) != 2:
            continue
        mobile_keys = [key for key, link in items if detect_device_hint(link) == "mobile"]
        if len(mobile_keys) == 1:
            hints[mobile_keys[0]] = "mobile"
            continue
        for key, _link in items:
            hints[key] = "responsive"
    return hints


def read_domains(path):
    with open(path, newline="", encoding="utf-8") as handle:
        rows = list(csv.reader(handle))
    if not rows:
        return [], ["domain"]
    header = rows[0]
    if "tracking_redirected" in header:
        drop_idx = header.index("tracking_redirected")
        header = [col for idx, col in enumerate(header) if idx != drop_idx]
        rows = [
            [cell for idx, cell in enumerate(row) if idx != drop_idx]
            for row in rows[1:]
        ]
        return rows, header
    if "redirect_chain" in header:
        drop_idx = header.index("redirect_chain")
        header = [col for idx, col in enumerate(header) if idx != drop_idx]
        rows = [
            [cell for idx, cell in enumerate(row) if idx != drop_idx]
            for row in rows[1:]
        ]
        return rows, header
    if "tracking_bad" in header:
        drop_idx = header.index("tracking_bad")
        header = [col for idx, col in enumerate(header) if idx != drop_idx]
        rows = [
            [cell for idx, cell in enumerate(row) if idx != drop_idx]
            for row in rows[1:]
        ]
        return rows, header
    if "tracking_bad_samples" in header:
        drop_idx = header.index("tracking_bad_samples")
        header = [col for idx, col in enumerate(header) if idx != drop_idx]
        rows = [
            [cell for idx, cell in enumerate(row) if idx != drop_idx]
            for row in rows[1:]
        ]
        return rows, header
    if any(cell.lower() in ("domain", "url") for cell in header):
        return rows[1:], header
    return rows, ["domain"]


def write_results(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(header)
        writer.writerows(rows)


def build_output_header(header):
    out_header = [
        col
        for col in header
        if col not in ("tracking_bad_samples", "tracking_bad", "tracking_redirected", "redirect_chain")
    ]
    new_cols = [
        "page_url",
        "page_status",
        "tracking_total",
        "tracking_ok",
        "tracking_error",
        "notes",
    ]
    for col in new_cols:
        if col not in out_header:
            out_header.append(col)
    return out_header


def process_domain(domain, out_header, ignore_https_redirect=False, scan_subpages=False, scan_wrapped=True, proxy_url=""):
    page = fetch_homepage_with_retry(domain, proxy_url=proxy_url)
    page_status = page["status"]
    page_url = page.get("page_url", "")
    page_final = page.get("final_url", "")
    notes = []

    if page_status == 0:
        notes.append(f"page_error:{page['error']}")
        tracking_links = []
    else:
        wrapped_enabled = bool(scan_wrapped) and not bool(scan_subpages)
        tracking_links = extract_tracking_links(
            page["body"],
            page_final or page_url,
            scan_subpages=scan_subpages,
            scan_wrapped=wrapped_enabled,
            proxy_url=proxy_url,
        )
        tracking_links = dedupe_tracking_links(tracking_links)

    tracking_total = len(tracking_links)
    tracking_ok = 0
    tracking_error = 0
    bad_links = []
    ok_links = []
    analyzed_cache = analyze_tracking_links_parallel(tracking_links, proxy_url=proxy_url)
    variant_hints = assign_ui_variant_hints(tracking_links)

    for link in tracking_links:
        variant_hint = variant_hints.get(tracking_identity_key(link), "")
        cached = analyzed_cache.get(link["url"])
        if cached is None:
            cached = analyze_tracking_link(link["url"], proxy_url=proxy_url)
            analyzed_cache[link["url"]] = cached
        result = dict(cached)
        if not result["is_redirect"]:
            tracking_ok += 1
            ok_links.append(
                {
                    "link": link["url"],
                    "reason": str(result["initial_status"]),
                    "final_url": result["final_url"],
                    "context": link.get("context", "no_text"),
                    "source_url": link.get("source_url", ""),
                    "wrapped_from": link.get("wrapped_from", ""),
                    "subpage_from": link.get("subpage_from", ""),
                    "source_type": link.get("source_type", "direct"),
                    "device_hint": variant_hint,
                }
            )
            continue

        final_url = result["final_url"]
        missing_https_redirect = is_http_to_https_same_host(link["url"], final_url)
        if missing_https_redirect:
            if ignore_https_redirect:
                tracking_ok += 1
                ok_links.append(
                    {
                        "link": link["url"],
                        "reason": f"{result['initial_status']}-> {result['final_status']} (thieu-https)",
                        "final_url": final_url,
                        "context": link.get("context", "no_text"),
                        "source_url": link.get("source_url", ""),
                        "wrapped_from": link.get("wrapped_from", ""),
                        "subpage_from": link.get("subpage_from", ""),
                        "source_type": link.get("source_type", "direct"),
                        "error_type": "",
                        "device_hint": variant_hint,
                    }
                )
                continue
            tracking_error += 1
            bad_links.append(
                {
                    "link": link["url"],
                    "reason": f"{result['initial_status']}-> {result['final_status']} (thieu-https)",
                    "final_url": final_url,
                    "context": link.get("context", "no_text"),
                    "source_url": link.get("source_url", ""),
                    "wrapped_from": link.get("wrapped_from", ""),
                    "subpage_from": link.get("subpage_from", ""),
                    "source_type": link.get("source_type", "direct"),
                    "error_type": "missing_https",
                    "device_hint": variant_hint,
                }
            )
            continue

        if is_different_domain_redirect(link["url"], final_url):
            tracking_error += 1
            bad_links.append(
                {
                    "link": link["url"],
                    "reason": f"{result['initial_status']}-> {result['final_status']}",
                    "final_url": final_url,
                    "context": link.get("context", "no_text"),
                    "source_url": link.get("source_url", ""),
                    "wrapped_from": link.get("wrapped_from", ""),
                    "subpage_from": link.get("subpage_from", ""),
                    "source_type": link.get("source_type", "direct"),
                    "error_type": "domain_redirect",
                    "device_hint": variant_hint,
                }
            )
        else:
            tracking_ok += 1
            ok_links.append(
                {
                    "link": link["url"],
                    "reason": f"{result['initial_status']}-> {result['final_status']} (same-domain)",
                    "final_url": final_url,
                    "context": link.get("context", "no_text"),
                    "source_url": link.get("source_url", ""),
                    "wrapped_from": link.get("wrapped_from", ""),
                    "subpage_from": link.get("subpage_from", ""),
                    "source_type": link.get("source_type", "direct"),
                    "error_type": "",
                    "device_hint": variant_hint,
                }
            )

    if tracking_total == 0 and page_status != 0:
        notes.append("no_tracking_links")

    out_row = [""] * len(out_header)
    out_row[out_header.index("domain")] = domain

    def set_col(col, value):
        idx = out_header.index(col)
        out_row[idx] = value

    set_col("page_url", page_url)
    set_col("page_status", page_status)
    set_col("tracking_total", tracking_total)
    set_col("tracking_ok", tracking_ok)
    set_col("tracking_error", tracking_error)
    set_col("notes", ";".join(notes))

    detail = {
        "tracking_ok": ok_links,
        "tracking_error": bad_links,
        "page_status": page_status,
        "notes": ";".join(notes),
    }

    time.sleep(0.2)
    return out_row, detail


def analyze_tracking_links_parallel(tracking_links, proxy_url=""):
    urls = []
    seen = set()
    for link in tracking_links or []:
        url = str(link.get("url") or "").strip()
        if not url or url in seen:
            continue
        seen.add(url)
        urls.append(url)
    if not urls:
        return {}
    if len(urls) == 1:
        url = urls[0]
        return {url: analyze_tracking_link(url, proxy_url=proxy_url)}

    out = {}
    worker_count = min(ANALYZE_WORKERS, len(urls))
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_map = {executor.submit(analyze_tracking_link, url, proxy_url): url for url in urls}
        for future in as_completed(future_map):
            url = future_map[future]
            try:
                out[url] = future.result()
            except Exception:
                out[url] = {
                    "is_redirect": False,
                    "initial_status": 0,
                    "final_status": 0,
                    "final_url": url,
                    "redirect_chain": "",
                }
    return out


def check_domains(domains, proxy_url=""):
    header = ["domain"]
    out_header = build_output_header(header)
    out_rows = []
    details = []

    for domain in domains:
        if not domain:
            continue
        out_row, detail = process_domain(domain, out_header, proxy_url=proxy_url)
        out_rows.append(out_row)
        details.append(detail)

    return out_header, out_rows, details


def main():
    input_path = "LIST_DOMAIN.csv"
    rows, header = read_domains(input_path)

    out_header = build_output_header(header)

    out_rows = []
    for row in rows:
        if not row or not row[0].strip():
            continue
        domain = row[0].strip()
        out_row, _ = process_domain(domain, out_header)
        out_rows.append(out_row)

    write_results(input_path, out_header, out_rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
