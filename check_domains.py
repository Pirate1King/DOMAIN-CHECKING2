import csv
import html
import re
import socket
import sys
import time
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlparse, urlsplit, urlunsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler


TRACKING_TOKEN = "a=mswl"
USER_AGENT = "Mozilla/5.0 (compatible; DomainCheck/1.0)"
TIMEOUT_SECS = 15
MAX_REDIRECTS = 5
MAX_WRAPPER_PROBES = 20
WRAPPER_TIMEOUT_SECS = 6
PAGE_RETRY_DELAY_SECS = 0.6
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
URL_REGEX = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
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
            }
        )
        self._current = None

    def handle_data(self, data):
        if self._current is not None and data:
            self._current["text_parts"].append(data)

    def _find_parent_context(self):
        for item in reversed(self._stack[:-1]):
            if item.get("id") or item.get("class"):
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
        return ""

    def _capture_non_anchor_candidate(self, tag, attrs_dict):
        if not attrs_dict:
            return
        has_relevant_attr = False
        for key, value in attrs_dict.items():
            if not value:
                continue
            low = str(value).lower()
            if "http" in low or TRACKING_TOKEN in low:
                has_relevant_attr = True
                break
            if key.startswith("data-") or key in ("onclick", "onmousedown"):
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
            }
        )


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_url(url, allow_redirects=True, timeout_secs=TIMEOUT_SECS):
    handlers = []
    if not allow_redirects:
        handlers.append(NoRedirect())
    opener = build_opener(*handlers)
    req = Request(url, headers={"User-Agent": USER_AGENT})
    return opener.open(req, timeout=timeout_secs)


def fetch_url(url, allow_redirects=True, timeout_secs=TIMEOUT_SECS):
    try:
        resp = _open_url(url, allow_redirects=allow_redirects, timeout_secs=timeout_secs)
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
        return {
            "status": exc.code,
            "final_url": url,
            "body": b"",
            "error": "",
            "location": exc.headers.get("Location", ""),
        }
    except (URLError, socket.timeout, ValueError) as exc:
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


def fetch_homepage(domain):
    last_error = ""
    for candidate in pick_homepage(domain):
        result = fetch_url(candidate, allow_redirects=True)
        if result["status"] != 0:
            result["page_url"] = candidate
            return result
        last_error = result["error"]
    return {
        "status": 0,
        "final_url": "",
        "body": b"",
        "error": last_error or "unreachable",
        "location": "",
        "page_url": "",
    }


def fetch_homepage_with_retry(domain):
    first = fetch_homepage(domain)
    if first["status"] == 200:
        return first
    # Retry once for non-200 to reduce false alarms from transient responses.
    time.sleep(PAGE_RETRY_DELAY_SECS)
    second = fetch_homepage(domain)
    if second["status"] == 200:
        return second
    return second


def extract_tracking_links(html_bytes, base_url, scan_subpages=False):
    try:
        html_text = html_bytes.decode("utf-8", errors="ignore")
    except Exception:
        html_text = ""
    parser = HrefCollector()
    parser.feed(html_text)
    links = []
    seen = set()
    wrapper_candidates = []
    wrapper_seen = set()
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
                        "href": href,
                        "source_url": normalize_candidate_url(href, base_url),
                        "wrapped_from": "",
                        "subpage_from": "",
                    }
                )
            for candidate_url in extract_url_candidates(raw, base_url):
                if not is_likely_wrapper_candidate(candidate_url, item, base_url):
                    continue
                key = (
                    candidate_url.lower(),
                    node_id,
                )
                if key in wrapper_seen:
                    continue
                wrapper_seen.add(key)
                wrapper_candidates.append(
                    {
                        "url": candidate_url,
                        "node_id": node_id,
                        "context": item.get("context", "no_text"),
                        "href": href,
                        "score": wrapper_candidate_score(candidate_url, item, base_url),
                    }
                )

    wrapper_candidates.sort(key=lambda x: x.get("score", 0), reverse=True)

    probes = 0
    for cand in wrapper_candidates:
        if probes >= MAX_WRAPPER_PROBES:
            break
        if TRACKING_TOKEN in cand["url"].lower():
            continue
        probes += 1
        wrapped_links = discover_wrapped_tracking_links(cand["url"], scan_subpages=scan_subpages)
        for wrapped_item in wrapped_links:
            found = wrapped_item.get("url", "")
            via_type = wrapped_item.get("via_type", "")
            subpage_from = wrapped_item.get("subpage_from", "")
            context_suffix = f"; wrapped_from={cand['url']}"
            wrapped_from = cand.get("url", "")
            if via_type == "subpage_direct":
                context_suffix = f"; subpage_from={subpage_from or cand['url']}"
                wrapped_from = ""
            key = (
                found.lower(),
                int(cand.get("node_id") or 0),
                (cand.get("context", "") or "").strip().lower(),
                (cand.get("href", "") or "").strip().lower(),
            )
            if key in seen:
                continue
            seen.add(key)
            links.append(
                {
                    "url": found,
                    "node_id": int(cand.get("node_id") or 0),
                    "context": f"{cand['context']}{context_suffix}",
                    "href": cand.get("href", ""),
                    "source_url": cand.get("url", ""),
                    "wrapped_from": wrapped_from,
                    "subpage_from": subpage_from,
                }
            )
    return links


def dedupe_tracking_links(links):
    out = []
    seen = set()
    for item in links or []:
        key = (
            str(item.get("url") or "").strip().lower(),
            str(item.get("context") or "").strip().lower(),
            str(item.get("href") or "").strip().lower(),
            str(item.get("source_url") or "").strip().lower(),
            str(item.get("wrapped_from") or "").strip().lower(),
            str(item.get("subpage_from") or "").strip().lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def extract_url_candidates(raw, base_url):
    text = html.unescape(str(raw or "")).strip()
    if not text:
        return []
    candidates = [text]
    candidates.extend(URL_REGEX.findall(text))
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

    if is_same_host(base_url, candidate_url):
        return True

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


def is_same_host(base_url, candidate_url):
    src = _normalize_host(base_url)
    dst = _normalize_host(candidate_url)
    return bool(src and dst and src == dst)


def discover_wrapped_tracking_links(url, scan_subpages=False):
    found = []

    no_redirect = fetch_url(url, allow_redirects=False, timeout_secs=WRAPPER_TIMEOUT_SECS)
    loc = (no_redirect.get("location") or "").strip()
    if loc:
        loc_abs = urljoin(url, loc)
        for tracking_url in extract_tracking_from_raw(loc_abs, url):
            found.append(
                {
                    "url": tracking_url,
                    "via_type": "wrapped_redirect",
                    "subpage_from": "",
                }
            )

    followed = fetch_url(url, allow_redirects=True, timeout_secs=WRAPPER_TIMEOUT_SECS)
    final_url = (followed.get("final_url") or "").strip()
    if final_url:
        for tracking_url in extract_tracking_from_raw(final_url, url):
            found.append(
                {
                    "url": tracking_url,
                    "via_type": "wrapped_redirect",
                    "subpage_from": "",
                }
            )

    if scan_subpages:
        body = followed.get("body") or b""
        if body:
            try:
                text = body.decode("utf-8", errors="ignore")
            except Exception:
                text = ""
            if text:
                for tracking_url in extract_tracking_from_raw(text, url):
                    found.append(
                        {
                            "url": tracking_url,
                            "via_type": "subpage_direct",
                            "subpage_from": final_url or url,
                        }
                    )

    out = []
    seen = set()
    for item in found:
        val = item.get("url", "")
        via_type = item.get("via_type", "")
        subpage_from = item.get("subpage_from", "")
        key = (val.lower(), via_type, subpage_from.lower())
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


def follow_redirects(url):
    current = url
    chain = []
    for _ in range(MAX_REDIRECTS):
        result = fetch_url(current, allow_redirects=False)
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


def check_tracking_link(url):
    initial = fetch_url(url, allow_redirects=False)
    status = initial["status"]
    location = initial["location"]
    if status in (301, 302, 303, 307, 308) and location:
        final_result, final_url = follow_redirects(url)
        final_status = final_result["status"]
        return False, f"{status}-> {final_status}", final_url
    if status == 0:
        return False, "error", url
    if status >= 400:
        return False, str(status), url
    return True, str(status), url


def analyze_tracking_link(url):
    initial = fetch_url(url, allow_redirects=False)
    initial_status = initial["status"]
    location = initial["location"]
    if initial_status in (301, 302, 303, 307, 308) and location:
        final_result, final_url, chain = follow_redirects(url)
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
        "page_final_url",
        "tracking_total",
        "tracking_ok",
        "tracking_error",
        "notes",
    ]
    for col in new_cols:
        if col not in out_header:
            out_header.append(col)
    return out_header


def process_domain(domain, out_header, ignore_https_redirect=False, scan_subpages=False):
    page = fetch_homepage_with_retry(domain)
    page_status = page["status"]
    page_url = page.get("page_url", "")
    page_final = page.get("final_url", "")
    notes = []

    if page_status == 0:
        notes.append(f"page_error:{page['error']}")
        tracking_links = []
    else:
        tracking_links = extract_tracking_links(page["body"], page_final or page_url, scan_subpages=scan_subpages)
        tracking_links = dedupe_tracking_links(tracking_links)

    tracking_total = len(tracking_links)
    tracking_ok = 0
    tracking_error = 0
    bad_links = []
    ok_links = []
    analyzed_cache = {}

    for link in tracking_links:
        cached = analyzed_cache.get(link["url"])
        if cached is None:
            cached = analyze_tracking_link(link["url"])
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
                        "error_type": "",
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
                    "error_type": "missing_https",
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
                    "error_type": "domain_redirect",
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
                    "error_type": "",
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
    set_col("page_final_url", page_final)
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


def check_domains(domains):
    header = ["domain"]
    out_header = build_output_header(header)
    out_rows = []
    details = []

    for domain in domains:
        if not domain:
            continue
        out_row, detail = process_domain(domain, out_header)
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
