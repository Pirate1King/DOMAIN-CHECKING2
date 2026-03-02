import csv
import socket
import sys
import time
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler


TRACKING_TOKEN = "a=mswl"
USER_AGENT = "Mozilla/5.0 (compatible; DomainCheck/1.0)"
TIMEOUT_SECS = 15
MAX_REDIRECTS = 5


class HrefCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self._current = None
        self._stack = []

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
        self.links.append(
            {
                "href": self._current["href"],
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


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_url(url, allow_redirects=True):
    handlers = []
    if not allow_redirects:
        handlers.append(NoRedirect())
    opener = build_opener(*handlers)
    req = Request(url, headers={"User-Agent": USER_AGENT})
    return opener.open(req, timeout=TIMEOUT_SECS)


def fetch_url(url, allow_redirects=True):
    try:
        resp = _open_url(url, allow_redirects=allow_redirects)
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


def extract_tracking_links(html_bytes, base_url):
    try:
        html_text = html_bytes.decode("utf-8", errors="ignore")
    except Exception:
        html_text = ""
    parser = HrefCollector()
    parser.feed(html_text)
    links = []
    for item in parser.links:
        href = item.get("href", "")
        if TRACKING_TOKEN in href.lower():
            links.append(
                {
                    "url": urljoin(base_url, href),
                    "context": item.get("context", "no_text"),
                    "href": href,
                }
            )
    return links


def follow_redirects(url):
    current = url
    for _ in range(MAX_REDIRECTS):
        result = fetch_url(current, allow_redirects=False)
        status = result["status"]
        location = result["location"]
        if status in (301, 302, 303, 307, 308) and location:
            current = urljoin(current, location)
            continue
        return result, current
    return {"status": 0, "final_url": current, "body": b"", "error": "too many redirects", "location": ""}, current


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
        final_result, final_url = follow_redirects(url)
        return {
            "is_redirect": True,
            "initial_status": initial_status,
            "final_status": final_result["status"],
            "final_url": final_url,
        }
    return {
        "is_redirect": False,
        "initial_status": initial_status,
        "final_status": initial_status,
        "final_url": url,
    }


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
        if col not in ("tracking_bad_samples", "tracking_bad", "tracking_redirected")
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


def process_domain(domain, out_header, ignore_https_redirect=False):
    page = fetch_homepage(domain)
    page_status = page["status"]
    page_url = page.get("page_url", "")
    page_final = page.get("final_url", "")
    notes = []

    if page_status == 0:
        notes.append(f"page_error:{page['error']}")
        tracking_links = []
    else:
        tracking_links = extract_tracking_links(page["body"], page_final or page_url)

    tracking_total = len(tracking_links)
    tracking_ok = 0
    tracking_error = 0
    bad_links = []

    for link in tracking_links:
        result = analyze_tracking_link(link["url"])
        if not result["is_redirect"]:
            tracking_ok += 1
            continue

        final_url = result["final_url"]
        if ignore_https_redirect and is_scheme_only_change(link["url"], final_url):
            tracking_ok += 1
            continue

        if is_different_domain_redirect(link["url"], final_url):
            tracking_error += 1
            bad_links.append(
                {
                    "link": link["url"],
                    "reason": f"{result['initial_status']}-> {result['final_status']}",
                    "final_url": final_url,
                    "context": link.get("context", "no_text"),
                }
            )
        else:
            tracking_ok += 1

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
