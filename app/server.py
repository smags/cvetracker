#!/usr/bin/env python3
"""CVE Tracker — Red Hat Security Data API frontend.

Single-file stdlib app. Persists a saved CVE list + 1h API cache on disk.
Endpoints:
  GET    /                  -> web UI
  GET    /api/list          -> saved CVEs, normalized
  POST   /api/cve           -> {"id": "CVE-YYYY-NNNN"} add (fetch + save)
  DELETE /api/cve/<id>      -> remove from saved list (+ drop cache)
  GET    /api/refresh/<id>  -> force refetch one CVE
"""
import json
import os
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8898"))
DATA_DIR = os.environ.get("DATA_DIR", "/data")
CACHE_DIR = os.path.join(DATA_DIR, "cache")
LIST_FILE = os.path.join(DATA_DIR, "cves.json")
API_BASE = "https://access.redhat.com/hydra/rest/securitydata/cve"
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
REFRESH_CHOICES = [30, 60, 120, 180]
DEFAULT_REFRESH_MIN = 60
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
MASKED = "********"
LOCK = threading.Lock()

# Force IPv4 (network has IPv6 disabled but DNS may return AAAA)
_orig_getaddrinfo = socket.getaddrinfo
def _getaddrinfo(host, port, *args, **kwargs):
    res = [r for r in _orig_getaddrinfo(host, port, *args, **kwargs) if r[0] == socket.AF_INET]
    if not res:
        raise socket.gaierror("no IPv4 address for %s" % host)
    return res
socket.getaddrinfo = _getaddrinfo

STATE_FIX = {  # package_state.fix_state -> (css class, label)
    "Affected": ("affected", "Affected"),
    "Fix deferred": ("deferred", "Fix deferred"),
    "Will not fix": ("wontfix", "Will not fix"),
    "Not affected": ("notaffected", "Not affected"),
    "New": ("new", "New"),
    "Out of support scope": ("oos", "Out of support scope"),
    "Out of development scope": ("oos", "Out of development scope"),
}
STATUS_ORDER = ["affected", "deferred", "wontfix", "new", "oos", "fixed", "notaffected"]


def natkey(s):
    """Natural sort key: digit runs compare numerically (RHEL 9 before RHEL 10)."""
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", s)]


def load_list():
    try:
        with open(LIST_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {"order": []}


def save_list(state):
    tmp = LIST_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, LIST_FILE)


def load_settings():
    try:
        with open(SETTINGS_FILE) as f:
            s = json.load(f)
    except (OSError, ValueError):
        s = {}
    if s.get("refresh_min") not in REFRESH_CHOICES:
        s["refresh_min"] = DEFAULT_REFRESH_MIN
    return s


def save_settings(s):
    tmp = SETTINGS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(s, f)
    os.replace(tmp, SETTINGS_FILE)


def cache_path(cve):
    return os.path.join(CACHE_DIR, cve + ".json")


def read_cache(cve):
    try:
        with open(cache_path(cve)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def proxy_url(s):
    """Proxy URL from settings, or None when the proxy is off/unconfigured."""
    if not s.get("proxy_enabled") or not (s.get("proxy_host") or "").strip():
        return None
    host = s["proxy_host"].strip()
    scheme, _, rest = host.partition("://")
    if not rest:
        scheme, rest = "http", host
    auth = ""
    user = (s.get("proxy_user") or "").strip()
    if user:
        auth = urllib.parse.quote(user, safe="") + ":" + \
            urllib.parse.quote(s.get("proxy_pass") or "", safe="") + "@"
    return scheme + "://" + auth + rest


def proxy_opener(s):
    # empty ProxyHandler dict = ignore ambient env proxies when proxy is off
    url = proxy_url(s)
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": url, "https": url} if url else {}))


def fetch_redhat(cve, settings=None):
    if settings is None:
        settings = load_settings()
    req = urllib.request.Request(
        API_BASE + "/" + cve + ".json",
        headers={"User-Agent": "cvetracker.example.com/1.0", "Accept": "application/json"})
    with proxy_opener(settings).open(req, timeout=20) as r:
        data = json.loads(r.read().decode("utf-8"))
    if isinstance(data, str):
        # Red Hat occasionally serves the payload double-encoded as a JSON string
        data = json.loads(data)
    return data


NO_INFO = "no info available at the moment"


def write_cache(cve, data):
    os.makedirs(CACHE_DIR, exist_ok=True)
    tmp = cache_path(cve) + ".tmp"
    with open(tmp, "w") as f:
        json.dump({"fetched_at": time.time(), "data": data}, f)
    os.replace(tmp, cache_path(cve))


def cached_result(cached):
    return cached["data"], (None if cached["data"] is not None else NO_INFO)


def get_data(cve, force=False):
    """Return (raw_dict, error). Any cached copy is served instantly; expiry
    is handled by the background refresher, never on the request path.
    A 404 is cached as data=None so the list stays fast; the refresher
    re-checks it after the TTL — Red Hat may add the CVE later."""
    cached = read_cache(cve)
    if cached and not force:
        return cached_result(cached)
    try:
        data = fetch_redhat(cve)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            write_cache(cve, None)
            return None, NO_INFO
        if cached:
            return cached_result(cached)
        return None, "Red Hat API error (HTTP %d)" % e.code
    except Exception as e:
        if cached:
            return cached_result(cached)
        return None, "fetch failed: %s" % e.__class__.__name__
    with LOCK:
        s = load_settings()
        s["last_sync"] = time.time()
        save_settings(s)
    write_cache(cve, data)
    return data, None


def _refresh_expired():
    """Refetch every saved CVE whose cache is missing or past the TTL."""
    ttl = load_settings()["refresh_min"] * 60
    with LOCK:
        order = list(load_list()["order"])
    stale = []
    for cve in order:
        cached = read_cache(cve)
        if not cached or time.time() - cached.get("fetched_at", 0) >= ttl:
            stale.append(cve)
    if stale:
        with ThreadPoolExecutor(max_workers=4) as ex:
            # force=True: get_data serves any cached copy unconditionally,
            # so only the refresher may re-fetch.
            list(ex.map(lambda c: get_data(c, force=True), stale))


def _refresher():
    while True:
        try:
            _refresh_expired()
        except Exception:  # noqa: BLE001 — keep the daemon alive
            pass
        time.sleep(30)


def normalize(cve, data):
    if not isinstance(data, dict):
        return {"id": cve, "error": True, "error_msg": "unexpected API payload", "rows": [], "sum": [0, 0, 0, 0]}
    rows, seen = [], {}
    for ar in data.get("affected_release") or []:
        prod = ar.get("product_name", "?")
        adv = ar.get("advisory", "")
        pkg = ar.get("package", "")
        date = (ar.get("release_date") or "")[:10]
        detail = " · ".join(x for x in (date, pkg) if x)
        row = {"product": prod, "status": "fixed", "label": "Fixed",
               "advisory": adv, "url": "https://access.redhat.com/errata/" + adv if adv else "",
               "detail": detail}
        seen[prod] = row
        rows.append(row)
    for ps in data.get("package_state") or []:
        prod = ps.get("product_name", "?")
        if prod in seen:
            continue  # a released erratum outranks package_state
        cls, label = STATE_FIX.get(ps.get("fix_state", ""), ("new", ps.get("fix_state", "?")))
        row = {"product": prod, "status": cls, "label": label,
               "advisory": "", "url": "", "detail": ps.get("package_name", "")}
        seen[prod] = row
        rows.append(row)
    rows.sort(key=lambda r: (STATUS_ORDER.index(r["status"]) if r["status"] in STATUS_ORDER else 9,
                             natkey(r["product"])))
    n_fixed = sum(1 for r in rows if r["status"] == "fixed")
    n_na = sum(1 for r in rows if r["status"] == "notaffected")
    n_oos = sum(1 for r in rows if r["status"] == "oos")
    n_aff = len(rows) - n_fixed - n_na - n_oos
    details = data.get("details") or []
    desc = ""
    if details:
        desc = re.sub(r"^" + re.escape(cve) + r"\s+", "", details[0])
    if not desc:
        desc = (data.get("statement") or "").strip()
    if len(desc) > 140:
        desc = desc[:137] + "..."
    pkgs = sorted({r["detail"].split("-0:")[0] for r in rows if r["detail"] and r["status"] != "fixed"} |
                  {(r["detail"].split(" · ")[-1].split("-0:")[0] if " · " in r["detail"] else "")
                   for r in rows if r["status"] == "fixed"})
    pkgs = [p for p in pkgs if p][:4]
    cvss3 = (data.get("cvss3") or {}).get("cvss3_score", "")
    return {
        "id": cve,
        "sev": (data.get("threat_severity") or "unknown").lower(),
        "desc": desc,
        "pub": (data.get("public_date") or "")[:10],
        "cvss3": cvss3,
        "pkgs": pkgs,
        "rows": rows,
        "sum": [n_fixed, n_aff, n_na, n_oos],
    }


def api_list():
    with LOCK:
        state = load_list()
    out = []
    for cve in state["order"]:
        data, err = get_data(cve)
        if data is None:
            out.append({"id": cve, "error": True, "error_msg": err, "rows": [], "sum": [0, 0, 0, 0]})
        else:
            out.append(normalize(cve, data))
    return out


class Handler(BaseHTTPRequestHandler):
    server_version = "cvetracker/1.0"

    def log_message(self, fmt, *args):
        pass

    def send_json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            body = PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path == "/api/list":
            try:
                self.send_json({"cves": api_list()})
            except Exception as e:  # noqa: BLE001
                self.send_json({"error": str(e)}, 500)
        elif self.path.startswith("/api/refresh/"):
            cve = self.path.rsplit("/", 1)[-1].upper()
            if not CVE_RE.match(cve):
                return self.send_json({"error": "bad CVE id"}, 400)
            data, err = get_data(cve, force=True)
            if data is None:
                return self.send_json({"error": err}, 404)
            self.send_json(normalize(cve, data))
        elif self.path == "/api/settings":
            s = load_settings()
            self.send_json({"refresh_min": s["refresh_min"],
                            "theme": s.get("theme"),
                            "product": s.get("product"),
                            "last_sync": s.get("last_sync"),
                            "proxy_enabled": bool(s.get("proxy_enabled")),
                            "proxy_host": s.get("proxy_host", ""),
                            "proxy_user": s.get("proxy_user", ""),
                            "proxy_pass_set": bool(s.get("proxy_pass"))})
        elif self.path == "/healthz":
            self.send_json({"ok": True})
        else:
            self.send_json({"error": "not found"}, 404)

    def do_POST(self):
        if self.path == "/api/proxytest":
            try:
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self.send_json({"error": "bad json"}, 400)
            with LOCK:
                t = dict(load_settings())
            for k in ("proxy_enabled", "proxy_host", "proxy_user"):
                if k in payload:
                    t[k] = payload[k]
            # password: null = clear, ""/masked = keep stored, else = use given
            if payload.get("proxy_pass") not in (None, "", MASKED):
                t["proxy_pass"] = payload["proxy_pass"]
            elif payload.get("proxy_pass") is None and "proxy_pass" in payload:
                t["proxy_pass"] = ""
            url = proxy_url(t)
            shown = url or "direct (proxy disabled)"
            for form in {t.get("proxy_pass") or "", urllib.parse.quote(t.get("proxy_pass") or "", safe="")}:
                if form:
                    shown = shown.replace(form, MASKED)
            t0 = time.time()
            try:
                fetch_redhat("CVE-2014-0160", t)
                self.send_json({"ok": True, "via": shown, "ms": int((time.time() - t0) * 1000)})
            except Exception as e:  # noqa: BLE001
                detail = str(e) or e.__class__.__name__
                if t.get("proxy_pass"):
                    detail = detail.replace(t["proxy_pass"], MASKED)
                self.send_json({"ok": False, "via": shown, "detail": detail})
            return
        if self.path == "/api/settings":
            try:
                length = int(self.headers.get("Content-Length", 0))
                payload = json.loads(self.rfile.read(length) or b"{}")
            except ValueError:
                return self.send_json({"error": "bad json"}, 400)
            with LOCK:
                s = load_settings()
                if "refresh_min" in payload:
                    if payload["refresh_min"] not in REFRESH_CHOICES:
                        return self.send_json({"error": "refresh_min must be one of %s" % REFRESH_CHOICES}, 400)
                    s["refresh_min"] = payload["refresh_min"]
                if "theme" in payload:
                    if payload["theme"] not in ("light", "dark"):
                        return self.send_json({"error": "theme must be light or dark"}, 400)
                    s["theme"] = payload["theme"]
                if "product" in payload:
                    s["product"] = str(payload.get("product") or "")
                if "proxy_enabled" in payload:
                    s["proxy_enabled"] = bool(payload["proxy_enabled"])
                if "proxy_host" in payload:
                    s["proxy_host"] = str(payload.get("proxy_host") or "").strip()
                if "proxy_user" in payload:
                    s["proxy_user"] = str(payload.get("proxy_user") or "").strip()
                if "proxy_pass" in payload:
                    p = payload["proxy_pass"]
                    if p is None:
                        s["proxy_pass"] = ""          # explicit clear
                    elif p not in ("", MASKED):
                        s["proxy_pass"] = str(p)      # real change; masked/empty keep
                save_settings(s)
            return self.send_json({"ok": True, "refresh_min": s["refresh_min"], "theme": s.get("theme")})
        if self.path != "/api/cve":
            return self.send_json({"error": "not found"}, 404)
        try:
            length = int(self.headers.get("Content-Length", 0))
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self.send_json({"error": "bad json"}, 400)
        cve = (payload.get("id") or "").strip().upper()
        if not CVE_RE.match(cve):
            return self.send_json({"error": "invalid CVE id (expected CVE-YYYY-NNNN)"}, 400)
        data, err = get_data(cve)
        with LOCK:
            state = load_list()
            if cve not in state["order"]:
                state["order"].append(cve)
                save_list(state)
        if data is None:
            # unknown to Red Hat (or unreachable): keep it on the list, the
            # background refresher will pick it up once info becomes available
            return self.send_json({"id": cve, "error": True, "error_msg": err,
                                   "rows": [], "sum": [0, 0, 0, 0]})
        self.send_json(normalize(cve, data))

    def do_DELETE(self):
        if not self.path.startswith("/api/cve/"):
            return self.send_json({"error": "not found"}, 404)
        cve = self.path.rsplit("/", 1)[-1].upper()
        if not CVE_RE.match(cve):
            return self.send_json({"error": "bad CVE id"}, 400)
        with LOCK:
            state = load_list()
            state["order"] = [c for c in state["order"] if c != cve]
            save_list(state)
        try:
            os.remove(cache_path(cve))
        except OSError:
            pass
        self.send_json({"ok": True, "removed": cve})


PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CVE Tracker</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg%20xmlns%3D%22http%3A//www.w3.org/2000/svg%22%20viewBox%3D%220%200%2024%2024%22%3E%3Cpath%20fill%3D%22%23ee0000%22%20d%3D%22M16.009%2013.386c1.577%200%203.86-.326%203.86-2.202a1.765%201.765%200%200%200-.04-.431l-.94-4.08c-.216-.898-.406-1.305-1.982-2.093-1.223-.625-3.888-1.658-4.676-1.658-.733%200-.947.946-1.822.946-.842%200-1.467-.706-2.255-.706-.757%200-1.25.515-1.63%201.576%200%200-1.06%202.99-1.197%203.424a.81.81%200%200%200-.028.245c0%201.162%204.577%204.974%2010.71%204.974m4.101-1.435c.218%201.032.218%201.14.218%201.277%200%201.765-1.984%202.745-4.593%202.745-5.895.004-11.06-3.451-11.06-5.734a2.326%202.326%200%200%201%20.19-.925C2.746%209.415%200%209.794%200%2012.217c0%203.969%209.405%208.861%2016.851%208.861%205.71%200%207.149-2.582%207.149-4.62%200-1.605-1.387-3.425-3.887-4.512%22/%3E%3C/svg%3E">
<style>
  :root, [data-theme="light"] {
    --bg:#f6f7f8; --card:#fff; --border:#e2e4e8; --border2:#eceef1; --text:#1a1a1a;
    --muted:#777; --faint:#888; --row:#f2f3f5; --sumbg:#fafbfc; --input:#fff; --inputb:#d0d4da;
    --link:#06c; --fixed-bg:#e3f6e8; --fixed-fg:#1a7f37; --aff-bg:#fdecea; --aff-fg:#c00;
    --wf-bg:#efe6f7; --wf-fg:#7b3fa0; --def-bg:#fff4d6; --def-fg:#9a6b00;
    --na-bg:#f0f1f3; --na-fg:#667; --new-bg:#e8eef9; --new-fg:#3b5bdb; --clear-bg:#c9ecd3;
    --oos-bg:#e8eef9; --oos-fg:#3b5bdb;
  }
  [data-theme="dark"] {
    --bg:#16181d; --card:#1f2229; --border:#2e323b; --border2:#2a2e36; --text:#e6e8ec;
    --muted:#9aa0ab; --faint:#7d838e; --row:#262a32; --sumbg:#1b1e24; --input:#16181d; --inputb:#3a3f49;
    --link:#6ab0f3; --fixed-bg:#12351d; --fixed-fg:#5dd37e; --aff-bg:#3d1714; --aff-fg:#ff7b72;
    --wf-bg:#2d1b3d; --wf-fg:#c792ea; --def-bg:#3a2e10; --def-fg:#e3b341;
    --na-bg:#25282e; --na-fg:#9aa0ab; --new-bg:#1a2440; --new-fg:#7aa2f7; --clear-bg:#1f3d28;
    --oos-bg:#1a2440; --oos-fg:#7aa2f7;
  }
  * { box-sizing:border-box; }
  body { font-family:-apple-system,'Segoe UI',Roboto,sans-serif; color:var(--text); background:var(--bg); margin:0; padding:24px; transition:background .2s,color .2s; }
  .wrap { width:75%; margin:0 auto; }
  header { display:flex; align-items:center; gap:12px; margin-bottom:18px; }
  .logo { width:38px; height:38px; display:flex; align-items:center; justify-content:center; flex-shrink:0; }
  .logo svg { width:36px; height:36px; fill:#ee0000; }
  h1 { font-size:20px; margin:0; }
  .sub { color:var(--muted); font-size:12.5px; }
  .theme { margin-left:auto; background:var(--card); border:1px solid var(--border); color:var(--text); border-radius:8px; padding:7px 14px; font-size:13px; cursor:pointer; }
  .inputcard { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:14px; margin-bottom:16px; }
  textarea { width:100%; height:64px; border:1px solid var(--inputb); border-radius:8px; padding:10px; font-family:ui-monospace,Menlo,monospace; font-size:13px; resize:vertical; background:var(--input); color:var(--text); }
  .row { display:flex; gap:10px; align-items:center; margin-top:10px; flex-wrap:wrap; }
  button.go { background:#ee0000; color:#fff; border:0; border-radius:8px; padding:9px 22px; font-size:14px; font-weight:600; cursor:pointer; }
  button.go:disabled { opacity:.5; }
  .hint { color:var(--faint); font-size:12px; }
  .errline { color:#e5484d; font-size:12.5px; display:none; }
  .toolbar { display:flex; align-items:center; gap:8px; margin:0 0 12px; flex-wrap:wrap; }
  .count { color:var(--muted); font-size:12.5px; margin-right:auto; }
  .sync { color:var(--faint); font-size:12px; white-space:nowrap; }
  .sync select { background:var(--card); border:1px solid var(--border); color:var(--text); border-radius:6px; padding:4px 6px; font-size:12px; cursor:pointer; }
  .fbtn { background:var(--card); border:1px solid var(--border); color:var(--muted); border-radius:16px; padding:5px 14px; font-size:12.5px; cursor:pointer; }
  .fbtn.on { background:var(--text); color:var(--bg); border-color:var(--text); font-weight:600; }
  .sbox { background:var(--card); border:1px solid var(--border); color:var(--text); border-radius:16px; padding:5px 14px; font-size:12.5px; width:300px; outline:none; }
  .sbox:focus { border-color:var(--link); }
  .cve { background:var(--card); border:1px solid var(--border); border-radius:10px; margin-bottom:12px; overflow:hidden; height:86px; }
  .cve.open { height:auto; }
  .cve.clear { background:var(--clear-bg); }
  .cve.clear .summary { background:transparent; }
  .chead { display:flex; align-items:center; gap:10px; padding:12px 16px; cursor:pointer; user-select:none; height:86px; }
  .chev { color:var(--faint); font-size:11px; }
  .cid { font-family:ui-monospace,Menlo,monospace; font-weight:700; font-size:15px; white-space:nowrap; }
  .cid a { color:var(--text); text-decoration:none; }
  .cid a:hover { color:#ee0000; }
  .sev { font-size:11px; font-weight:700; padding:3px 10px; border-radius:20px; text-transform:uppercase; letter-spacing:.4px; }
  .sev.critical { background:#c00; color:#fff; }
  .sev.important { background:#ff8b00; color:#fff; }
  .sev.moderate { background:#ffd166; color:#5a4500; }
  .sev.low { background:#cfe3ff; color:#123; }
  .sev.unknown { background:var(--na-bg); color:var(--na-fg); }
  .one { color:var(--muted); font-size:12.5px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; flex:1; min-width:80px; }
  .cbadges { display:flex; gap:6px; flex-shrink:0; }
  .cb { font-size:11px; font-weight:700; padding:2px 8px; border-radius:10px; white-space:nowrap; }
  .cb.f { background:var(--fixed-bg); color:var(--fixed-fg); }
  .cb.a { background:var(--aff-bg); color:var(--aff-fg); }
  .cb.n { background:var(--na-bg); color:var(--na-fg); }
  .cb.o { background:var(--oos-bg); color:var(--oos-fg); }
  .meta { color:var(--faint); font-size:12px; white-space:nowrap; }
  .del { border:1px solid var(--border); background:transparent; color:var(--faint); border-radius:6px; padding:3px 10px; font-size:12px; cursor:pointer; }
  .del:hover { color:#e5484d; border-color:#e5484d; }
  .ref { border:1px solid var(--border); background:transparent; color:var(--faint); border-radius:6px; padding:3px 10px; font-size:12px; cursor:pointer; margin-right:6px; }
  .ref:hover { color:var(--link); border-color:var(--link); }
  .ref:disabled { opacity:.5; cursor:default; }
  .cbody { border-top:1px solid var(--border2); }
  .pkg { font-size:12.5px; color:var(--muted); padding:8px 16px 0; }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th { text-align:left; color:var(--faint); font-weight:600; font-size:11px; text-transform:uppercase; letter-spacing:.4px; padding:8px 16px; border-bottom:1px solid var(--border2); }
  td { padding:7px 16px; border-bottom:1px solid var(--row); vertical-align:top; }
  tr:last-child td { border-bottom:0; }
  .st { font-size:11.5px; font-weight:700; padding:2px 9px; border-radius:12px; white-space:nowrap; }
  .st.fixed { background:var(--fixed-bg); color:var(--fixed-fg); }
  .st.affected { background:var(--aff-bg); color:var(--aff-fg); }
  .st.wontfix { background:var(--wf-bg); color:var(--wf-fg); }
  .st.deferred { background:var(--def-bg); color:var(--def-fg); }
  .st.new { background:var(--new-bg); color:var(--new-fg); }
  .st.oos { background:var(--oos-bg); color:var(--oos-fg); }
  .st.notaffected { background:var(--na-bg); color:var(--na-fg); }
  .err a { font-family:ui-monospace,Menlo,monospace; color:var(--link); text-decoration:none; font-size:12.5px; }
  .err a:hover { text-decoration:underline; }
  .err .date { color:var(--faint); font-size:11.5px; }
  .summary { display:flex; gap:8px; padding:10px 16px; background:var(--sumbg); border-top:1px solid var(--border2); font-size:12px; color:var(--muted); flex-wrap:wrap; }
  .summary b { color:var(--text); }
  .empty { color:var(--faint); font-size:13px; padding:14px 4px; display:none; }
  .loading { color:var(--faint); font-size:13px; padding:6px 2px; }
  .modalbg { position:fixed; inset:0; background:rgba(0,0,0,.45); display:none; justify-content:center; z-index:50; }
  .modalbg.on { display:flex; }
  .modal { background:var(--card); border:1px solid var(--border); border-radius:12px; width:460px; max-width:92vw; max-height:86vh; overflow:auto; margin-top:8vh; padding:0 0 18px; box-shadow:0 12px 40px rgba(0,0,0,.35); height:fit-content; }
  .mhead { display:flex; align-items:center; padding:14px 16px; border-bottom:1px solid var(--border2); position:sticky; top:0; background:var(--card); }
  .mhead h2 { font-size:15px; margin:0; flex:1; }
  .mclose { border:1px solid var(--border); background:transparent; color:var(--faint); border-radius:6px; padding:3px 10px; font-size:13px; cursor:pointer; }
  .mclose:hover { color:#e5484d; border-color:#e5484d; }
  .msec { padding:14px 16px 0; }
  .mlab { color:var(--faint); font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:.4px; margin-bottom:8px; }
  .seg { display:flex; gap:8px; }
  .seg button { flex:1; background:var(--row); border:1px solid var(--border); color:var(--text); border-radius:8px; padding:8px 0; font-size:13px; cursor:pointer; }
  .seg button.on { border-color:#ee0000; box-shadow:0 0 0 1px #ee0000 inset; font-weight:600; }
  .msel, .minp { width:100%; background:var(--input); border:1px solid var(--inputb); color:var(--text); border-radius:8px; padding:8px 10px; font-size:13px; outline:none; }
  .msel:focus, .minp:focus { border-color:var(--link); }
  .mchk { display:flex; gap:8px; align-items:center; font-size:13px; color:var(--text); cursor:pointer; }
  .pgrid { display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-top:8px; }
  .prow { display:flex; gap:10px; align-items:center; margin-top:10px; }
  .pres { font-size:12px; color:var(--faint); }
  .pres.ok { color:var(--fixed-fg); }
  .pres.bad { color:#e5484d; }
  .mfoot { display:flex; gap:10px; justify-content:flex-end; padding:18px 16px 0; }
  .modal { scrollbar-color: var(--inputb) var(--card); }
</style>
</head>
<body data-theme="light">
<div class="wrap">
  <header>
    <div class="logo"><svg viewBox="0 0 24 24" role="img" aria-label="Red Hat"><path d="M16.009 13.386c1.577 0 3.86-.326 3.86-2.202a1.765 1.765 0 0 0-.04-.431l-.94-4.08c-.216-.898-.406-1.305-1.982-2.093-1.223-.625-3.888-1.658-4.676-1.658-.733 0-.947.946-1.822.946-.842 0-1.467-.706-2.255-.706-.757 0-1.25.515-1.63 1.576 0 0-1.06 2.99-1.197 3.424a.81.81 0 0 0-.028.245c0 1.162 4.577 4.974 10.71 4.974m4.101-1.435c.218 1.032.218 1.14.218 1.277 0 1.765-1.984 2.745-4.593 2.745-5.895.004-11.06-3.451-11.06-5.734a2.326 2.326 0 0 1 .19-.925C2.746 9.415 0 9.794 0 12.217c0 3.969 9.405 8.861 16.851 8.861 5.71 0 7.149-2.582 7.149-4.62 0-1.605-1.387-3.425-3.887-4.512"/></svg></div>
    <div>
      <h1>CVE Tracker</h1>
    </div>
    <button class="theme" onclick="openSettings()">⚙️ Settings</button>
  </header>

  <div class="inputcard">
    <textarea id="inp" placeholder="Paste CVE IDs — one per line or comma-separated"></textarea>
    <div class="row">
      <button class="go" id="addbtn" onclick="addCves()">Add to list</button>
      <span class="hint">saved on the server &middot; auto-refreshed on the interval from Settings</span>
      <span class="errline" id="errline"></span>
    </div>
  </div>

  <div class="toolbar">
    <span class="count" id="count"></span>
    <span class="sync" id="sync"></span>
    <label class="sync">Product
      <select id="prodsel" onchange="setProduct(this.value)"></select>
    </label>
    <button class="fbtn on" data-f="all" onclick="setFilter('all')">All</button>
    <button class="fbtn" data-f="affected" onclick="setFilter('affected')">Affected only</button>
    <button class="fbtn" data-f="notaffected" onclick="setFilter('notaffected')">Not affected only</button>
    <input class="sbox" id="q" placeholder="Search: id, keyword, product (rhel, ocp, osp)…" oninput="setQuery(this.value)">
  </div>

  <div class="loading" id="loading">Loading…</div>
  <div id="list"></div>
  <div class="empty" id="empty">Nothing here yet — add CVEs above, or none match the current filter.</div>
</div>

<div class="modalbg" id="modalbg" onclick="if(event.target===this)closeSettings()">
  <div class="modal" role="dialog" aria-modal="true" aria-label="Settings">
    <div class="mhead"><h2>⚙️ Settings</h2><button class="mclose" onclick="closeSettings()">&times;</button></div>
    <div class="msec">
      <div class="mlab">Appearance</div>
      <div class="seg">
        <button id="th_light" onclick="pickTheme('light')">☀️ Light</button>
        <button id="th_dark" onclick="pickTheme('dark')">🌙 Dark</button>
      </div>
    </div>
    <div class="msec">
      <div class="mlab">Refresh interval</div>
      <select id="refsel" class="msel">
        <option value="30">Every 30 min</option>
        <option value="60">Every 60 min</option>
        <option value="120">Every 120 min</option>
        <option value="180">Every 180 min</option>
      </select>
    </div>
    <div class="msec">
      <div class="mlab">Proxy server</div>
      <label class="mchk"><input type="checkbox" id="pxen" onchange="proxyEnToggle()"> Use a proxy server for Red Hat API calls</label>
      <div id="pxbox">
        <div style="margin-top:8px"><input class="minp" id="pxhost" placeholder="host:port — e.g. proxy.example.com:3128" autocomplete="off" spellcheck="false"></div>
        <div class="pgrid">
          <input class="minp" id="pxuser" placeholder="Username (optional)" autocomplete="off">
          <input class="minp" id="pxpass" type="password" placeholder="Password" autocomplete="new-password">
        </div>
        <label class="mchk" id="pxclrwrap" style="display:none;margin-top:8px"><input type="checkbox" id="pxclr"> Clear saved password</label>
        <div class="prow"><button class="fbtn" id="pxtestbtn" onclick="testProxy()">Test proxy</button><span class="pres" id="pxres"></span></div>
      </div>
    </div>
    <div class="mfoot"><button class="fbtn" onclick="closeSettings()">Cancel</button><button class="go" id="savebtn" onclick="saveSettings()">Save</button></div>
  </div>
</div>

<script>
let CVES = [];            // server order
let BY_ID = {};           // id -> normalized data
let FILTER = "all";
let QUERY = "";
let PRODUCT = "";            // server-side setting, loaded in loadSettings()
let PRODUCT_LOADED = false;
let SETTINGS = {};           // last GET /api/settings, seeds the modal
const isOpen = JSON.parse(localStorage.getItem("cv-open") || "{}");

function esc(s){ return String(s==null?"":s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function setQuery(v){ QUERY = v.trim().toLowerCase(); render(); }
function prodInitials(p){ return p.split(/[\s.\-\/]+/).map(w=>w[0]||"").join("").toLowerCase(); }
function cardMatch(d){
  if (!QUERY) return true;
  const toks = QUERY.split(/\s+/).filter(Boolean);
  if (!toks.length) return true;
  const hay = [d.id.toLowerCase(), (d.desc||"").toLowerCase(), (d.pkgs||[]).join(" ").toLowerCase(),
               (d.error_msg||"").toLowerCase(), (d.rows||[]).map(r=>r.advisory||"").join(" ").toLowerCase()];
  const inis = (d.rows||[]).map(r=>prodInitials(r.product));
  return toks.every(t => hay.some(h=>h.includes(t)) || inis.some(i=>i.includes(t)));
}
function rowMatch(r){
  if (PRODUCT && r.product !== PRODUCT) return false;
  if (FILTER === "all") return true;
  if (FILTER === "notaffected") return r.status === "notaffected";
  return r.status !== "notaffected" && r.status !== "oos";
}
function rebuildProductOptions(){
  const sel = document.getElementById("prodsel");
  const prods = [...new Set(CVES.flatMap(d => (d.rows||[]).map(r=>r.product)))]
    .sort((a,b)=>a.localeCompare(b, undefined, {numeric:true, sensitivity:"base"}));
  if (PRODUCT && !prods.includes(PRODUCT)) PRODUCT = "";
  sel.innerHTML = `<option value="">All products</option>` +
    prods.map(p=>`<option value="${esc(p)}"${p===PRODUCT?" selected":""}>${esc(p)}</option>`).join("");
}
function setProduct(v){ PRODUCT = v; render();
  fetch("/api/settings", {method:"POST", headers:{"Content-Type":"application/json"},
    body:JSON.stringify({product: v})});
}
function card(d){
  const id = d.id;
  if (d.error) {
    return `<div class="cve" style="${cardMatch(d)?"":"display:none"}"><div class="chead">
      <span class="cid">${esc(id)}</span><span class="sev unknown">${d.error_msg === "no info available at the moment" ? "pending" : "error"}</span>
      <span class="one">${esc(d.error_msg||"unavailable from Red Hat API")}</span>
      <button class="ref" onclick="ref(event,'${id}')">↻ refresh</button><button class="del" onclick="del(event,'${id}')">✕ delete</button></div></div>`;
  }
  const rows = d.rows.filter(rowMatch).map(r=>
    `<tr><td>${esc(r.product)}</td><td><span class="st ${r.status}">${esc(r.label)}</span></td>`+
    `<td class="err">${r.url?`<a href="${esc(r.url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${esc(r.advisory)}</a>`:""} `+
    `<span class="date">${esc(r.advisory?r.detail:"")}</span></td></tr>`).join("");
  const visible = d.rows.some(rowMatch) && cardMatch(d);
  const open = !!isOpen[id];
  const cvss = d.cvss3 ? ` · CVSS3 ${esc(d.cvss3)}` : "";
  const clean = d.sum[1]===0 ? " clear" : "";
  return `<div class="cve${open?" open":""}${clean}" style="${visible?"":"display:none"}">
    <div class="chead" onclick="toggle('${id}')">
      <span class="chev">${open?"▼":"▶"}</span>
      <span class="cid"><a href="https://access.redhat.com/security/cve/${esc(id)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${esc(id)}</a></span>
      <span class="sev ${esc(d.sev)}">${esc(d.sev)}</span>
      <span class="one">${esc(d.desc)}</span>
      <span class="cbadges"><span class="cb f">${d.sum[0]} fixed</span><span class="cb a">${d.sum[1]} affected</span><span class="cb n">${d.sum[2]} not affected</span>${d.sum[3]?`<span class="cb o">${d.sum[3]} unsupported</span>`:""}</span>
      <span class="meta">pub ${esc(d.pub)}${esc(cvss)}</span>
      <button class="ref" onclick="ref(event,'${id}')">↻ refresh</button><button class="del" onclick="del(event,'${id}')">✕ delete</button>
    </div>
    <div class="cbody" style="${open?"":"display:none"}">
      ${d.pkgs.length?`<div class="pkg">packages: <span style="font-family:ui-monospace,Menlo,monospace;font-size:12px">${d.pkgs.map(esc).join(", ")}</span></div>`:""}
      <table><tr><th style="width:34%">Product</th><th style="width:16%">Status</th><th>Errata / fixed package</th></tr>${rows}</table>
      <div class="summary"><span><b>${d.sum[0]}</b> fixed</span><span>·</span><span><b>${d.sum[1]}</b> affected</span><span>·</span><span><b>${d.sum[2]}</b> not affected</span>${d.sum[3]?`<span>·</span><span><b>${d.sum[3]}</b> unsupported</span>`:""}</div>
    </div>
  </div>`;
}
function render(){
  BY_ID = {}; CVES.forEach(d => BY_ID[d.id] = d);
  CVES.sort((a,b) => (b.error?1:0)-(a.error?1:0) || (b.pub||"").localeCompare(a.pub||"") || a.id.localeCompare(b.id)); // untracked on top, then newest published
  rebuildProductOptions();
  document.getElementById("list").innerHTML = CVES.map(card).join("");
  const shown = CVES.filter(d => cardMatch(d) && (d.error || d.rows.some(rowMatch))).length;
  document.getElementById("count").textContent = CVES.length + (CVES.length===1 ? " CVE saved" : " CVEs saved") + ((FILTER!=="all" || PRODUCT || QUERY) ? " · " + shown + " match filter" : "");
  document.getElementById("empty").style.display = (CVES.length===0 || shown===0) ? "block" : "none";
}
async function load(){
  document.getElementById("loading").style.display = "";
  try {
    const r = await fetch("/api/list");
    const j = await r.json();
    CVES = j.cves || [];
  } catch(e){ CVES = []; }
  document.getElementById("loading").style.display = "none";
  render();
}
function toggle(id){ isOpen[id] = !isOpen[id]; localStorage.setItem("cv-open", JSON.stringify(isOpen)); render(); }
async function del(e,id){
  e.stopPropagation();
  await fetch("/api/cve/"+id, {method:"DELETE"});
  delete isOpen[id]; localStorage.setItem("cv-open", JSON.stringify(isOpen));
  CVES = CVES.filter(d=>d.id!==id); render();
}
async function ref(e,id){
  e.stopPropagation();
  const btn = e.target;
  btn.disabled = true; btn.textContent = "↻ …";
  const restore = () => { btn.disabled = false; btn.textContent = "↻ refresh"; };
  try {
    const r = await fetch("/api/refresh/"+id);
    const j = await r.json();
    if (j.error) { btn.textContent = "↻ failed"; setTimeout(restore, 2000); return; }
    CVES = CVES.map(d => d.id===id ? j : d);
    render();
  } catch(err){ btn.textContent = "↻ failed"; setTimeout(restore, 2000); }
}
async function addCves(){
  const btn = document.getElementById("addbtn"), el = document.getElementById("errline");
  const ids = [...new Set(document.getElementById("inp").value.split(/[\s,]+/)
    .map(x=>x.toUpperCase()).filter(x=>/^CVE-\d{4}-\d+$/.test(x)))];
  el.style.display = "none";
  if (!ids.length) { el.textContent = "No valid CVE IDs found in input."; el.style.display=""; return; }
  btn.disabled = true; btn.textContent = "Fetching…";
  const errs = [];
  for (const id of ids) {           // sequential, per user preference
    try {
      const r = await fetch("/api/cve", {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({id})});
      const j = await r.json();
      if (!r.ok) { errs.push(id + ": " + (j.error||r.status)); continue; }
      if (!CVES.some(d=>d.id===id)) CVES.push(j); else CVES[CVES.findIndex(d=>d.id===id)] = j;
    } catch(e){ errs.push(id + ": network error"); }
  }
  btn.disabled = false; btn.textContent = "Add to list";
  document.getElementById("inp").value = "";
  if (errs.length) { el.textContent = errs.join(" · "); el.style.display = ""; }
  render();
}
function setFilter(f){
  FILTER = f;
  document.querySelectorAll(".fbtn").forEach(b=>b.classList.toggle("on", b.dataset.f===f));
  render();
}
function setTheme(t){
  document.body.dataset.theme = t;
  localStorage.setItem("cv-theme", t);
  syncThemeBtns();
}
function syncThemeBtns(){
  const t = document.body.dataset.theme;
  document.getElementById("th_light").classList.toggle("on", t === "light");
  document.getElementById("th_dark").classList.toggle("on", t === "dark");
}
function pickTheme(t){   // applied instantly, persisted in the background
  setTheme(t);
  fetch("/api/settings", {method:"POST", headers:{"Content-Type":"application/json"},
    body:JSON.stringify({theme:t})});
}
function openSettings(){
  document.getElementById("refsel").value = String(SETTINGS.refresh_min || 60);
  document.getElementById("pxen").checked = !!SETTINGS.proxy_enabled;
  document.getElementById("pxhost").value = SETTINGS.proxy_host || "";
  document.getElementById("pxuser").value = SETTINGS.proxy_user || "";
  const pass = document.getElementById("pxpass");
  pass.value = "";
  pass.placeholder = SETTINGS.proxy_pass_set ? "••••••••" : "none";
  document.getElementById("pxclrwrap").style.display = SETTINGS.proxy_pass_set ? "" : "none";
  document.getElementById("pxclr").checked = false;
  const res = document.getElementById("pxres");
  res.className = "pres"; res.textContent = "";
  proxyEnToggle(); syncThemeBtns();
  document.getElementById("modalbg").classList.add("on");
}
function closeSettings(){ document.getElementById("modalbg").classList.remove("on"); }
function proxyEnToggle(){
  const on = document.getElementById("pxen").checked;
  document.getElementById("pxbox").style.opacity = on ? "1" : ".45";
  ["pxhost","pxuser","pxpass","pxclr","pxtestbtn"].forEach(id => document.getElementById(id).disabled = !on);
}
function proxyPayload(){
  const p = { proxy_enabled: document.getElementById("pxen").checked,
              proxy_host: document.getElementById("pxhost").value.trim(),
              proxy_user: document.getElementById("pxuser").value.trim() };
  const pass = document.getElementById("pxpass").value;
  if (document.getElementById("pxclr").checked) p.proxy_pass = null;
  else if (pass) p.proxy_pass = pass;   // empty field = keep stored password
  return p;
}
async function testProxy(){
  const btn = document.getElementById("pxtestbtn"), res = document.getElementById("pxres");
  btn.disabled = true; res.className = "pres"; res.textContent = "Testing…";
  try {
    const j = await (await fetch("/api/proxytest", {method:"POST",
      headers:{"Content-Type":"application/json"}, body:JSON.stringify(proxyPayload())})).json();
    if (j.ok) { res.className = "pres ok"; res.textContent = "✓ OK via " + j.via + " (" + j.ms + " ms)"; }
    else { res.className = "pres bad"; res.textContent = "✗ " + (j.detail || "failed") + " — via " + j.via; }
  } catch(e){ res.className = "pres bad"; res.textContent = "✗ network error"; }
  proxyEnToggle();
}
async function saveSettings(){
  const btn = document.getElementById("savebtn"); btn.disabled = true;
  const payload = Object.assign({refresh_min: +document.getElementById("refsel").value}, proxyPayload());
  try {
    await fetch("/api/settings", {method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify(payload)});
  } catch(e){}
  btn.disabled = false;
  closeSettings();
  await load(); await loadSettings();
}
async function loadSettings(){
  try {
    const j = await (await fetch("/api/settings")).json();
    SETTINGS = j;
    if (j.last_sync) document.getElementById("sync").textContent =
      "Last sync: " + new Date(j.last_sync * 1000).toLocaleString();
    if (j.theme) setTheme(j.theme);
    if (!PRODUCT_LOADED && "product" in j) { PRODUCT = j.product || ""; PRODUCT_LOADED = true; }
  } catch(e){}
}
document.addEventListener("keydown", e => { if (e.key === "Escape") closeSettings(); });
document.body.dataset.theme = localStorage.getItem("cv-theme") ||
  (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
syncThemeBtns();
(async function(){ await loadSettings(); await load(); await loadSettings(); })();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    os.makedirs(CACHE_DIR, exist_ok=True)
    threading.Thread(target=_refresher, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()