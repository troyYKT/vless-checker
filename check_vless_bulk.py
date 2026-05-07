#!/usr/bin/env python3
"""
Bulk VLESS checker.

Features:
- Built-in sources: CIDR, SNI, CIDR_checked
- GitHub download with local fallback
- Direct single vless:// link support
- normal/light modes
- cfg latency via https://www.gstatic.com/generate_204
- optional soft load test
- sorted working output by fastest cfg_ms
- Windows/macOS/Linux friendly

Requirements:
- Python 3.10+
- xray in PATH
- curl in PATH
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PRINT_LOCK = threading.Lock()
SCRIPT_DIR = Path(__file__).resolve().parent

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

CFG_LATENCY_URL = "https://www.gstatic.com/generate_204"
LOAD_TEST_URL = "https://www.gstatic.com/generate_204"

DEFAULT_TESTS = {
    "ip": "https://api.ipify.org?format=json",
    "google": "https://www.google.com/generate_204",
    "youtube": "https://www.youtube.com/generate_204",
    "instagram": "https://www.instagram.com/favicon.ico",
    "telegram": "https://telegram.org/favicon.ico",
    "whatsapp": "https://www.whatsapp.com/favicon.ico",
}

PRESET_SOURCES = {
    "1": {
        "name": "CIDR",
        "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
        "local_file": "WHITE-CIDR-RU-all.txt",
    },
    "2": {
        "name": "SNI",
        "url": "https://github.com/igareck/vpn-configs-for-russia/blob/main/WHITE-SNI-RU-all.txt",
        "local_file": "WHITE-SNI-RU-all.txt",
    },
    "3": {
        "name": "CIDR_checked",
        "url": "https://github.com/igareck/vpn-configs-for-russia/blob/main/WHITE-CIDR-RU-checked.txt",
        "local_file": "WHITE-CIDR-RU-checked.txt",
    },
}

CLIENT_QUERY_ORDER: List[Tuple[str, Tuple[str, ...], Optional[str], bool]] = [
    ("encryption", ("encryption",), "none", True),
    ("security", ("security",), None, False),
    ("type", ("type",), None, False),
    ("flow", ("flow",), None, False),
    ("sni", ("sni", "serverName"), None, False),
    ("fp", ("fp", "fingerprint"), None, False),
    ("pbk", ("pbk", "publicKey"), None, False),
    ("sid", ("sid", "shortId"), None, False),
    ("spx", ("spx", "spiderX"), None, False),
    ("alpn", ("alpn",), None, False),
    ("allowInsecure", ("allowInsecure",), None, False),
    ("host", ("host",), None, False),
    ("path", ("path",), None, False),
    ("serviceName", ("serviceName",), None, False),
    ("authority", ("authority",), None, False),
    ("mode", ("mode",), None, False),
    ("headerType", ("headerType",), None, False),
    ("quicSecurity", ("quicSecurity",), None, False),
    ("key", ("key",), None, False),
    ("mldsa65Verify", ("mldsa65Verify",), None, False),
]


@dataclass
class TestResult:
    ok: bool
    http_code: str = "000"
    time_total: str = ""
    error: str = ""


@dataclass
class LoadResult:
    enabled: bool = False
    ok: bool = True
    ok_count: int = 0
    total: int = 0
    success_rate: float = 0.0
    avg_ms: Optional[int] = None
    min_ms: Optional[int] = None
    error: str = ""


@dataclass
class LinkResult:
    index: int
    name: str
    link: str
    client_link: str
    ok: bool
    cfg_ok: bool
    ip_ok: bool
    google_ok: bool
    youtube_ok: bool
    instagram_ok: bool
    telegram_ok: bool
    whatsapp_ok: bool
    cfg_http: str
    ip_http: str
    google_http: str
    youtube_http: str
    instagram_http: str
    telegram_http: str
    whatsapp_http: str
    cfg_ms: Optional[int]
    load: LoadResult
    error: str
    elapsed: float


def log(msg: str) -> None:
    with PRINT_LOCK:
        print(msg, flush=True)


def color_enabled() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def colorize_status(status: str) -> str:
    if not color_enabled():
        return status
    if status == "OK":
        return "\033[92mOK\033[0m"
    if status == "FAIL":
        return "\033[91mFAIL\033[0m"
    return status


def decode_output(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def default_local_dir() -> Path:
    system = platform.system().lower()
    if system in {"windows", "darwin"}:
        return Path.home() / "vless_checker"
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            return Path("/root/vless_checker")
    except Exception:
        pass
    return Path.home() / "vless_checker"


def safe_filename_part(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    value = value.strip("._-")
    return value or "custom"


def github_blob_to_raw(url: str) -> str:
    p = urllib.parse.urlsplit(url)
    if p.netloc.lower() != "github.com" or "/blob/" not in p.path:
        return url
    parts = p.path.strip("/").split("/")
    if len(parts) >= 5 and parts[2] == "blob":
        owner, repo, _, branch = parts[:4]
        rest = "/".join(parts[4:])
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{rest}"
    return url


def url_basename_for_cache(source: str) -> str:
    try:
        url = github_blob_to_raw(source)
        name = Path(urllib.parse.urlsplit(url).path).name
    except Exception:
        name = ""
    name = safe_filename_part(name) if name else "vless_links.txt"
    return name or "vless_links.txt"


def read_input(
    source: str,
    timeout: int = 30,
    local_fallback: Optional[str] = None,
    local_source_dir: Optional[Path] = None,
) -> str:
    """Read subscription text/URL/local file/direct vless:// link.

    Important Windows fix: direct vless:// links are not file paths.
    """
    source = str(source).strip().strip('"\'')

    if source.lower().startswith("vless://"):
        return source + "\n"

    local_source_dir = local_source_dir or default_local_dir()

    if re.match(r"^https?://", source, re.I):
        url = github_blob_to_raw(source)
        try:
            print(f"Downloading source: {url}", flush=True)
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            text = data.decode("utf-8", errors="replace")

            # Cache downloaded preset/custom file when we know the fallback name.
            cache_name = local_fallback or url_basename_for_cache(url)
            if cache_name:
                try:
                    local_source_dir.mkdir(parents=True, exist_ok=True)
                    (local_source_dir / cache_name).write_text(text, encoding="utf-8")
                except Exception:
                    pass
            return text
        except Exception as e:
            print(f"Download failed: {e}", flush=True)
            candidates: List[Path] = []
            if local_fallback:
                candidates.append(local_source_dir / local_fallback)
                candidates.append(SCRIPT_DIR / local_fallback)
            else:
                name = url_basename_for_cache(url)
                candidates.append(local_source_dir / name)
                candidates.append(SCRIPT_DIR / name)

            for path in candidates:
                if path.exists():
                    print(f"Using local fallback: {path}", flush=True)
                    return path.read_text(encoding="utf-8", errors="replace")
            raise RuntimeError(
                f"Could not download {url} and local fallback was not found. "
                f"Checked: {', '.join(str(p) for p in candidates)}"
            ) from e

    path = Path(source).expanduser()
    if not path.exists() and not path.is_absolute():
        # Also allow local files from --local-dir and script directory.
        for candidate in (local_source_dir / source, SCRIPT_DIR / source):
            if candidate.exists():
                path = candidate
                break
    return path.read_text(encoding="utf-8", errors="replace")


def try_b64_decode(text: str) -> Optional[str]:
    compact = re.sub(r"\s+", "", text.strip())
    if not compact or len(compact) < 16:
        return None
    if "vless://" in text.lower():
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return None
    compact = compact.replace("-", "+").replace("_", "/")
    compact += "=" * (-len(compact) % 4)
    try:
        decoded = base64.b64decode(compact, validate=False)
        out = decoded.decode("utf-8", errors="replace")
        if "vless://" in out.lower():
            return out
    except Exception:
        return None
    return None


def extract_vless_links(text: str) -> List[str]:
    decoded = try_b64_decode(text)
    if decoded:
        text = decoded

    links: List[str] = []
    seen = set()

    for raw_line in text.splitlines():
        line = raw_line.strip().strip('"\'')
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("vless://"):
            link = line
            if link not in seen:
                seen.add(link)
                links.append(link)
            continue
        for m in re.finditer(r"vless://[^\s<'\"]+", line, flags=re.I):
            link = m.group(0).strip()
            if link not in seen:
                seen.add(link)
                links.append(link)
    return links


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(host: str, port: int, proc: subprocess.Popen, timeout: float = 4.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def qget(q: Dict[str, List[str]], key: str, default: Optional[str] = None) -> Optional[str]:
    value = q.get(key, [default])[0]
    if value is None:
        return None
    return urllib.parse.unquote(str(value))


def bool_q(value: Optional[str]) -> bool:
    return str(value).lower() in {"1", "true", "yes", "y"}


def split_csv(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    return [x for x in re.split(r"[,;]", value) if x]


def parse_vless(url: str) -> Tuple[dict, str]:
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme.lower() != "vless":
        raise ValueError("not a vless:// link")

    uuid = urllib.parse.unquote(parsed.username or "")
    host = parsed.hostname
    port = parsed.port
    name = urllib.parse.unquote(parsed.fragment or host or "link")
    q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    if not uuid or not host or not port:
        raise ValueError("missing uuid/host/port")

    network = (qget(q, "type", "tcp") or "tcp").lower()
    security = (qget(q, "security", "none") or "none").lower()
    flow = qget(q, "flow")

    user = {"id": uuid, "encryption": qget(q, "encryption", "none") or "none"}
    if flow:
        user["flow"] = flow

    stream: Dict[str, object] = {"network": network, "security": security}

    if security == "tls":
        tls = {"serverName": qget(q, "sni", qget(q, "serverName", host)) or host}
        fp = qget(q, "fp") or qget(q, "fingerprint")
        alpn = split_csv(qget(q, "alpn"))
        if fp:
            tls["fingerprint"] = fp
        if alpn:
            tls["alpn"] = alpn
        if bool_q(qget(q, "allowInsecure")):
            tls["allowInsecure"] = True
        stream["tlsSettings"] = tls

    elif security == "reality":
        pbk = qget(q, "pbk") or qget(q, "publicKey")
        if not pbk:
            raise ValueError("reality link has no public key: pbk/publicKey")
        reality = {
            "serverName": qget(q, "sni", qget(q, "serverName", host)) or host,
            "fingerprint": qget(q, "fp", qget(q, "fingerprint", "chrome")) or "chrome",
            "publicKey": pbk,
            "shortId": qget(q, "sid", qget(q, "shortId", "")) or "",
            "spiderX": qget(q, "spx", qget(q, "spiderX", "/")) or "/",
        }
        mldsa = qget(q, "mldsa65Verify")
        if mldsa:
            reality["mldsa65Verify"] = mldsa
        stream["realitySettings"] = reality

    elif security not in {"none", ""}:
        pass

    if network == "tcp":
        header_type = qget(q, "headerType", "none") or "none"
        if header_type != "none":
            tcp = {"header": {"type": header_type}}
            host_header = qget(q, "host")
            path = qget(q, "path")
            if header_type == "http":
                request: Dict[str, object] = {}
                if path:
                    request["path"] = [path]
                if host_header:
                    request["headers"] = {"Host": [host_header]}
                if request:
                    tcp["header"]["request"] = request
            stream["tcpSettings"] = tcp

    elif network == "ws":
        ws = {"path": qget(q, "path", "/") or "/", "headers": {}}
        h = qget(q, "host")
        if h:
            ws["headers"]["Host"] = h
        stream["wsSettings"] = ws

    elif network == "grpc":
        grpc = {"serviceName": qget(q, "serviceName", "") or ""}
        authority = qget(q, "authority")
        if authority:
            grpc["authority"] = authority
        mode = qget(q, "mode")
        if mode == "multi":
            grpc["multiMode"] = True
        stream["grpcSettings"] = grpc

    elif network == "httpupgrade":
        hu = {"path": qget(q, "path", "/") or "/"}
        h = qget(q, "host")
        if h:
            hu["host"] = h
        stream["httpupgradeSettings"] = hu

    elif network in {"xhttp", "splithttp"}:
        key = "xhttpSettings" if network == "xhttp" else "splithttpSettings"
        xh = {"path": qget(q, "path", "/") or "/"}
        h = qget(q, "host")
        mode = qget(q, "mode")
        if h:
            xh["host"] = h
        if mode:
            xh["mode"] = mode
        stream[key] = xh

    elif network in {"kcp", "mkcp"}:
        stream["network"] = "kcp"
        stream["kcpSettings"] = {"header": {"type": qget(q, "headerType", "none") or "none"}}

    elif network == "quic":
        stream["quicSettings"] = {
            "security": qget(q, "quicSecurity", "none") or "none",
            "key": qget(q, "key", "") or "",
            "header": {"type": qget(q, "headerType", "none") or "none"},
        }

    else:
        raise ValueError(f"unsupported transport type={network}")

    outbound = {
        "protocol": "vless",
        "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]},
        "streamSettings": stream,
        "tag": "proxy",
    }
    return outbound, name


def build_xray_config(vless_url: str, socks_port: int, socks_user: str, socks_pass: str) -> Tuple[dict, str]:
    outbound, name = parse_vless(vless_url)
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": socks_port,
                "protocol": "socks",
                "settings": {
                    "auth": "password",
                    "accounts": [{"user": socks_user, "pass": socks_pass}],
                    "udp": False,
                },
                "tag": "socks-in",
            }
        ],
        "outbounds": [outbound],
    }
    return config, name


def clean_client_link(url: str) -> str:
    parsed = urllib.parse.urlsplit(url.strip())
    if parsed.scheme.lower() != "vless":
        return url.strip()
    q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    out: List[Tuple[str, str]] = []
    for target_key, aliases, default, always in CLIENT_QUERY_ORDER:
        value = None
        for alias in aliases:
            if alias in q and q[alias]:
                value = q[alias][0]
                break
        if value is None:
            value = default
        if value is not None and (always or value != ""):
            out.append((target_key, value))
    query = urllib.parse.urlencode(out, doseq=False, safe="/,:@")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def mask_link(url: str) -> str:
    try:
        p = urllib.parse.urlsplit(url)
        if p.scheme.lower() != "vless":
            return url
        host = p.hostname or "host"
        port = f":{p.port}" if p.port else ""
        frag = f"#{urllib.parse.unquote(p.fragment)}" if p.fragment else ""
        return f"vless://***@{host}{port}{frag}"
    except Exception:
        return "vless://***"


def ms_from_time_total(value: str) -> Optional[int]:
    try:
        return int(round(float(value) * 1000))
    except Exception:
        return None


def http_ok(code: str, kind: str) -> bool:
    try:
        c = int(code)
    except Exception:
        return False
    if kind in {"ip", "cfg", "google", "youtube"}:
        return 200 <= c < 400
    # For favicon/static checks, 400/404 still means the domain is reachable.
    return 200 <= c < 500


def parse_curl_markers(stdout: str, stderr: str) -> Tuple[str, str, str]:
    combined = f"{stdout}\n{stderr}"
    code = "000"
    tt = ""
    m = re.search(r"__CURL_HTTP_CODE__:(\d{3})", combined)
    if m:
        code = m.group(1)
    m = re.search(r"__CURL_TIME_TOTAL__:([0-9.]+)", combined)
    if m:
        tt = m.group(1)

    # Remove marker lines from user-facing error.
    cleaned = re.sub(r"__CURL_HTTP_CODE__:\d{3}", "", combined)
    cleaned = re.sub(r"__CURL_TIME_TOTAL__:[0-9.]+", "", cleaned)
    cleaned = cleaned.strip()
    return code, tt, cleaned


def curl_test(
    curl_bin: str,
    proxy: str,
    url: str,
    timeout: int,
    kind: str,
    method: str = "GET",
) -> TestResult:
    marker = "__CURL_HTTP_CODE__:%{http_code}\n__CURL_TIME_TOTAL__:%{time_total}\n"
    cmd = [
        curl_bin,
        "-L",
        "--silent",
        "--show-error",
        "--connect-timeout",
        str(timeout),
        "--max-time",
        str(timeout),
        "--proxy",
        proxy,
        "--user-agent",
        USER_AGENT,
        "--output",
        os.devnull,
        "--write-out",
        marker,
    ]
    if method.upper() == "HEAD":
        cmd.append("--head")
    cmd.append(url)

    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 4)
        out = decode_output(r.stdout)
        err = decode_output(r.stderr)
        code, tt, cleaned = parse_curl_markers(out, err)
        ok = http_ok(code, kind) and r.returncode == 0
        if not ok:
            if cleaned:
                error = cleaned
            else:
                error = f"curl return code {r.returncode}"
        else:
            error = ""
        return TestResult(ok=ok, http_code=code, time_total=tt, error=error)
    except subprocess.TimeoutExpired:
        return TestResult(ok=False, http_code="000", error=f"curl process timed out after {timeout + 4}s")
    except Exception as e:
        return TestResult(ok=False, http_code="000", error=str(e))


def run_load_test(
    curl_bin: str,
    proxy: str,
    timeout: int,
    requests: int,
    workers: int,
) -> LoadResult:
    requests = max(1, requests)
    workers = max(1, min(workers, requests))
    times: List[int] = []
    errors: List[str] = []

    def one() -> TestResult:
        return curl_test(curl_bin, proxy, LOAD_TEST_URL, timeout, "cfg", method="GET")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(one) for _ in range(requests)]
        for fut in as_completed(futs):
            tr = fut.result()
            if tr.ok:
                ms = ms_from_time_total(tr.time_total)
                if ms is not None:
                    times.append(ms)
            elif tr.error:
                errors.append(tr.error)

    ok_count = len(times)
    rate = ok_count / requests if requests else 0.0
    avg = int(round(sum(times) / len(times))) if times else None
    mn = min(times) if times else None
    return LoadResult(
        enabled=True,
        ok=ok_count == requests,
        ok_count=ok_count,
        total=requests,
        success_rate=rate,
        avg_ms=avg,
        min_ms=mn,
        error="; ".join(errors[:2]),
    )


def check_one(
    index: int,
    total: int,
    link: str,
    timeout: int,
    xray_bin: str,
    curl_bin: str,
    mode: str,
    service_workers: int,
    site_method: str,
    load_test: bool,
    load_requests: int,
    load_workers: int,
    load_required: bool,
    load_min_success_rate: float,
) -> LinkResult:
    started = time.time()
    cfg = ip = google = youtube = instagram = telegram = whatsapp = TestResult(False)
    load = LoadResult(enabled=load_test, ok=not load_required)
    name = ""
    err_parts: List[str] = []
    client_link = clean_client_link(link)

    socks_port = free_port()
    socks_user = f"u{index}"
    socks_pass = f"p{index}_{int(time.time() * 1000)}"
    proxy = f"socks5h://{socks_user}:{socks_pass}@127.0.0.1:{socks_port}"

    proc: Optional[subprocess.Popen] = None
    try:
        config, name = build_xray_config(link, socks_port, socks_user, socks_pass)
        with tempfile.TemporaryDirectory(prefix="vless_check_") as td:
            config_path = Path(td) / "config.json"
            config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
            proc = subprocess.Popen(
                [xray_bin, "run", "-config", str(config_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if not wait_port("127.0.0.1", socks_port, proc, timeout=4.0):
                out, e = proc.communicate(timeout=2) if proc.poll() is not None else (b"", b"")
                msg = decode_output(e or out).strip() or "xray did not open SOCKS port"
                raise RuntimeError(msg)

            cfg = curl_test(curl_bin, proxy, CFG_LATENCY_URL, timeout, "cfg", method="GET")
            ip = curl_test(curl_bin, proxy, DEFAULT_TESTS["ip"], timeout, "ip", method="GET")

            # If the tunnel itself does not work, skip the service tests.
            if cfg.ok and ip.ok:
                method = "HEAD" if site_method.upper() == "HEAD" else "GET"
                specs = [
                    ("google", DEFAULT_TESTS["google"], "google"),
                    ("youtube", DEFAULT_TESTS["youtube"], "youtube"),
                    ("instagram", DEFAULT_TESTS["instagram"], "instagram"),
                    ("telegram", DEFAULT_TESTS["telegram"], "telegram"),
                    ("whatsapp", DEFAULT_TESTS["whatsapp"], "whatsapp"),
                ]
                results: Dict[str, TestResult] = {}
                with ThreadPoolExecutor(max_workers=max(1, service_workers)) as ex:
                    futs = {
                        ex.submit(curl_test, curl_bin, proxy, url, timeout, kind, method): key
                        for key, url, kind in specs
                    }
                    for fut in as_completed(futs):
                        results[futs[fut]] = fut.result()

                google = results.get("google", google)
                youtube = results.get("youtube", youtube)
                instagram = results.get("instagram", instagram)
                telegram = results.get("telegram", telegram)
                whatsapp = results.get("whatsapp", whatsapp)

                if load_test:
                    load = run_load_test(curl_bin, proxy, timeout, load_requests, load_workers)
            else:
                if cfg.error:
                    err_parts.append(cfg.error)
                if ip.error:
                    err_parts.append(ip.error)

    except Exception as e:
        err_parts.append(str(e))
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    cfg_ms = ms_from_time_total(cfg.time_total)

    required_ok = cfg.ok and ip.ok and google.ok and youtube.ok
    if mode == "normal":
        required_ok = required_ok and instagram.ok and telegram.ok and whatsapp.ok
    # light mode: Instagram/Telegram/WhatsApp are diagnostic only.

    if load_test and load_required:
        required_ok = required_ok and load.success_rate >= load_min_success_rate

    for tr in [cfg, ip, google, youtube, instagram, telegram, whatsapp]:
        if tr.error and tr.error not in err_parts:
            err_parts.append(tr.error)
    if load.error and load.error not in err_parts:
        err_parts.append(load.error)

    return LinkResult(
        index=index,
        name=name,
        link=link,
        client_link=client_link,
        ok=required_ok,
        cfg_ok=cfg.ok,
        ip_ok=ip.ok,
        google_ok=google.ok,
        youtube_ok=youtube.ok,
        instagram_ok=instagram.ok,
        telegram_ok=telegram.ok,
        whatsapp_ok=whatsapp.ok,
        cfg_http=cfg.http_code,
        ip_http=ip.http_code,
        google_http=google.http_code,
        youtube_http=youtube.http_code,
        instagram_http=instagram.http_code,
        telegram_http=telegram.http_code,
        whatsapp_http=whatsapp.http_code,
        cfg_ms=cfg_ms,
        load=load,
        error="; ".join(x for x in err_parts if x)[:1000],
        elapsed=time.time() - started,
    )


def sort_results(results: List[LinkResult]) -> List[LinkResult]:
    return sorted(results, key=lambda r: (r.cfg_ms is None, r.cfg_ms if r.cfg_ms is not None else 10**9, r.index))


def write_links(path: Path, rows: List[LinkResult]) -> None:
    rows = sort_results(rows)
    path.write_text("\n".join(r.client_link for r in rows) + ("\n" if rows else ""), encoding="utf-8")


def write_csv(path: Path, rows: List[LinkResult]) -> None:
    rows = sort_results(rows)
    fields = [
        "ok",
        "index",
        "name",
        "cfg_ms",
        "cfg_ok",
        "cfg_http",
        "ip_ok",
        "ip_http",
        "google_ok",
        "google_http",
        "youtube_ok",
        "youtube_http",
        "instagram_ok",
        "instagram_http",
        "telegram_ok",
        "telegram_http",
        "whatsapp_ok",
        "whatsapp_http",
        "load_enabled",
        "load_ok",
        "load_ok_count",
        "load_total",
        "load_success_rate",
        "load_avg_ms",
        "load_min_ms",
        "elapsed_sec",
        "error",
        "link",
        "client_link",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow(
                {
                    "ok": int(r.ok),
                    "index": r.index,
                    "name": r.name,
                    "cfg_ms": r.cfg_ms if r.cfg_ms is not None else "",
                    "cfg_ok": int(r.cfg_ok),
                    "cfg_http": r.cfg_http,
                    "ip_ok": int(r.ip_ok),
                    "ip_http": r.ip_http,
                    "google_ok": int(r.google_ok),
                    "google_http": r.google_http,
                    "youtube_ok": int(r.youtube_ok),
                    "youtube_http": r.youtube_http,
                    "instagram_ok": int(r.instagram_ok),
                    "instagram_http": r.instagram_http,
                    "telegram_ok": int(r.telegram_ok),
                    "telegram_http": r.telegram_http,
                    "whatsapp_ok": int(r.whatsapp_ok),
                    "whatsapp_http": r.whatsapp_http,
                    "load_enabled": int(r.load.enabled),
                    "load_ok": int(r.load.ok),
                    "load_ok_count": r.load.ok_count,
                    "load_total": r.load.total,
                    "load_success_rate": f"{r.load.success_rate:.3f}" if r.load.enabled else "",
                    "load_avg_ms": r.load.avg_ms if r.load.avg_ms is not None else "",
                    "load_min_ms": r.load.min_ms if r.load.min_ms is not None else "",
                    "elapsed_sec": f"{r.elapsed:.2f}",
                    "error": r.error,
                    "link": r.link,
                    "client_link": r.client_link,
                }
            )


def choose_source() -> Tuple[str, str, Optional[str]]:
    print("Choose VLESS source:")
    print("  1) CIDR")
    print("  2) SNI")
    print("  3) CIDR_checked")
    print("  4) Enter custom URL, local file path or direct vless:// link")
    while True:
        choice = input("Select source [1-4]: ").strip()
        if choice in PRESET_SOURCES:
            item = PRESET_SOURCES[choice]
            return item["url"], item["name"], item["local_file"]
        if choice == "4":
            src = input("Enter URL, local file path or vless:// link: ").strip()
            return src, "custom", None
        print("Invalid choice. Enter 1, 2, 3 or 4.")


def choose_mode() -> str:
    print("Choose check mode:")
    print("  1) normal - strict: IP + Google + YouTube + Instagram + Telegram + WhatsApp")
    print("  2) light  - soft: IP + Google + YouTube; other services are shown but not required")
    while True:
        choice = input("Select mode [1-2]: ").strip()
        if choice == "1":
            return "normal"
        if choice == "2":
            return "light"
        print("Invalid choice. Enter 1 or 2.")


def find_binary(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    if platform.system().lower() == "windows" and not name.endswith(".exe"):
        return shutil.which(name + ".exe")
    return None


def main() -> int:
    ap = argparse.ArgumentParser(description="Check VLESS links from txt/URL/direct link")
    ap.add_argument("--input", "-i", help="local file, URL, subscription, or direct vless:// link")
    ap.add_argument("--local-dir", default=str(default_local_dir()), help="local fallback directory for preset txt files")
    ap.add_argument("--output", "-o", help="CSV result path")
    ap.add_argument("--working-output", help="TXT with working clean client links")
    ap.add_argument("--workers", "-w", type=int, default=12, help="parallel xray processes")
    ap.add_argument("--service-workers", type=int, default=6, help="parallel service checks inside one config")
    ap.add_argument("--timeout", "-t", type=int, default=8, help="per-request timeout seconds")
    ap.add_argument("--limit", type=int, default=0, help="check only first N links; 0 = all")
    ap.add_argument("--offset", type=int, default=0, help="skip first N links")
    ap.add_argument("--mode", choices=["normal", "light"], help="check mode")
    ap.add_argument("--site-method", choices=["HEAD", "GET"], default="HEAD", help="method for site checks")
    ap.add_argument("--no-head", action="store_true", help="use GET instead of HEAD for site checks")
    ap.add_argument("--show-links", action="store_true", help="print full VLESS links in console; unsafe for public logs")
    ap.add_argument("--save-failed", action="store_true", help="save failed rows to CSV too")
    ap.add_argument("--raw-output", action="store_true", help="write original links instead of clean client links")
    ap.add_argument("--load-test", action="store_true", help="enable soft load test with lightweight generate_204 requests")
    ap.add_argument("--load-requests", type=int, default=10, help="load-test request count")
    ap.add_argument("--load-workers", type=int, default=3, help="load-test parallel requests")
    ap.add_argument("--load-required", action="store_true", help="require load-test success to save link")
    ap.add_argument("--load-min-success-rate", type=float, default=0.8, help="required load success rate if --load-required")
    args = ap.parse_args()

    local_dir = Path(args.local_dir).expanduser()
    source_name = "custom"
    local_fallback: Optional[str] = None

    if args.input:
        source = args.input.strip()
        for item in PRESET_SOURCES.values():
            if source == item["url"] or github_blob_to_raw(source) == github_blob_to_raw(item["url"]):
                source_name = item["name"]
                local_fallback = item["local_file"]
                break
        if source.lower().startswith("vless://"):
            source_name = "single"
    else:
        source, source_name, local_fallback = choose_source()

    mode = args.mode or choose_mode()
    site_method = "GET" if args.no_head else args.site_method

    xray_bin = find_binary("xray")
    curl_bin = find_binary("curl")
    if not xray_bin:
        print("ERROR: xray not found in PATH. Install xray-core first.", file=sys.stderr)
        return 2
    if not curl_bin:
        print("ERROR: curl not found in PATH.", file=sys.stderr)
        return 2

    try:
        text = read_input(source, local_fallback=local_fallback, local_source_dir=local_dir)
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    links = extract_vless_links(text)
    total_in_source = len(links)
    if args.offset and args.offset > 0:
        links = links[args.offset :]
    if args.limit and args.limit > 0:
        links = links[: args.limit]

    if not links:
        print("ERROR: no vless:// links found. If this is a subscription, make sure it is plain text or base64.", file=sys.stderr)
        return 1

    suffix = safe_filename_part(f"{source_name}_{mode}")
    output = Path(args.output) if args.output else Path(f"vless_check_results_{suffix}.csv")
    working_output = Path(args.working_output) if args.working_output else Path(f"working_vless_{suffix}.txt")

    print(f"Selected mode: {mode}")
    log(
        f"Found {len(links)} VLESS links, source={source_name}. Total in source: {total_in_source}. "
        f"Checking with workers={args.workers}, service_workers={args.service_workers}, "
        f"timeout={args.timeout}s, mode={mode}, site_method={site_method}"
    )
    if args.load_test:
        log(
            f"Load test enabled: requests={args.load_requests}, workers={args.load_workers}, "
            f"required={args.load_required}"
        )

    results: List[LinkResult] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {
            ex.submit(
                check_one,
                i,
                len(links),
                link,
                args.timeout,
                xray_bin,
                curl_bin,
                mode,
                args.service_workers,
                site_method,
                args.load_test,
                args.load_requests,
                args.load_workers,
                args.load_required,
                args.load_min_success_rate,
            ): (i, link)
            for i, link in enumerate(links, start=1)
        }
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            shown = r.link if args.show_links else mask_link(r.link)
            status_plain = "OK" if r.ok else "FAIL"
            status = colorize_status(status_plain)
            cfg_s = f"{r.cfg_ms}ms" if r.cfg_ms is not None else "-ms"
            load_s = ""
            if args.load_test:
                if r.load.total:
                    load_s = f" load={r.load.ok_count}/{r.load.total}({int(round(r.load.success_rate * 100))}%"
                    if r.load.avg_ms is not None:
                        load_s += f" avg={r.load.avg_ms}ms"
                    load_s += ")"
                else:
                    load_s = " load=0/0(0%)"
            log(
                f"[{r.index}/{len(links)}] {status} cfg={cfg_s}{load_s} "
                f"ip={int(r.ip_ok)}({r.ip_http}) g={int(r.google_ok)}({r.google_http}) "
                f"yt={int(r.youtube_ok)}({r.youtube_http}) ig={int(r.instagram_ok)}({r.instagram_http}) "
                f"tg={int(r.telegram_ok)}({r.telegram_http}) wa={int(r.whatsapp_ok)}({r.whatsapp_http}) {shown}"
                + (f" | {r.error}" if r.error else "")
            )

    working_results = [r for r in results if r.ok]

    # If raw-output is requested, override client_link before writing links only.
    if args.raw_output:
        for r in results:
            r.client_link = r.link

    write_links(working_output, working_results)
    write_csv(output, results if args.save_failed else working_results)

    total = len(results)
    all_ok = len(working_results)
    cfg_ok = sum(1 for r in results if r.cfg_ok)
    ip_ok = sum(1 for r in results if r.ip_ok)
    google_ok = sum(1 for r in results if r.google_ok)
    yt_ok = sum(1 for r in results if r.youtube_ok)
    ig_ok = sum(1 for r in results if r.instagram_ok)
    tg_ok = sum(1 for r in results if r.telegram_ok)
    wa_ok = sum(1 for r in results if r.whatsapp_ok)
    fastest = min((r.cfg_ms for r in working_results if r.cfg_ms is not None), default=None)

    print("\nSummary")
    print(f"  total checked:   {total}")
    print(f"  working saved:   {all_ok}")
    print(f"  mode:            {mode}")
    print(f"  cfg ok:          {cfg_ok}")
    print(f"  vless/ip ok:     {ip_ok}")
    print(f"  google ok:       {google_ok}")
    print(f"  youtube ok:      {yt_ok}")
    print(f"  instagram ok:    {ig_ok}")
    print(f"  telegram ok:     {tg_ok}")
    print(f"  whatsapp ok:     {wa_ok}")
    if fastest is not None:
        print(f"  fastest cfg:     {fastest} ms")
    print("  sort:            fastest configs first by gstatic generate_204 latency")
    print(f"  local dir:       {local_dir}")
    print(f"  txt working:     {working_output} (clean client links)")
    print(f"  csv:             {output}" + (" (all results)" if args.save_failed else " (working only)"))

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
