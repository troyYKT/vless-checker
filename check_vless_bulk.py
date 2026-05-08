#!/usr/bin/env python3
"""
Bulk VLESS checker.

What this version is optimized for:
- fewer false OK results under blocking/unstable networks
- real website checks by default, not only tiny generate_204/favicon probes
- confirmation runs: a config must pass more than once before being saved
- lower default concurrency to avoid overloading your Mac/network/proxy
- GitHub download fallback that survives macOS Python CA problems
- safer parsing of messy public VLESS lists, including type=raw and broken headerType=none",,

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
import ssl
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
from typing import Dict, Iterable, List, Optional, Tuple

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
    # Old/fast probes. Use with --profile probe if you want the previous behavior.
    "google_probe": "https://www.google.com/generate_204",
    "youtube_probe": "https://www.youtube.com/generate_204",
    "instagram_probe": "https://www.instagram.com/favicon.ico",
    "telegram_probe": "https://telegram.org/favicon.ico",
    "whatsapp_probe": "https://www.whatsapp.com/favicon.ico",
    # Real checks. These are intentionally heavier than generate_204/favicon.
    # They filter configs that pass a tiny request but do not open real pages.
    "google_real": "https://www.google.com/search?q=vless-check",
    "youtube_real": "https://www.youtube.com/",
    "instagram_real": "https://www.instagram.com/",
    "telegram_real": "https://telegram.org/",
    "whatsapp_real": "https://www.whatsapp.com/",
}

PRESET_SOURCES = {
    "1": {
        "name": "CIDR",
        "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
        "local_file": "WHITE-CIDR-RU-all.txt",
    },
    "2": {
        "name": "SNI",
        "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
        "local_file": "WHITE-SNI-RU-all.txt",
    },
    "3": {
        "name": "CIDR_checked",
        "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
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
    size_download: int = 0
    body_preview: str = ""
    error: str = ""

    @property
    def ms(self) -> Optional[int]:
        try:
            return int(round(float(str(self.time_total).replace(",", ".")) * 1000))
        except Exception:
            return None


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
    cfg_bytes: int
    ip_bytes: int
    google_bytes: int
    youtube_bytes: int
    instagram_bytes: int
    telegram_bytes: int
    whatsapp_bytes: int
    stable_ok_count: int
    stable_total: int
    load: LoadResult
    ip_body: str
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


def safe_filename_part(value: Optional[str]) -> str:
    value = value or "custom"
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


def fallback_candidates(local_source_dir: Path, fallback_name: str) -> List[Path]:
    candidates = [
        local_source_dir.expanduser() / fallback_name,
        SCRIPT_DIR / fallback_name,
        Path.cwd() / fallback_name,
    ]
    seen = set()
    out: List[Path] = []
    for p in candidates:
        key = str(p.expanduser())
        if key not in seen:
            seen.add(key)
            out.append(p)
    return out


def read_input(
    source: str,
    timeout: int = 30,
    local_fallback: Optional[str] = None,
    local_source_dir: Optional[Path] = None,
    retry_insecure_download: bool = True,
) -> str:
    source = str(source).strip().strip('"\'')
    if source.lower().startswith("vless://"):
        return source + "\n"

    local_source_dir = (local_source_dir or default_local_dir()).expanduser()

    if re.match(r"^https?://", source, re.I):
        url = github_blob_to_raw(source)
        fallback_name = local_fallback or url_basename_for_cache(url)
        primary_fallback = local_source_dir / fallback_name
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})

        def fetch(context=None) -> str:
            with urllib.request.urlopen(req, timeout=timeout, context=context) as resp:
                data = resp.read()
            return data.decode("utf-8", errors="replace")

        try:
            log(f"Downloading source: {url}")
            try:
                text = fetch()
            except Exception as first_error:
                if "CERTIFICATE_VERIFY_FAILED" not in str(first_error):
                    raise
                try:
                    import certifi  # type: ignore

                    text = fetch(ssl.create_default_context(cafile=certifi.where()))
                except Exception:
                    if not retry_insecure_download:
                        raise first_error
                    log("Download TLS verification failed; retrying without certificate verification")
                    text = fetch(ssl._create_unverified_context())
            try:
                primary_fallback.parent.mkdir(parents=True, exist_ok=True)
                primary_fallback.write_text(text, encoding="utf-8")
                log(f"Saved/updated local copy: {primary_fallback}")
            except Exception as e:
                log(f"Warning: could not save local copy {primary_fallback}: {e}")
            return text
        except Exception as e:
            log(f"Download failed: {e}")
            for p in fallback_candidates(local_source_dir, fallback_name):
                if p.exists():
                    log(f"Using local fallback: {p}")
                    return p.read_text(encoding="utf-8", errors="replace")
            tried = ", ".join(str(p) for p in fallback_candidates(local_source_dir, fallback_name))
            raise RuntimeError(f"Could not download {url} and local fallback was not found. Checked: {tried}") from e

    path = Path(source).expanduser()
    if not path.exists() and not path.is_absolute():
        for candidate in (local_source_dir / source, SCRIPT_DIR / source, Path.cwd() / source):
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


def normalize_vless_link(raw: str) -> str:
    # Some public lists contain JSON/CSV leftovers after a link: vless://...",,
    link = raw.strip().strip('"\'')
    while link and link[-1] in {",", ";", "]", "}", ")", "'", '"'}:
        link = link[:-1].strip()
    return link


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
            link = normalize_vless_link(line)
            if link not in seen:
                seen.add(link)
                links.append(link)
            continue
        for m in re.finditer(r"vless://[^\s<'\"]+", line, flags=re.I):
            link = normalize_vless_link(m.group(0))
            if link not in seen:
                seen.add(link)
                links.append(link)
    return links


def free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def wait_port(host: str, port: int, proc: subprocess.Popen, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with socket.create_connection((host, port), timeout=0.25):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def sanitize_q_value(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    s = str(value)
    for _ in range(3):
        decoded = urllib.parse.unquote(s)
        if decoded == s:
            break
        s = decoded
    s = s.strip().strip('"\'')
    s = re.sub(r"[\\'\",;]+$", "", s).strip()
    return s


def qget(q: Dict[str, List[str]], key: str, default: Optional[str] = None) -> Optional[str]:
    value = q.get(key, [default])[0]
    return sanitize_q_value(value)


def normalize_none_value(value: Optional[str]) -> str:
    v = (sanitize_q_value(value) or "none").strip().lower()
    if v.startswith("none"):
        return "none"
    return v


def bool_q(value: Optional[str]) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def split_csv(value: Optional[str]) -> Optional[List[str]]:
    if not value:
        return None
    return [x.strip() for x in re.split(r"[,;]", value) if x.strip()]


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

    raw_network = (qget(q, "type", "tcp") or "tcp").lower()
    network = "tcp" if raw_network == "raw" else raw_network
    security = normalize_none_value(qget(q, "security", "none"))
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
        # Keep unsupported security as-is; xray will report details.
        pass

    if network == "tcp":
        header_type = normalize_none_value(qget(q, "headerType", "none"))
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
        stream["kcpSettings"] = {"header": {"type": normalize_none_value(qget(q, "headerType", "none"))}}

    elif network == "quic":
        stream["quicSettings"] = {
            "security": normalize_none_value(qget(q, "quicSecurity", "none")),
            "key": qget(q, "key", "") or "",
            "header": {"type": normalize_none_value(qget(q, "headerType", "none"))},
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
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
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
                value = sanitize_q_value(q[alias][0])
                break
        if value is None:
            value = default
        if value is not None and (always or value != ""):
            out.append((target_key, value))
    query = urllib.parse.urlencode(out, doseq=False, safe="/,:@")
    return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, parsed.fragment))


def mask_link(url: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() != "vless":
            return url
        host = parsed.hostname or "host"
        port = f":{parsed.port}" if parsed.port else ""
        frag = f"#{urllib.parse.unquote(parsed.fragment)}" if parsed.fragment else ""
        return f"vless://***@{host}{port}{frag}"
    except Exception:
        return "vless://***"


def ms_from_time_total(value: str) -> Optional[int]:
    try:
        return int(round(float(str(value).replace(",", ".")) * 1000))
    except Exception:
        return None


def http_ok(code: str, kind: str) -> bool:
    try:
        c = int(code)
    except Exception:
        return False
    if kind in {"ip", "cfg", "real"}:
        return 200 <= c < 400
    if kind == "probe":
        return 200 <= c < 500
    return 200 <= c < 400


def parse_curl_output(stdout: str, stderr: str) -> Tuple[str, str, int, str, str]:
    combined = f"{stdout}\n{stderr}"
    marker = "\n__CURL_META__"
    body = stdout
    meta = ""
    if marker in stdout:
        body, meta = stdout.rsplit(marker, 1)
    else:
        m = re.search(r"__CURL_META__(.*)$", combined, flags=re.S)
        if m:
            meta = m.group(1)

    http_code = "000"
    time_total = ""
    size_download = 0
    parts = meta.strip().split()
    if parts:
        http_code = parts[0]
    if len(parts) > 1:
        time_total = parts[1]
    if len(parts) > 2:
        try:
            size_download = int(float(parts[2]))
        except Exception:
            size_download = 0

    cleaned = re.sub(r"__CURL_META__.*$", "", combined, flags=re.S).strip()
    preview = re.sub(r"\s+", " ", body.strip())[:180]
    return http_code, time_total, size_download, preview, cleaned


def curl_test(
    curl_bin: str,
    proxy: str,
    url: str,
    timeout: int,
    kind: str,
    *,
    method: str = "GET",
    min_bytes: int = 0,
    capture_body: bool = False,
) -> TestResult:
    fmt = "\n__CURL_META__%{http_code} %{time_total} %{size_download}"
    cmd = [
        curl_bin,
        "--silent",
        "--show-error",
        "--location",
        "--max-redirs",
        "3",
        "--connect-timeout",
        str(timeout),
        "--max-time",
        str(timeout),
        "--proxy",
        proxy,
        "--user-agent",
        USER_AGENT,
        "--output",
        "-" if capture_body else os.devnull,
        "--write-out",
        fmt,
    ]
    if method.upper() == "HEAD":
        cmd.append("--head")
    cmd.append(url)

    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 4)
    except subprocess.TimeoutExpired:
        return TestResult(ok=False, error=f"curl process timed out after {timeout + 4}s")
    except Exception as e:
        return TestResult(ok=False, error=str(e))

    stdout = decode_output(proc.stdout)
    stderr = decode_output(proc.stderr)
    code, tt, size_download, preview, cleaned = parse_curl_output(stdout, stderr)
    ok = proc.returncode == 0 and http_ok(code, kind) and size_download >= min_bytes
    error = ""
    if not ok:
        if proc.returncode == 0 and http_ok(code, kind) and size_download < min_bytes:
            error = f"downloaded only {size_download} bytes, expected at least {min_bytes}"
        elif cleaned:
            error = cleaned
        else:
            error = f"curl return code {proc.returncode}"
    return TestResult(ok=ok, http_code=code, time_total=tt, size_download=size_download, body_preview=preview, error=error)


def service_specs(profile: str) -> List[Tuple[str, str, str, int]]:
    """Return (result_key, url, curl_kind, min_download_bytes)."""
    if profile == "probe":
        return [
            ("google", DEFAULT_TESTS["google_probe"], "probe", 0),
            ("youtube", DEFAULT_TESTS["youtube_probe"], "probe", 0),
            ("instagram", DEFAULT_TESTS["instagram_probe"], "probe", 0),
            ("telegram", DEFAULT_TESTS["telegram_probe"], "probe", 0),
            ("whatsapp", DEFAULT_TESTS["whatsapp_probe"], "probe", 0),
        ]
    return [
        ("google", DEFAULT_TESTS["google_real"], "real", 1500),
        ("youtube", DEFAULT_TESTS["youtube_real"], "real", 20000),
        ("instagram", DEFAULT_TESTS["instagram_real"], "real", 1500),
        ("telegram", DEFAULT_TESTS["telegram_real"], "real", 3000),
        ("whatsapp", DEFAULT_TESTS["whatsapp_real"], "real", 3000),
    ]


def run_load_test(curl_bin: str, proxy: str, timeout: int, requests: int, workers: int) -> LoadResult:
    requests = max(1, requests)
    workers = max(1, min(workers, requests))
    times: List[int] = []
    errors: List[str] = []

    def one() -> TestResult:
        return curl_test(curl_bin, proxy, LOAD_TEST_URL, timeout, "cfg", method="GET")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = [ex.submit(one) for _ in range(requests)]
        for fut in as_completed(futures):
            tr = fut.result()
            if tr.ok and tr.ms is not None:
                times.append(tr.ms)
            elif tr.error:
                errors.append(tr.error)

    ok_count = len(times)
    return LoadResult(
        enabled=True,
        ok=ok_count == requests,
        ok_count=ok_count,
        total=requests,
        success_rate=ok_count / requests if requests else 0.0,
        avg_ms=int(round(sum(times) / len(times))) if times else None,
        min_ms=min(times) if times else None,
        error="; ".join(errors[:2]),
    )


def empty_suite() -> Dict[str, TestResult]:
    return {
        "cfg": TestResult(False),
        "ip": TestResult(False),
        "google": TestResult(False),
        "youtube": TestResult(False),
        "instagram": TestResult(False),
        "telegram": TestResult(False),
        "whatsapp": TestResult(False),
    }


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
    profile: str,
    confirm_runs: int,
    max_cfg_ms: int,
    load_test: bool,
    load_requests: int,
    load_workers: int,
    load_required: bool,
    load_min_success_rate: float,
) -> LinkResult:
    del total
    started = time.time()
    name = f"link-{index}"
    client_link = clean_client_link(link)
    load = LoadResult(enabled=load_test, ok=not load_required)
    err_parts: List[str] = []
    stable_ok_count = 0
    stable_total = max(1, confirm_runs)

    socks_port = free_port()
    socks_user = f"u{os.getpid()}_{index}"
    socks_pass = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
    proxy = f"socks5h://{urllib.parse.quote(socks_user)}:{urllib.parse.quote(socks_pass)}@127.0.0.1:{socks_port}"

    def required_ok(suite: Dict[str, TestResult]) -> bool:
        required = suite["cfg"].ok and suite["ip"].ok and suite["google"].ok and suite["youtube"].ok
        if mode == "normal":
            required = required and suite["instagram"].ok and suite["telegram"].ok and suite["whatsapp"].ok
        return required

    def add_suite_errors(suite: Dict[str, TestResult], prefix: str = "") -> None:
        for key in ["cfg", "ip", "google", "youtube", "instagram", "telegram", "whatsapp"]:
            tr = suite[key]
            if tr.error:
                msg = f"{prefix}{key}: {tr.error}" if prefix else f"{key}: {tr.error}"
                if msg not in err_parts:
                    err_parts.append(msg)

    def run_suite() -> Dict[str, TestResult]:
        suite = empty_suite()
        suite["cfg"] = curl_test(curl_bin, proxy, CFG_LATENCY_URL, timeout, "cfg", method="GET")
        cfg_ms = suite["cfg"].ms
        if max_cfg_ms > 0 and cfg_ms is not None and cfg_ms > max_cfg_ms:
            suite["cfg"].ok = False
            suite["cfg"].error = f"cfg latency {cfg_ms}ms > limit {max_cfg_ms}ms"
        if not suite["cfg"].ok:
            return suite

        suite["ip"] = curl_test(
            curl_bin,
            proxy,
            DEFAULT_TESTS["ip"],
            timeout,
            "ip",
            method="GET",
            capture_body=True,
        )
        if not suite["ip"].ok:
            return suite

        method = "HEAD" if site_method.upper() == "HEAD" else "GET"
        workers = max(1, min(service_workers, 5))
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {
                ex.submit(curl_test, curl_bin, proxy, url, timeout, kind, method=method, min_bytes=min_bytes): key
                for key, url, kind, min_bytes in service_specs(profile)
            }
            for fut in as_completed(futs):
                suite[futs[fut]] = fut.result()
        return suite

    first_suite = empty_suite()
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
            if not wait_port("127.0.0.1", socks_port, proc, timeout=5.0):
                err_text = ""
                if proc.poll() is not None:
                    try:
                        out, err = proc.communicate(timeout=2)
                        err_text = decode_output(err or out).strip()
                    except Exception:
                        err_text = ""
                raise RuntimeError(err_text or "xray did not open SOCKS port")

            first_suite = run_suite()
            if required_ok(first_suite):
                stable_ok_count = 1
                for pass_no in range(2, stable_total + 1):
                    confirm_suite = run_suite()
                    if required_ok(confirm_suite):
                        stable_ok_count += 1
                    else:
                        add_suite_errors(confirm_suite, prefix=f"confirm pass {pass_no}: ")
                        break
                if load_test:
                    load = run_load_test(curl_bin, proxy, timeout, load_requests, load_workers)
            else:
                add_suite_errors(first_suite)

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

    if load_test and load_required and load.success_rate < load_min_success_rate:
        err_parts.append(f"load success rate {load.success_rate:.0%} < required {load_min_success_rate:.0%}")

    ok = stable_ok_count >= stable_total
    if load_test and load_required:
        ok = ok and load.success_rate >= load_min_success_rate

    cfg = first_suite["cfg"]
    ip = first_suite["ip"]
    google = first_suite["google"]
    youtube = first_suite["youtube"]
    instagram = first_suite["instagram"]
    telegram = first_suite["telegram"]
    whatsapp = first_suite["whatsapp"]

    return LinkResult(
        index=index,
        name=name,
        link=link,
        client_link=client_link,
        ok=ok,
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
        cfg_ms=cfg.ms,
        cfg_bytes=cfg.size_download,
        ip_bytes=ip.size_download,
        google_bytes=google.size_download,
        youtube_bytes=youtube.size_download,
        instagram_bytes=instagram.size_download,
        telegram_bytes=telegram.size_download,
        whatsapp_bytes=whatsapp.size_download,
        stable_ok_count=stable_ok_count,
        stable_total=stable_total,
        load=load,
        ip_body=ip.body_preview,
        error="; ".join(x for x in err_parts if x)[:1200],
        elapsed=time.time() - started,
    )


def result_sort_key(r: LinkResult) -> Tuple[int, int, int]:
    return (0 if r.cfg_ms is not None else 1, r.cfg_ms if r.cfg_ms is not None else 10**9, r.index)


def write_links(path: Path, rows: Iterable[LinkResult], clean_links: bool = True) -> None:
    sorted_rows = sorted(rows, key=result_sort_key)
    with path.open("w", encoding="utf-8") as f:
        for r in sorted_rows:
            f.write((r.client_link if clean_links else r.link.rstrip()) + "\n")


def write_csv(path: Path, rows: Iterable[LinkResult], clean_links: bool = True) -> None:
    sorted_rows = sorted(rows, key=result_sort_key)
    fields = [
        "ok",
        "index",
        "name",
        "cfg_ms",
        "stable_ok_count",
        "stable_total",
        "cfg_ok",
        "cfg_http",
        "cfg_bytes",
        "ip_ok",
        "ip_http",
        "ip_bytes",
        "ip_body",
        "google_ok",
        "google_http",
        "google_bytes",
        "youtube_ok",
        "youtube_http",
        "youtube_bytes",
        "instagram_ok",
        "instagram_http",
        "instagram_bytes",
        "telegram_ok",
        "telegram_http",
        "telegram_bytes",
        "whatsapp_ok",
        "whatsapp_http",
        "whatsapp_bytes",
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
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for r in sorted_rows:
            writer.writerow(
                {
                    "ok": int(r.ok),
                    "index": r.index,
                    "name": r.name,
                    "cfg_ms": r.cfg_ms if r.cfg_ms is not None else "",
                    "stable_ok_count": r.stable_ok_count,
                    "stable_total": r.stable_total,
                    "cfg_ok": int(r.cfg_ok),
                    "cfg_http": r.cfg_http,
                    "cfg_bytes": r.cfg_bytes,
                    "ip_ok": int(r.ip_ok),
                    "ip_http": r.ip_http,
                    "ip_bytes": r.ip_bytes,
                    "ip_body": r.ip_body,
                    "google_ok": int(r.google_ok),
                    "google_http": r.google_http,
                    "google_bytes": r.google_bytes,
                    "youtube_ok": int(r.youtube_ok),
                    "youtube_http": r.youtube_http,
                    "youtube_bytes": r.youtube_bytes,
                    "instagram_ok": int(r.instagram_ok),
                    "instagram_http": r.instagram_http,
                    "instagram_bytes": r.instagram_bytes,
                    "telegram_ok": int(r.telegram_ok),
                    "telegram_http": r.telegram_http,
                    "telegram_bytes": r.telegram_bytes,
                    "whatsapp_ok": int(r.whatsapp_ok),
                    "whatsapp_http": r.whatsapp_http,
                    "whatsapp_bytes": r.whatsapp_bytes,
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
                    "client_link": r.client_link if clean_links else r.link,
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
            source = input("Enter URL, local file path or vless:// link: ").strip()
            return source, "custom", None
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
    ap = argparse.ArgumentParser(
        description="Check VLESS links with realistic site checks and confirmation runs"
    )
    ap.add_argument("--input", "-i", help="local file, URL, subscription, or direct vless:// link")
    ap.add_argument("--local-dir", default=str(default_local_dir()), help="local fallback/cache directory")
    ap.add_argument("--output", "-o", help="CSV result path")
    ap.add_argument("--working-output", help="TXT with working clean client links")
    ap.add_argument("--workers", "-w", type=int, default=6, help="parallel xray processes; default 6")
    ap.add_argument("--service-workers", type=int, default=3, help="parallel site checks inside one config; default 3")
    ap.add_argument("--timeout", "-t", type=int, default=12, help="per-request timeout seconds; default 12")
    ap.add_argument("--limit", type=int, default=0, help="check only first N links after offset; 0 = all")
    ap.add_argument("--offset", type=int, default=0, help="skip first N links")
    ap.add_argument("--mode", choices=["normal", "light"], help="check mode")
    ap.add_argument("--profile", choices=["real", "probe"], default="real", help="real = actual pages; probe = old generate_204/favicon checks")
    ap.add_argument("--confirm-runs", type=int, default=2, help="save only configs passing this many consecutive suites")
    ap.add_argument("--max-cfg-ms", type=int, default=5000, help="reject configs slower than this on gstatic; 0 disables")
    ap.add_argument("--site-method", choices=["HEAD", "GET"], default="GET", help="method for site checks; default GET")
    ap.add_argument("--no-head", action="store_true", help="compat alias: force GET for site checks")
    ap.add_argument("--show-links", action="store_true", help="print full VLESS links in console; unsafe for public logs")
    ap.add_argument("--save-failed", action="store_true", help="save failed rows to CSV too")
    ap.add_argument("--raw-output", action="store_true", help="write original links instead of clean client links")
    ap.add_argument("--strict-download-tls", action="store_true", help="do not retry GitHub download without TLS verification")
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
    confirm_runs = max(1, args.confirm_runs)

    xray_bin = find_binary("xray")
    curl_bin = find_binary("curl")
    if not xray_bin:
        print("ERROR: xray not found in PATH. Install xray-core first.", file=sys.stderr)
        return 2
    if not curl_bin:
        print("ERROR: curl not found in PATH.", file=sys.stderr)
        return 2

    try:
        text = read_input(
            source,
            local_fallback=local_fallback,
            local_source_dir=local_dir,
            retry_insecure_download=not args.strict_download_tls,
        )
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    links = extract_vless_links(text)
    total_in_source = len(links)
    if args.offset and args.offset > 0:
        links = links[args.offset:]
    if args.limit and args.limit > 0:
        links = links[: args.limit]

    if not links:
        print("ERROR: no vless:// links found. If this is a subscription, make sure it is plain text or base64.", file=sys.stderr)
        return 1

    suffix = safe_filename_part(f"{source_name}_{mode}_{args.profile}")
    output = Path(args.output) if args.output else Path(f"vless_check_results_{suffix}.csv")
    working_output = Path(args.working_output) if args.working_output else Path(f"working_vless_{suffix}.txt")

    print(f"Selected mode: {mode}")
    log(
        f"Found {len(links)} VLESS links, source={source_name}. Total in source: {total_in_source}. "
        f"Checking with workers={args.workers}, service_workers={args.service_workers}, "
        f"timeout={args.timeout}s, mode={mode}, profile={args.profile}, "
        f"confirm_runs={confirm_runs}, max_cfg_ms={args.max_cfg_ms}, site_method={site_method}"
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
                args.profile,
                confirm_runs,
                args.max_cfg_ms,
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
            stable_s = f" stable={r.stable_ok_count}/{r.stable_total}" if r.stable_total > 1 else ""
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
                f"[{r.index}/{len(links)}] {status} cfg={cfg_s}{stable_s}{load_s} "
                f"ip={int(r.ip_ok)}({r.ip_http}) g={int(r.google_ok)}({r.google_http}) "
                f"yt={int(r.youtube_ok)}({r.youtube_http}) ig={int(r.instagram_ok)}({r.instagram_http}) "
                f"tg={int(r.telegram_ok)}({r.telegram_http}) wa={int(r.whatsapp_ok)}({r.whatsapp_http}) {shown}"
                + (f" | {r.error}" if r.error else "")
            )

    working_results = [r for r in results if r.ok]
    if args.raw_output:
        for r in results:
            r.client_link = r.link

    write_links(working_output, working_results, clean_links=not args.raw_output)
    write_csv(output, results if args.save_failed else working_results, clean_links=not args.raw_output)

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
    print(f"  profile:         {args.profile}")
    print(f"  confirm runs:    {confirm_runs}")
    print(f"  max cfg ms:      {args.max_cfg_ms if args.max_cfg_ms > 0 else 'disabled'}")
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
    print(f"  txt working:     {working_output}" + (" (clean client links)" if not args.raw_output else " (raw links)"))
    print(f"  csv:             {output}" + (" (all results)" if args.save_failed else " (working only)"))

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
