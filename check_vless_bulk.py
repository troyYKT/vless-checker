#!/usr/bin/env python3
"""
Bulk VLESS checker.

The script launches xray-core as a temporary VLESS client for every link,
opens a local SOCKS proxy, and checks access through that proxy.

Built-in sources:
  1) CIDR         WHITE-CIDR-RU-all.txt
  2) SNI          WHITE-SNI-RU-all.txt
  3) CIDR checked WHITE-CIDR-RU-checked.txt

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
    body_preview: str = ""


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
    ip_body: str
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
    local_source_dir = local_source_dir or default_local_dir()

    if re.match(r"^https?://", source, re.I):
        url = github_blob_to_raw(source)
        fallback_name = local_fallback or url_basename_for_cache(url)
        fallback_paths = [local_source_dir / fallback_name, SCRIPT_DIR / fallback_name]

        try:
            log(f"Downloading source: {url}")
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            text = data.decode("utf-8", errors="replace")

            try:
                fallback_paths[0].parent.mkdir(parents=True, exist_ok=True)
                fallback_paths[0].write_text(text, encoding="utf-8")
                log(f"Saved/updated local copy: {fallback_paths[0]}")
            except Exception as e:
                log(f"Warning: could not save local copy {fallback_paths[0]}: {e}")
            return text
        except Exception as e:
            log(f"Download failed: {e}")
            for fp in fallback_paths:
                if fp.exists():
                    log(f"Using local fallback: {fp}")
                    return fp.read_text(encoding="utf-8", errors="replace")
            raise RuntimeError(
                "Could not download source and local fallback was not found. Checked: "
                + ", ".join(str(x) for x in fallback_paths)
            ) from e

    return Path(source).read_text(encoding="utf-8", errors="replace")


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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def wait_port(host: str, port: int, proc: subprocess.Popen, timeout: float = 5.0) -> bool:
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


def qget(q: Dict[str, List[str]], key: str, default=None):
    if key not in q:
        return default
    values = q.get(key) or []
    if not values:
        return default
    value = values[0]
    if value is None:
        return default
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
        header_type = qget(q, "headerType") or "none"
        if header_type and header_type != "none":
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
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }
    return config, name


def ms_from_time_total(value: str) -> Optional[int]:
    try:
        return int(round(float(value) * 1000))
    except Exception:
        return None


def curl_test(
    curl_bin: str,
    url: str,
    socks_port: int,
    socks_user: str,
    socks_pass: str,
    timeout: int,
    *,
    head: bool = False,
    capture_body: bool = False,
) -> TestResult:
    proxy = f"socks5h://{urllib.parse.quote(socks_user)}:{urllib.parse.quote(socks_pass)}@127.0.0.1:{socks_port}"
    fmt = "\n__CURL_META__%{http_code} %{time_total}"
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
        "-A",
        USER_AGENT,
    ]
    if head:
        cmd.append("--head")
    cmd += ["-o", "-" if capture_body else os.devnull, "-w", fmt, url]

    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False, timeout=timeout + 3)
    except subprocess.TimeoutExpired:
        return TestResult(ok=False, error="curl timeout")
    except Exception as e:
        return TestResult(ok=False, error=str(e))

    stdout = decode_output(p.stdout)
    stderr = decode_output(p.stderr).strip()
    http_code = "000"
    time_total = ""
    body = stdout

    # Robust parsing for Windows curl/PowerShell and for HEAD responses.
    m = re.search(r"__CURL_META__(\d{3})\s+([0-9.]+)", stdout)
    if m:
        http_code = m.group(1)
        time_total = m.group(2)
        body = stdout[: m.start()]
    else:
        marker = "\n__CURL_META__"
        if marker in stdout:
            body, meta = stdout.rsplit(marker, 1)
            parts = meta.strip().split()
            if parts:
                http_code = parts[0]
            if len(parts) > 1:
                time_total = parts[1]

    ok = p.returncode == 0 and http_code != "000"
    err = stderr if p.returncode != 0 else ""
    preview = re.sub(r"\s+", " ", body.strip())[:180]
    return TestResult(ok=ok, http_code=http_code, time_total=time_total, error=err, body_preview=preview)


def run_load_test(
    curl_bin: str,
    socks_port: int,
    socks_user: str,
    socks_pass: str,
    timeout: int,
    requests: int,
    workers: int,
    min_success_rate: float,
) -> LoadResult:
    requests = max(1, requests)
    workers = max(1, min(workers, requests))
    times: List[int] = []
    errors: List[str] = []
    ok_count = 0

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [
            ex.submit(
                curl_test,
                curl_bin,
                LOAD_TEST_URL,
                socks_port,
                socks_user,
                socks_pass,
                timeout,
                head=True,
                capture_body=False,
            )
            for _ in range(requests)
        ]
        for fut in as_completed(futs):
            r = fut.result()
            if r.ok:
                ok_count += 1
                ms = ms_from_time_total(r.time_total)
                if ms is not None:
                    times.append(ms)
            elif r.error:
                errors.append(r.error)

    rate = ok_count / requests
    avg_ms = int(round(sum(times) / len(times))) if times else None
    min_ms = min(times) if times else None
    return LoadResult(
        enabled=True,
        ok=rate >= min_success_rate,
        ok_count=ok_count,
        total=requests,
        success_rate=rate,
        avg_ms=avg_ms,
        min_ms=min_ms,
        error="; ".join(errors[:3])[:300],
    )


def check_one(
    index: int,
    link: str,
    timeout: int,
    xray_bin: str,
    curl_bin: str,
    do_all_tests: bool,
    service_workers: int,
    use_head: bool,
    mode: str,
    load_test_enabled: bool,
    load_requests: int,
    load_workers: int,
    load_required: bool,
    load_min_success_rate: float,
) -> LinkResult:
    started = time.time()
    socks_port = free_port()
    socks_user = f"u{os.getpid()}_{index}"
    socks_pass = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
    name = f"link-{index}"
    proc: Optional[subprocess.Popen] = None

    def fail_result(err: str) -> LinkResult:
        return LinkResult(
            index=index, name=name, link=link, ok=False,
            cfg_ok=False, ip_ok=False, google_ok=False, youtube_ok=False, instagram_ok=False, telegram_ok=False, whatsapp_ok=False,
            cfg_http="000", ip_http="000", google_http="000", youtube_http="000", instagram_http="000", telegram_http="000", whatsapp_http="000",
            cfg_ms=None, ip_body="", load=LoadResult(enabled=load_test_enabled, ok=False if load_required else True),
            error=err[:500], elapsed=time.time() - started,
        )

    try:
        config, name = build_xray_config(link, socks_port, socks_user, socks_pass)
        with tempfile.TemporaryDirectory(prefix="vless-check-") as td:
            config_path = os.path.join(td, "config.json")
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False)

            proc = subprocess.Popen(
                [xray_bin, "run", "-config", config_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not wait_port("127.0.0.1", socks_port, proc, timeout=5.0):
                err = ""
                if proc.poll() is not None:
                    try:
                        _, err_bytes = proc.communicate(timeout=2)
                        err = decode_output(err_bytes).strip()
                    except Exception:
                        err = ""
                return fail_result(f"xray did not start/listen: {err[:300]}")

            cfg = curl_test(curl_bin, CFG_LATENCY_URL, socks_port, socks_user, socks_pass, timeout, head=True)
            ip = curl_test(curl_bin, DEFAULT_TESTS["ip"], socks_port, socks_user, socks_pass, timeout, capture_body=True)

            service_results: Dict[str, TestResult] = {
                "google": TestResult(False),
                "youtube": TestResult(False),
                "instagram": TestResult(False),
                "telegram": TestResult(False),
                "whatsapp": TestResult(False),
            }
            if ip.ok or do_all_tests:
                service_names = list(service_results.keys())
                max_service_workers = max(1, min(service_workers, len(service_names)))
                with ThreadPoolExecutor(max_workers=max_service_workers) as tex:
                    tfutures = {
                        tex.submit(
                            curl_test,
                            curl_bin,
                            DEFAULT_TESTS[svc],
                            socks_port,
                            socks_user,
                            socks_pass,
                            timeout,
                            head=use_head,
                            capture_body=False,
                        ): svc
                        for svc in service_names
                    }
                    for tfut in as_completed(tfutures):
                        service_results[tfutures[tfut]] = tfut.result()

            google = service_results["google"]
            yt = service_results["youtube"]
            ig = service_results["instagram"]
            tg = service_results["telegram"]
            wa = service_results["whatsapp"]

            load = LoadResult(enabled=False)
            if load_test_enabled and (ip.ok or do_all_tests):
                load = run_load_test(
                    curl_bin,
                    socks_port,
                    socks_user,
                    socks_pass,
                    timeout,
                    load_requests,
                    load_workers,
                    load_min_success_rate,
                )

            if mode == "light":
                ok = ip.ok and google.ok and yt.ok
            else:
                ok = ip.ok and google.ok and yt.ok and ig.ok and tg.ok and wa.ok
            if load_required and load_test_enabled:
                ok = ok and load.ok

            cfg_ms = ms_from_time_total(cfg.time_total)
            errors = [cfg.error, ip.error, google.error, yt.error, ig.error, tg.error, wa.error, load.error]
            err = "; ".join(x for x in errors if x)[:500]

            return LinkResult(
                index=index, name=name, link=link, ok=ok,
                cfg_ok=cfg.ok, ip_ok=ip.ok, google_ok=google.ok, youtube_ok=yt.ok,
                instagram_ok=ig.ok, telegram_ok=tg.ok, whatsapp_ok=wa.ok,
                cfg_http=cfg.http_code, ip_http=ip.http_code, google_http=google.http_code,
                youtube_http=yt.http_code, instagram_http=ig.http_code,
                telegram_http=tg.http_code, whatsapp_http=wa.http_code,
                cfg_ms=cfg_ms, ip_body=ip.body_preview, load=load,
                error=err, elapsed=time.time() - started,
            )

    except Exception as e:
        return fail_result(str(e))
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()


def mask_link(link: str) -> str:
    try:
        p = urllib.parse.urlsplit(link)
        host = p.hostname or "?"
        port = p.port or "?"
        frag = urllib.parse.unquote(p.fragment or "")
        return f"vless://***@{host}:{port}" + (f"#{frag}" if frag else "")
    except Exception:
        return link[:80]


def clean_vless_link(link: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(link.strip())
        if parsed.scheme.lower() != "vless":
            return link.strip()
        uuid = urllib.parse.unquote(parsed.username or "")
        host = parsed.hostname or ""
        port = parsed.port
        if not uuid or not host or not port:
            return link.strip()
        host_part = f"[{host}]" if ":" in host and not host.startswith("[") else host
        q = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        clean_params: List[Tuple[str, str]] = []
        for out_key, aliases, default, always in CLIENT_QUERY_ORDER:
            value = None
            found = False
            for alias in aliases:
                if alias in q:
                    value = qget(q, alias, "")
                    found = True
                    break
            if not found and always:
                value = default
                found = True
            if found and value is not None:
                clean_params.append((out_key, value))

        query = urllib.parse.urlencode(clean_params, doseq=False, safe=",-")
        name = urllib.parse.unquote(parsed.fragment or "") or host
        fragment = urllib.parse.quote(name, safe="")
        return f"vless://{urllib.parse.quote(uuid, safe='-')}@{host_part}:{port}?{query}#{fragment}"
    except Exception:
        return link.strip()


def sort_key_fastest(r: LinkResult):
    return (r.cfg_ms is None, r.cfg_ms if r.cfg_ms is not None else 10**12, r.index)


def write_csv(path: str, results: Iterable[LinkResult], clean_links: bool = True) -> None:
    rows = sorted(results, key=sort_key_fastest)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "index", "name", "all_ok", "mode_ok", "cfg_ok", "cfg_http", "cfg_ms",
            "vless_ip_ok", "google_ok", "youtube_ok", "instagram_ok", "telegram_ok", "whatsapp_ok",
            "ip_http", "google_http", "youtube_http", "instagram_http", "telegram_http", "whatsapp_http",
            "load_enabled", "load_ok", "load_ok_count", "load_total", "load_success_rate", "load_avg_ms", "load_min_ms",
            "ip_body", "elapsed_sec", "error", "link",
        ])
        for r in rows:
            w.writerow([
                r.index, r.name, int(r.ok), int(r.ok), int(r.cfg_ok), r.cfg_http, r.cfg_ms if r.cfg_ms is not None else "",
                int(r.ip_ok), int(r.google_ok), int(r.youtube_ok), int(r.instagram_ok), int(r.telegram_ok), int(r.whatsapp_ok),
                r.ip_http, r.google_http, r.youtube_http, r.instagram_http, r.telegram_http, r.whatsapp_http,
                int(r.load.enabled), int(r.load.ok), r.load.ok_count, r.load.total,
                f"{r.load.success_rate:.2f}" if r.load.enabled else "",
                r.load.avg_ms if r.load.avg_ms is not None else "",
                r.load.min_ms if r.load.min_ms is not None else "",
                r.ip_body, f"{r.elapsed:.2f}", r.error,
                clean_vless_link(r.link) if clean_links else r.link,
            ])


def write_links(path: str, results: Iterable[LinkResult], clean_links: bool = True) -> None:
    rows = sorted(results, key=sort_key_fastest)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            out_link = clean_vless_link(r.link) if clean_links else r.link.rstrip()
            f.write(out_link + "\n")


def choose_input_source() -> Tuple[str, Optional[str], Optional[str]]:
    print("Choose VLESS source:")
    for key in sorted(PRESET_SOURCES, key=int):
        print(f"  {key}) {PRESET_SOURCES[key]['name']}")
    custom_key = str(len(PRESET_SOURCES) + 1)
    print(f"  {custom_key}) Enter custom URL or local file path")

    while True:
        choice = input(f"Select source [1-{custom_key}]: ").strip()
        if choice in PRESET_SOURCES:
            preset = PRESET_SOURCES[choice]
            print(f"Selected: {preset['name']}")
            return preset["url"], preset["name"], preset["local_file"]
        if choice == custom_key:
            custom = input("Enter URL or local file path: ").strip()
            if custom:
                return custom, None, None
        print(f"Invalid choice. Enter 1-{custom_key}.")


def choose_mode() -> str:
    print("Choose check mode:")
    print("  1) normal - strict: IP + Google + YouTube + Instagram + Telegram + WhatsApp")
    print("  2) light  - soft: IP + Google + YouTube; other services are shown but not required")
    while True:
        choice = input("Select mode [1-2]: ").strip().lower()
        if choice in {"1", "normal", "n"}:
            print("Selected mode: normal")
            return "normal"
        if choice in {"2", "light", "l"}:
            print("Selected mode: light")
            return "light"
        print("Invalid choice. Enter 1 or 2.")


def format_result_line(r: LinkResult, total: int, show_link: bool, load_enabled: bool) -> str:
    shown = r.link if show_link else mask_link(r.link)
    raw_status = "OK" if r.ok else "FAIL"
    status = colorize_status(raw_status)
    cfg = f"{r.cfg_ms}ms" if r.cfg_ms is not None else "-ms"
    load_part = ""
    if load_enabled:
        avg = f" avg={r.load.avg_ms}ms" if r.load.avg_ms is not None else ""
        load_part = f" load={r.load.ok_count}/{r.load.total}({int(r.load.success_rate * 100)}%{avg})"
    return (
        f"[{r.index}/{total}] {status} cfg={cfg}{load_part} "
        f"ip={int(r.ip_ok)}({r.ip_http}) g={int(r.google_ok)}({r.google_http}) "
        f"yt={int(r.youtube_ok)}({r.youtube_http}) ig={int(r.instagram_ok)}({r.instagram_http}) "
        f"tg={int(r.telegram_ok)}({r.telegram_http}) wa={int(r.whatsapp_ok)}({r.whatsapp_http}) {shown}"
        + (f" | {r.error}" if r.error else "")
    )


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Check VLESS links from txt/URL for IP, Google, YouTube, Instagram, Telegram and WhatsApp access"
    )
    ap.add_argument("--input", "-i", help="local .txt file or URL with VLESS links/subscription; if omitted, an interactive menu is shown")
    ap.add_argument("--output", "-o", default=None, help="CSV result path; default: source/mode-specific file")
    ap.add_argument("--working-output", default=None, help="TXT file for working VLESS links only; default: source/mode-specific file")
    ap.add_argument("--local-dir", default=str(default_local_dir()), help="folder for local fallback TXT files")
    ap.add_argument("--mode", choices=["normal", "light"], default=None, help="normal=strict, light=IP+Google+YouTube only")
    ap.add_argument("--save-failed", action="store_true", help="include failed links in CSV too; default CSV contains only working links")
    ap.add_argument("--workers", "-w", type=int, default=12, help="parallel xray processes; default = 12")
    ap.add_argument("--service-workers", type=int, default=6, help="parallel site checks inside each working VLESS link; default = 6")
    ap.add_argument("--timeout", "-t", type=int, default=8, help="per-request timeout seconds; default = 8")
    ap.add_argument("--limit", type=int, default=0, help="check only N links; default = 0 means all")
    ap.add_argument("--offset", type=int, default=0, help="skip first N links before applying --limit")
    ap.add_argument("--all-tests-even-if-ip-fails", action="store_true", help="still test services if ipify check fails")
    ap.add_argument("--no-head", action="store_true", help="use GET instead of faster HEAD for service checks")
    ap.add_argument("--show-links", action="store_true", help="print full VLESS links in console; unsafe for public logs")
    ap.add_argument("--raw-output", action="store_true", help="save original links instead of cleaned v2rayNG/Happ-compatible links")
    ap.add_argument("--load-test", action="store_true", help="run a soft load test with lightweight parallel requests")
    ap.add_argument("--load-requests", type=int, default=10, help="number of load-test requests; default = 10")
    ap.add_argument("--load-workers", type=int, default=3, help="parallel load-test requests; default = 3")
    ap.add_argument("--load-required", action="store_true", help="require load-test success rate for saving working links")
    ap.add_argument("--load-min-success-rate", type=float, default=0.8, help="minimum load success rate if --load-required; default = 0.8")
    args = ap.parse_args()

    source_label: Optional[str] = None
    local_fallback: Optional[str] = None
    if not args.input:
        args.input, source_label, local_fallback = choose_input_source()
    else:
        # If --input is one of the built-in URLs, still use the known fallback name/label.
        raw_input = github_blob_to_raw(args.input)
        for preset in PRESET_SOURCES.values():
            if raw_input == github_blob_to_raw(preset["url"]):
                source_label = preset["name"]
                local_fallback = preset["local_file"]
                break

    if args.mode is None:
        args.mode = choose_mode()

    if args.output is None:
        label = f"{safe_filename_part(source_label)}_{args.mode}" if source_label else args.mode
        args.output = f"vless_check_results_{label}.csv"
    if args.working_output is None:
        label = f"{safe_filename_part(source_label)}_{args.mode}" if source_label else args.mode
        args.working_output = f"working_vless_{label}.txt"

    xray_bin = shutil.which("xray")
    curl_bin = shutil.which("curl")
    if not xray_bin:
        print("ERROR: xray not found in PATH. Install xray-core first.", file=sys.stderr)
        return 2
    if not curl_bin:
        print("ERROR: curl not found in PATH.", file=sys.stderr)
        return 2

    local_dir = Path(args.local_dir).expanduser()
    text = read_input(args.input, local_fallback=local_fallback, local_source_dir=local_dir)
    links = extract_vless_links(text)
    original_count = len(links)
    if args.offset and args.offset > 0:
        links = links[args.offset:]
    if args.limit and args.limit > 0:
        links = links[: args.limit]

    if not links:
        print("ERROR: no vless:// links found. If this is a subscription, make sure it is plain text or base64.", file=sys.stderr)
        return 1

    offset_note = f", offset={args.offset}" if args.offset else ""
    source_note = f", source={source_label}" if source_label else ""
    log(
        f"Found {len(links)} VLESS links{offset_note}{source_note}. "
        f"Total in source: {original_count}. "
        f"Checking with workers={args.workers}, service_workers={args.service_workers}, "
        f"timeout={args.timeout}s, mode={args.mode}, site_method={'GET' if args.no_head else 'HEAD'}"
    )
    if args.load_test:
        log(f"Load test enabled: requests={args.load_requests}, workers={args.load_workers}, required={args.load_required}")

    results: List[LinkResult] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futures = {
            ex.submit(
                check_one,
                i,
                link,
                args.timeout,
                xray_bin,
                curl_bin,
                args.all_tests_even_if_ip_fails,
                args.service_workers,
                not args.no_head,
                args.mode,
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
            log(format_result_line(r, len(links), args.show_links, args.load_test))

    working_results = sorted([r for r in results if r.ok], key=sort_key_fastest)
    csv_results = results if args.save_failed else working_results
    clean_links = not args.raw_output
    write_csv(args.output, csv_results, clean_links=clean_links)
    write_links(args.working_output, working_results, clean_links=clean_links)

    total = len(results)
    all_ok = len(working_results)
    ip_ok = sum(1 for r in results if r.ip_ok)
    google_ok = sum(1 for r in results if r.google_ok)
    yt_ok = sum(1 for r in results if r.youtube_ok)
    ig_ok = sum(1 for r in results if r.instagram_ok)
    tg_ok = sum(1 for r in results if r.telegram_ok)
    wa_ok = sum(1 for r in results if r.whatsapp_ok)
    load_ok = sum(1 for r in results if r.load.enabled and r.load.ok)
    fastest = working_results[0].cfg_ms if working_results and working_results[0].cfg_ms is not None else None

    print("\nSummary")
    print(f"  total checked:   {total}")
    print(f"  working saved:   {all_ok}")
    print(f"  mode:            {args.mode}")
    print(f"  vless/ip ok:     {ip_ok}")
    print(f"  google ok:       {google_ok}")
    print(f"  youtube ok:      {yt_ok}")
    print(f"  instagram ok:    {ig_ok}")
    print(f"  telegram ok:     {tg_ok}")
    print(f"  whatsapp ok:     {wa_ok}")
    if args.load_test:
        print(f"  load ok:         {load_ok}")
    if fastest is not None:
        print(f"  fastest cfg:     {fastest} ms")
    print("  sort:            fastest configs first by gstatic generate_204 latency")
    print(f"  local dir:       {local_dir}")
    print(f"  txt working:     {args.working_output}" + (" (clean client links)" if clean_links else " (raw links)"))
    print(f"  csv:             {args.output}" + (" (all results)" if args.save_failed else " (working only)"))

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
