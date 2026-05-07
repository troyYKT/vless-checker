#!/usr/bin/env python3
"""
Bulk VLESS checker.

Checks VLESS links from a local .txt file or URL by launching xray-core with each
link as outbound, then testing access through a temporary local SOCKS proxy.

Config latency (cfg_ms) is measured through https://www.gstatic.com/generate_204.

Requirements:
  - python3
  - xray in PATH
  - curl in PATH

Examples:
  python3 check_vless_bulk.py          # menu: downloads CIDR/SNI, falls back to /root/vless_checker files
  python3 check_vless_bulk.py --input links.txt
  python3 check_vless_bulk.py --input 'https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt' --workers 4 --limit 0
  python3 check_vless_bulk.py --input links.txt --workers 12 --service-workers 6 --timeout 8 --limit 0
  python3 check_vless_bulk.py --mode light --limit 0
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
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
DEFAULT_LOCAL_SOURCE_DIR = Path("/root/vless_checker")

# ANSI colors for terminal output. Disabled automatically when stdout is not a TTY
# or when NO_COLOR is set, so redirected logs stay clean.
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_RESET = "\033[0m"


def color_text(text: str, color: str) -> str:
    if not USE_COLOR:
        return text
    return f"{color}{text}{COLOR_RESET}"


CONFIG_LATENCY_URL = "https://www.gstatic.com/generate_204"

DEFAULT_TESTS = {
    "ip": "https://api.ipify.org?format=json",
    "google": "https://www.google.com/generate_204",
    "youtube": "https://www.youtube.com/generate_204",
    "instagram": "https://www.instagram.com/favicon.ico",
    # Lightweight checks only. Extra Telegram/WhatsApp domains were removed
    # because they made the filter too strict for real-world working configs.
    "telegram": "https://telegram.org/favicon.ico",
    "whatsapp": "https://www.whatsapp.com/favicon.ico",
}

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0 Safari/537.36"
)

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
}


@dataclass
class TestResult:
    ok: bool
    http_code: str = "000"
    time_total: str = ""
    error: str = ""
    body_preview: str = ""


@dataclass
class LinkResult:
    index: int
    name: str
    link: str
    ok: bool
    ip_ok: bool
    google_ok: bool
    youtube_ok: bool
    instagram_ok: bool
    telegram_ok: bool
    whatsapp_ok: bool
    telegram_org_ok: bool
    telegram_web_ok: bool
    telegram_tme_ok: bool
    whatsapp_www_ok: bool
    whatsapp_web_ok: bool
    whatsapp_static_ok: bool
    ip_http: str
    google_http: str
    youtube_http: str
    instagram_http: str
    telegram_http: str
    whatsapp_http: str
    telegram_org_http: str
    telegram_web_http: str
    telegram_tme_http: str
    whatsapp_www_http: str
    whatsapp_web_http: str
    whatsapp_static_http: str
    config_time: str
    latency_score: float
    ip_body: str
    error: str
    elapsed: float


def make_empty_result(index: int, name: str, link: str, error: str, elapsed: float) -> LinkResult:
    """Build a failed LinkResult with all checks empty/false."""
    return LinkResult(
        index=index, name=name, link=link, ok=False,
        ip_ok=False, google_ok=False, youtube_ok=False, instagram_ok=False, telegram_ok=False, whatsapp_ok=False,
        telegram_org_ok=False, telegram_web_ok=False, telegram_tme_ok=False,
        whatsapp_www_ok=False, whatsapp_web_ok=False, whatsapp_static_ok=False,
        ip_http="000", google_http="000", youtube_http="000", instagram_http="000", telegram_http="000", whatsapp_http="000",
        telegram_org_http="000", telegram_web_http="000", telegram_tme_http="000",
        whatsapp_www_http="000", whatsapp_web_http="000", whatsapp_static_http="000",
        config_time="", latency_score=9999.0, ip_body="", error=error, elapsed=elapsed,
    )


def log(msg: str) -> None:
    with PRINT_LOCK:
        print(msg, flush=True)


def decode_output(data) -> str:
    """Decode subprocess output safely, even if a server sends non-UTF-8 bytes."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def time_to_float(value: str, default: float = 9999.0) -> float:
    """Convert curl %{time_total} seconds string to float for sorting."""
    try:
        if value is None or value == "":
            return default
        return float(str(value).replace(",", "."))
    except Exception:
        return default


def time_to_ms(value: str) -> str:
    """Return curl seconds string as milliseconds for readable console/CSV output."""
    try:
        return str(int(round(float(str(value).replace(",", ".")) * 1000)))
    except Exception:
        return ""

def http_group_code(*results: TestResult) -> str:
    """Return grouped HTTP codes like 200/200/302 for multi-domain checks."""
    return "/".join((r.http_code or "000") for r in results)


def bool_group(*results: TestResult) -> bool:
    """Group check succeeds only when every required domain is reachable."""
    return all(r.ok for r in results)


def github_blob_to_raw(url: str) -> str:
    """Convert github.com/.../blob/branch/path to raw.githubusercontent.com URL."""
    p = urllib.parse.urlsplit(url)
    if p.netloc.lower() != "github.com" or "/blob/" not in p.path:
        return url
    # /owner/repo/blob/branch/path/to/file
    parts = p.path.strip("/").split("/")
    if len(parts) >= 5 and parts[2] == "blob":
        owner, repo, _, branch = parts[:4]
        rest = "/".join(parts[4:])
        return f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{rest}"
    return url


def url_basename_for_cache(source: str) -> str:
    """Return a safe filename for caching/fallback by URL basename."""
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
    local_source_dir: Path = DEFAULT_LOCAL_SOURCE_DIR,
) -> str:
    """Read links from URL or file.

    For URLs, first tries to download fresh content. If download fails, reads a
    fallback file from local_source_dir. On successful download, the content is
    saved to that fallback file for future offline/blocked runs.
    """
    if re.match(r"^https?://", source, re.I):
        url = github_blob_to_raw(source)
        fallback_name = local_fallback or url_basename_for_cache(url)
        fallback_path = local_source_dir / fallback_name

        try:
            log(f"Downloading source: {url}")
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            text = data.decode("utf-8", errors="replace")

            # Refresh local copy. If the fallback folder is not writable, continue anyway.
            try:
                fallback_path.parent.mkdir(parents=True, exist_ok=True)
                fallback_path.write_text(text, encoding="utf-8")
                log(f"Saved/updated local copy: {fallback_path}")
            except Exception as e:
                log(f"Warning: could not save local copy {fallback_path}: {e}")
            return text

        except Exception as e:
            log(f"Download failed: {e}")
            if fallback_path.exists():
                log(f"Using local fallback: {fallback_path}")
                return fallback_path.read_text(encoding="utf-8", errors="replace")
            raise RuntimeError(
                f"Could not download {url} and local fallback was not found: {fallback_path}"
            ) from e

    return Path(source).read_text(encoding="utf-8", errors="replace")


def try_b64_decode(text: str) -> Optional[str]:
    compact = re.sub(r"\s+", "", text.strip())
    if not compact or len(compact) < 16:
        return None
    # Do not try to decode normal text containing many URL punctuation chars.
    if "vless://" in text.lower():
        return None
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return None
    # support base64url and missing padding
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
        # Most subscription files keep one link per line.
        if line.lower().startswith("vless://"):
            link = line
            if link not in seen:
                seen.add(link)
                links.append(link)
            continue
        # Fallback: pull links from mixed text/HTML. Stop on whitespace or quotes.
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
    name = urllib.parse.unquote(parsed.fragment or host or f"link")
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
        # Leave unsupported security as-is so xray can return a clear error.
        pass

    # Transport settings
    if network == "tcp":
        header_type = qget(q, "headerType") or qget(q, "headerType", "none")
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
        # xray-core versions differ: new versions use xhttpSettings, older use splithttpSettings.
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


def curl_test(
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
    # Separator makes parsing reliable even if a body is printed by a redirect/error page.
    fmt = "\\n__CURL_META__%{http_code} %{time_total}"
    cmd = [
        "curl",
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
        # HEAD is much faster for access checks: we only need to know
        # whether the host is reachable and returns any HTTP status.
        cmd.append("--head")
    cmd += [
        "-o",
        "-" if capture_body else os.devnull,
        "-w",
        fmt,
        url,
    ]
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False, timeout=timeout + 3)
    except subprocess.TimeoutExpired:
        return TestResult(ok=False, error="curl timeout")

    stdout = decode_output(p.stdout)
    stderr = decode_output(p.stderr).strip()
    http_code = "000"
    time_total = ""
    body = stdout
    marker = "\n__CURL_META__"
    if marker in stdout:
        body, meta = stdout.rsplit(marker, 1)
        parts = meta.strip().split()
        if parts:
            http_code = parts[0]
        if len(parts) > 1:
            time_total = parts[1]

    # For access checking, any real HTTP response means TLS/connectivity reached the service.
    # 403/429 can happen on Instagram/Google services but still mean it is reachable.
    ok = p.returncode == 0 and http_code != "000"
    preview = re.sub(r"\s+", " ", body.strip())[:180]
    return TestResult(ok=ok, http_code=http_code, time_total=time_total, error=stderr, body_preview=preview)



CHECK_MODES = {
    "normal": {
        "title": "normal",
        "description": "strict: IP + Google + YouTube + Instagram + Telegram + WhatsApp",
        "required": ("ip_ok", "google_ok", "youtube_ok", "instagram_ok", "telegram_ok", "whatsapp_ok"),
    },
    "light": {
        "title": "light",
        "description": "soft: IP + Google + YouTube; Instagram/Telegram/WhatsApp are diagnostic only",
        "required": ("ip_ok", "google_ok", "youtube_ok"),
    },
}


def result_ok_for_mode(
    mode: str,
    *,
    ip_ok: bool,
    google_ok: bool,
    youtube_ok: bool,
    instagram_ok: bool,
    telegram_ok: bool,
    whatsapp_ok: bool,
) -> bool:
    """Return whether a config should be saved for the selected mode."""
    if mode == "light":
        return ip_ok and google_ok and youtube_ok
    # normal/strict mode
    return ip_ok and google_ok and youtube_ok and instagram_ok and telegram_ok and whatsapp_ok


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
) -> LinkResult:
    del curl_bin  # curl is called by name after we verified PATH; kept for readability.
    started = time.time()
    socks_port = free_port()
    socks_user = f"u{os.getpid()}_{index}"
    socks_pass = base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("=")
    name = f"link-{index}"
    proc: Optional[subprocess.Popen] = None

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
                    _, err = proc.communicate(timeout=2)
                err_text = decode_output(err).strip()[:300]
                return make_empty_result(
                    index=index, name=name, link=link,
                    error=f"xray did not start/listen: {err_text}",
                    elapsed=time.time() - started,
                )

            # cfg_ms is a lightweight practical latency test through the VLESS config.
            # It is intentionally separate from IP check, so sorting is not affected by
            # api.ipify.org response time.
            cfg = curl_test(CONFIG_LATENCY_URL, socks_port, socks_user, socks_pass, timeout, capture_body=False)
            ip = curl_test(DEFAULT_TESTS["ip"], socks_port, socks_user, socks_pass, timeout, capture_body=True)
            google = TestResult(False)
            yt = TestResult(False)
            ig = TestResult(False)
            tg_org = TestResult(False)
            tg_web = TestResult(False)
            tg_tme = TestResult(False)
            wa_www = TestResult(False)
            wa_web = TestResult(False)
            wa_static = TestResult(False)
            if ip.ok or do_all_tests:
                service_names = [
                    "google",
                    "youtube",
                    "instagram",
                    "telegram",
                    "whatsapp",
                ]
                service_results: Dict[str, TestResult] = {}
                max_service_workers = max(1, min(service_workers, len(service_names)))
                with ThreadPoolExecutor(max_workers=max_service_workers) as tex:
                    tfutures = {
                        tex.submit(
                            curl_test,
                            DEFAULT_TESTS[name],
                            socks_port,
                            socks_user,
                            socks_pass,
                            timeout,
                            head=use_head,
                            capture_body=False,
                        ): name
                        for name in service_names
                    }
                    for tfut in as_completed(tfutures):
                        service_results[tfutures[tfut]] = tfut.result()

                google = service_results.get("google", TestResult(False))
                yt = service_results.get("youtube", TestResult(False))
                ig = service_results.get("instagram", TestResult(False))
                tg_org = service_results.get("telegram", TestResult(False))
                wa_www = service_results.get("whatsapp", TestResult(False))
                # Extra domains are intentionally not required anymore.
                tg_web = TestResult(False)
                tg_tme = TestResult(False)
                wa_web = TestResult(False)
                wa_static = TestResult(False)

            tg_ok = tg_org.ok
            wa_ok = wa_www.ok
            ok = result_ok_for_mode(
                mode,
                ip_ok=ip.ok,
                google_ok=google.ok,
                youtube_ok=yt.ok,
                instagram_ok=ig.ok,
                telegram_ok=tg_ok,
                whatsapp_ok=wa_ok,
            )
            err = "; ".join(
                x
                for x in [
                    cfg.error, ip.error, google.error, yt.error, ig.error,
                    tg_org.error, tg_web.error, tg_tme.error,
                    wa_www.error, wa_web.error, wa_static.error,
                ]
                if x
            )[:500]
            return LinkResult(
                index=index,
                name=name,
                link=link,
                ok=ok,
                ip_ok=ip.ok,
                google_ok=google.ok,
                youtube_ok=yt.ok,
                instagram_ok=ig.ok,
                telegram_ok=tg_ok,
                whatsapp_ok=wa_ok,
                telegram_org_ok=tg_org.ok,
                telegram_web_ok=tg_web.ok,
                telegram_tme_ok=tg_tme.ok,
                whatsapp_www_ok=wa_www.ok,
                whatsapp_web_ok=wa_web.ok,
                whatsapp_static_ok=wa_static.ok,
                ip_http=ip.http_code,
                google_http=google.http_code,
                youtube_http=yt.http_code,
                instagram_http=ig.http_code,
                telegram_http=tg_org.http_code,
                whatsapp_http=wa_www.http_code,
                telegram_org_http=tg_org.http_code,
                telegram_web_http=tg_web.http_code,
                telegram_tme_http=tg_tme.http_code,
                whatsapp_www_http=wa_www.http_code,
                whatsapp_web_http=wa_web.http_code,
                whatsapp_static_http=wa_static.http_code,
                config_time=cfg.time_total,
                latency_score=time_to_float(cfg.time_total),
                ip_body=ip.body_preview,
                error=err,
                elapsed=time.time() - started,
            )

    except Exception as e:
        return make_empty_result(
            index=index, name=name, link=link,
            error=str(e)[:500], elapsed=time.time() - started,
        )
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


# Parameters that are understood by common Android clients such as v2rayNG/Happ.
# Unknown/service parameters are stripped when writing working links.
CLIENT_QUERY_ORDER = [
    ("encryption", ("encryption",), "none", True),
    ("security", ("security",), "none", True),
    ("type", ("type",), "tcp", True),
    ("flow", ("flow",), None, False),
    ("sni", ("sni", "serverName"), None, False),
    ("fp", ("fp", "fingerprint"), None, False),
    ("pbk", ("pbk", "publicKey"), None, False),
    ("sid", ("sid", "shortId"), None, False),
    ("spx", ("spx", "spiderX"), None, False),
    ("alpn", ("alpn",), None, False),
    ("allowInsecure", ("allowInsecure",), None, False),
    ("path", ("path",), None, False),
    ("host", ("host",), None, False),
    ("serviceName", ("serviceName",), None, False),
    ("authority", ("authority",), None, False),
    ("mode", ("mode",), None, False),
    ("headerType", ("headerType",), None, False),
    ("quicSecurity", ("quicSecurity",), None, False),
    ("key", ("key",), None, False),
]


def clean_vless_link(link: str) -> str:
    """Return a clean vless:// link suitable for importing into v2rayNG/Happ.

    Keeps only connection-critical parameters and normalizes common aliases:
    serverName -> sni, fingerprint -> fp, publicKey -> pbk, shortId -> sid,
    spiderX -> spx. Everything else is stripped.
    """
    try:
        parsed = urllib.parse.urlsplit(link.strip())
        if parsed.scheme.lower() != "vless":
            return link.strip()

        uuid = urllib.parse.unquote(parsed.username or "")
        host = parsed.hostname or ""
        port = parsed.port
        if not uuid or not host or not port:
            return link.strip()

        # IPv6 addresses must be wrapped in brackets in URLs.
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


def result_sort_key(r: LinkResult) -> Tuple[int, float, int]:
    """Sort working links first, then by VLESS config latency, then original order."""
    return (0 if r.ok else 1, r.latency_score, r.index)


def write_csv(path: str, results: Iterable[LinkResult], clean_links: bool = True) -> None:
    rows = sorted(results, key=result_sort_key)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "index", "name", "all_ok",
            "vless_ip_ok", "google_ok", "youtube_ok", "instagram_ok", "telegram_ok", "whatsapp_ok",
            "telegram_org_ok", "telegram_web_ok", "telegram_tme_ok",
            "whatsapp_www_ok", "whatsapp_web_ok", "whatsapp_static_ok",
            "ip_http", "google_http", "youtube_http", "instagram_http", "telegram_http", "whatsapp_http",
            "telegram_org_http", "telegram_web_http", "telegram_tme_http",
            "whatsapp_www_http", "whatsapp_web_http", "whatsapp_static_http",
            "config_latency_ms",
            "ip_body", "elapsed_sec", "error", "link",
        ])
        for r in rows:
            w.writerow([
                r.index, r.name, int(r.ok),
                int(r.ip_ok), int(r.google_ok), int(r.youtube_ok), int(r.instagram_ok), int(r.telegram_ok), int(r.whatsapp_ok),
                int(r.telegram_org_ok), int(r.telegram_web_ok), int(r.telegram_tme_ok),
                int(r.whatsapp_www_ok), int(r.whatsapp_web_ok), int(r.whatsapp_static_ok),
                r.ip_http, r.google_http, r.youtube_http, r.instagram_http, r.telegram_http, r.whatsapp_http,
                r.telegram_org_http, r.telegram_web_http, r.telegram_tme_http,
                r.whatsapp_www_http, r.whatsapp_web_http, r.whatsapp_static_http,
                time_to_ms(r.config_time) if r.latency_score < 9999 else "",
                r.ip_body, f"{r.elapsed:.2f}", r.error,
                clean_vless_link(r.link) if clean_links else r.link,
            ])


def write_links(path: str, results: Iterable[LinkResult], clean_links: bool = True) -> None:
    rows = sorted(results, key=result_sort_key)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            out_link = clean_vless_link(r.link) if clean_links else r.link.rstrip()
            f.write(out_link + "\n")



def safe_filename_part(value: str) -> str:
    """Return a safe short filename part for source-specific output files."""
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    value = value.strip("._-")
    return value or "custom"


def choose_input_source() -> Tuple[str, Optional[str], Optional[str]]:
    """Ask the user to choose a built-in source when --input is not provided."""
    print("Choose VLESS source:")
    for key in sorted(PRESET_SOURCES):
        item = PRESET_SOURCES[key]
        print(f"  {key}) {item['name']}")
    print("  3) Enter custom URL or local file path")

    while True:
        choice = input("Select source [1-3]: ").strip()
        if choice in PRESET_SOURCES:
            item = PRESET_SOURCES[choice]
            print(f"Selected: {item['name']}")
            return item["url"], item["name"], item["local_file"]
        if choice == "3":
            custom = input("Enter URL or local file path: ").strip()
            if custom:
                # For custom URLs, fallback/cache file is inferred from URL basename.
                return custom, None, None
        print("Invalid choice. Enter 1, 2 or 3.")



def choose_check_mode() -> str:
    """Ask the user to choose strict or soft filtering mode."""
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


def main() -> int:
    ap = argparse.ArgumentParser(description="Check VLESS links from txt/URL. Normal mode requires IP, Google, YouTube, Instagram, Telegram and WhatsApp; light mode requires IP, Google and YouTube. cfg_ms uses gstatic generate_204")
    ap.add_argument("--input", "-i", help="local .txt file or URL with VLESS links/subscription; if omitted, an interactive CIDR/SNI menu is shown")
    ap.add_argument("--output", "-o", default=None, help="CSV result path; default: source-specific file for menu choices, otherwise vless_check_results.csv")
    ap.add_argument("--working-output", default=None, help="TXT file for working VLESS links only; default: source-specific file for menu choices, otherwise working_vless.txt")
    ap.add_argument("--save-failed", action="store_true", help="include failed links in CSV too; default CSV contains only working links")
    ap.add_argument("--workers", "-w", type=int, default=12, help="parallel xray processes; default = 12; reduce to 4-8 on a weak server")
    ap.add_argument("--service-workers", type=int, default=6, help="parallel site checks inside each working VLESS link; default = 6")
    ap.add_argument("--timeout", "-t", type=int, default=8, help="per-request timeout seconds; default = 8; increase to 12 for fewer false FAIL results")
    ap.add_argument("--limit", type=int, default=0, help="check only N links; default = 0/all; use 30 for first 30")
    ap.add_argument("--offset", type=int, default=0, help="skip first N links before applying --limit; useful for checking batches: 0, 30, 60...")
    ap.add_argument("--all-tests-even-if-ip-fails", action="store_true", help="still test Google/YouTube/Instagram/Telegram/WhatsApp if ipify check fails")
    ap.add_argument("--no-head", action="store_true", help="use GET instead of faster HEAD for Google/YouTube/Instagram/Telegram/WhatsApp checks")
    ap.add_argument("--mode", choices=["normal", "light"], default=None, help="filter mode: normal=strict all services, light=IP+Google+YouTube only; if omitted in a terminal, a menu is shown")
    ap.add_argument("--show-links", action="store_true", help="print full VLESS links in console; unsafe for public logs")
    ap.add_argument("--raw-output", action="store_true", help="save original links instead of cleaned v2rayNG/Happ-compatible links")
    ap.add_argument("--local-dir", default=str(DEFAULT_LOCAL_SOURCE_DIR), help="folder for GitHub fallback/cache files; default: /root/vless_checker")
    args = ap.parse_args()

    source_label: Optional[str] = None
    local_fallback: Optional[str] = None
    if not args.input:
        args.input, source_label, local_fallback = choose_input_source()

    if args.mode is None:
        args.mode = choose_check_mode() if sys.stdin.isatty() else "normal"

    mode_suffix = safe_filename_part(args.mode)

    # Auto-save menu choices into different files. Explicit --output / --working-output
    # still overrides these defaults. The mode suffix prevents strict/light runs
    # from overwriting each other.
    if args.output is None:
        args.output = f"vless_check_results_{safe_filename_part(source_label)}_{mode_suffix}.csv" if source_label else f"vless_check_results_{mode_suffix}.csv"
    if args.working_output is None:
        args.working_output = f"working_vless_{safe_filename_part(source_label)}_{mode_suffix}.txt" if source_label else f"working_vless_{mode_suffix}.txt"

    xray_bin = shutil.which("xray")
    curl_bin = shutil.which("curl")
    if not xray_bin:
        print("ERROR: xray not found in PATH. Install xray-core first.", file=sys.stderr)
        return 2
    if not curl_bin:
        print("ERROR: curl not found in PATH.", file=sys.stderr)
        return 2

    text = read_input(args.input, local_fallback=local_fallback, local_source_dir=Path(args.local_dir))
    links = extract_vless_links(text)
    if args.offset and args.offset > 0:
        links = links[args.offset :]
    if args.limit and args.limit > 0:
        links = links[: args.limit]

    if not links:
        print("ERROR: no vless:// links found. If this is a subscription, make sure it is plain text or base64.", file=sys.stderr)
        return 1

    offset_note = f", offset={args.offset}" if args.offset else ""
    log(
        f"Found {len(links)} VLESS links{offset_note}. "
        f"Checking with workers={args.workers}, service_workers={args.service_workers}, "
        f"timeout={args.timeout}s, site_method={'GET' if args.no_head else 'HEAD'}, "
        f"mode={args.mode} ({CHECK_MODES[args.mode]['description']}), "
        f"cfg_latency=gstatic_generate_204"
    )
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
            ): (i, link)
            for i, link in enumerate(links, start=1)
        }
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            shown = r.link if args.show_links else mask_link(r.link)
            status_plain = "OK" if r.ok else "FAIL"
            status = color_text(status_plain, COLOR_GREEN if r.ok else COLOR_RED)
            config_ms = time_to_ms(r.config_time) if r.latency_score < 9999 else "-"
            log(
                f"[{r.index}/{len(links)}] {status} "
                f"cfg={config_ms}ms "
                f"ip={int(r.ip_ok)}({r.ip_http}) "
                f"g={int(r.google_ok)}({r.google_http}) "
                f"yt={int(r.youtube_ok)}({r.youtube_http}) "
                f"ig={int(r.instagram_ok)}({r.instagram_http}) "
                f"tg={int(r.telegram_ok)}({r.telegram_http}) "
                f"wa={int(r.whatsapp_ok)}({r.whatsapp_http}) {shown}"
                + (f" | {r.error}" if r.error else "")
            )

    working_results = [r for r in results if r.ok]
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

    print("\nSummary")
    print(f"  total checked:   {total}")
    print(f"  working saved:   {all_ok}")
    print(f"  vless/ip ok:     {ip_ok}")
    print(f"  google ok:       {google_ok}")
    print(f"  youtube ok:      {yt_ok}")
    print(f"  instagram ok:    {ig_ok}")
    print(f"  telegram ok:     {tg_ok}")
    print(f"  whatsapp ok:     {wa_ok}")
    if working_results:
        fastest = sorted(working_results, key=result_sort_key)[0]
        print(f"  fastest config:  {time_to_ms(fastest.config_time)} ms  ({fastest.name})")
    print(f"  sort:            fastest configs first by gstatic generate_204 latency")
    print(f"  txt working:     {args.working_output}" + (" (clean client links)" if clean_links else " (raw links)"))
    print(f"  csv:             {args.output}" + (" (all results)" if args.save_failed else " (working only)"))

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
