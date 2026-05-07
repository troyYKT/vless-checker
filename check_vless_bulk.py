#!/usr/bin/env python3
"""
Bulk VLESS checker.

Checks VLESS links from CIDR/SNI subscription files by launching xray-core as a
client for each link, opening a temporary local SOCKS proxy, then testing access
through that proxy.

Features:
  - Interactive source menu: CIDR / SNI / custom input
  - Interactive mode menu: normal / light
  - GitHub download with local fallback/cache
  - macOS-friendly fallback folder: ~/vless_checker
  - Linux root fallback folder: /root/vless_checker
  - Clean v2rayNG/Happ-compatible output links
  - Config latency via https://www.gstatic.com/generate_204
  - Fastest working configs saved first
  - Colored terminal output: OK green, FAIL red

Requirements:
  - python3
  - xray in PATH
  - curl in PATH

Examples:
  python3 check_vless_bulk.py
  python3 check_vless_bulk.py --mode light
  python3 check_vless_bulk.py --mode normal --limit 30
  python3 check_vless_bulk.py --input links.txt --mode light
  python3 check_vless_bulk.py --local-dir ~/vless_checker --mode normal
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import re
import secrets
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


def default_local_source_dir() -> Path:
    env_value = os.environ.get("VLESS_CHECKER_LOCAL_DIR")
    if env_value:
        return Path(env_value).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "vless_checker"
    try:
        if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
            return Path("/root/vless_checker")
    except Exception:
        pass
    return Path.home() / "vless_checker"


DEFAULT_LOCAL_SOURCE_DIR = default_local_source_dir()

# ANSI colors. Disabled automatically when stdout is not a TTY or NO_COLOR is set.
USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
COLOR_GREEN = "\033[92m"
COLOR_RED = "\033[91m"
COLOR_YELLOW = "\033[93m"
COLOR_RESET = "\033[0m"

CONFIG_LATENCY_URL = "https://www.gstatic.com/generate_204"

DEFAULT_TESTS = {
    "ip": "https://api.ipify.org?format=json",
    "google": "https://www.google.com/generate_204",
    "youtube": "https://www.youtube.com/generate_204",
    "instagram": "https://www.instagram.com/favicon.ico",
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
    ok: bool = False
    http_code: str = "000"
    time_total: str = ""
    error: str = ""
    body_preview: str = ""


@dataclass
class LinkResult:
    index: int
    name: str
    link: str
    ok: bool = False
    ip_ok: bool = False
    google_ok: bool = False
    youtube_ok: bool = False
    instagram_ok: bool = False
    telegram_ok: bool = False
    whatsapp_ok: bool = False
    ip_http: str = "000"
    google_http: str = "000"
    youtube_http: str = "000"
    instagram_http: str = "000"
    telegram_http: str = "000"
    whatsapp_http: str = "000"
    config_time: str = ""
    latency_score: float = 9999.0
    ip_body: str = ""
    error: str = ""
    elapsed: float = 0.0


def color_text(text: str, color: str) -> str:
    if not USE_COLOR:
        return text
    return f"{color}{text}{COLOR_RESET}"


def log(msg: str) -> None:
    with PRINT_LOCK:
        print(msg, flush=True)


def decode_output(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


def time_to_float(value: str, default: float = 9999.0) -> float:
    try:
        if not value:
            return default
        return float(str(value).replace(",", "."))
    except Exception:
        return default


def time_to_ms(value: str) -> str:
    try:
        return str(int(round(float(str(value).replace(",", ".")) * 1000)))
    except Exception:
        return ""


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
    return safe_filename_part(name) if name else "vless_links.txt"


def fallback_candidates(local_source_dir: Path, fallback_name: str) -> List[Path]:
    paths = [
        local_source_dir.expanduser() / fallback_name,
        SCRIPT_DIR / fallback_name,
        Path.cwd() / fallback_name,
    ]
    unique: List[Path] = []
    seen = set()
    for p in paths:
        try:
            key = str(p.resolve())
        except Exception:
            key = str(p)
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def read_input(
    source: str,
    timeout: int = 30,
    local_fallback: Optional[str] = None,
    local_source_dir: Path = DEFAULT_LOCAL_SOURCE_DIR,
) -> str:
    source = str(Path(source).expanduser()) if not re.match(r"^https?://", source, re.I) else source

    if re.match(r"^https?://", source, re.I):
        url = github_blob_to_raw(source)
        fallback_name = local_fallback or url_basename_for_cache(url)
        primary_fallback = local_source_dir.expanduser() / fallback_name

        try:
            log(f"Downloading source: {url}")
            req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            text = data.decode("utf-8", errors="replace")

            try:
                primary_fallback.parent.mkdir(parents=True, exist_ok=True)
                primary_fallback.write_text(text, encoding="utf-8")
                log(f"Saved/updated local copy: {primary_fallback}")
            except Exception as e:
                log(f"Warning: could not save local copy {primary_fallback}: {e}")
            return text

        except Exception as e:
            log(f"Download failed: {e}")
            candidates = fallback_candidates(local_source_dir, fallback_name)
            for path in candidates:
                if path.exists():
                    log(f"Using local fallback: {path}")
                    return path.read_text(encoding="utf-8", errors="replace")
            tried = "\n  ".join(str(p) for p in candidates)
            raise RuntimeError(
                f"Could not download {url} and no local fallback was found. Tried:\n  {tried}"
            ) from e

    return Path(source).expanduser().read_text(encoding="utf-8", errors="replace")


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
        # Keep unsupported security as-is; xray will report details.
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
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }
    return config, name


def http_reachable(code: str) -> bool:
    try:
        c = int(code)
        # 4xx still proves the remote host answered through the proxy.
        return 200 <= c < 500
    except Exception:
        return False


def curl_test(
    url: str,
    socks_port: int,
    socks_user: str,
    socks_pass: str,
    timeout: int,
    *,
    head: bool = False,
    capture_body: bool = False,
    curl_bin: str = "curl",
) -> TestResult:
    proxy = f"socks5h://{urllib.parse.quote(socks_user)}:{urllib.parse.quote(socks_pass)}@127.0.0.1:{socks_port}"
    marker = "\n__VLESS_CHECKER_HTTP_CODE__%{http_code}\n__VLESS_CHECKER_TIME_TOTAL__%{time_total}\n"

    cmd = [
        curl_bin,
        "-L",
        "--silent",
        "--show-error",
        "--connect-timeout", str(timeout),
        "--max-time", str(timeout),
        "--user-agent", USER_AGENT,
        "-x", proxy,
        "-w", marker,
    ]
    if head:
        cmd.append("--head")
    if not capture_body:
        cmd += ["-o", os.devnull]
    cmd.append(url)

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 3)
    except subprocess.TimeoutExpired as e:
        return TestResult(False, "000", "", f"curl timeout after {timeout}s", decode_output(e.stdout)[:200])

    stdout = decode_output(result.stdout)
    stderr = decode_output(result.stderr).strip()

    code = "000"
    total = ""
    body = stdout
    m = re.search(
        r"\n__VLESS_CHECKER_HTTP_CODE__(\d{3})\n__VLESS_CHECKER_TIME_TOTAL__([0-9.,]+)\s*$",
        stdout,
        flags=re.S,
    )
    if m:
        code = m.group(1)
        total = m.group(2)
        body = stdout[: m.start()]

    ok = result.returncode == 0 and http_reachable(code)
    return TestResult(
        ok=ok,
        http_code=code,
        time_total=total,
        error="" if ok else (stderr or f"curl return code {result.returncode}"),
        body_preview=body.strip()[:300] if capture_body else "",
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
) -> LinkResult:
    started = time.time()
    proc: Optional[subprocess.Popen] = None
    name = "link"

    try:
        socks_port = free_port()
        socks_user = "u" + secrets.token_hex(4)
        socks_pass = "p" + secrets.token_hex(8)
        config, name = build_xray_config(link, socks_port, socks_user, socks_pass)

        with tempfile.TemporaryDirectory(prefix="vless-check-") as td:
            config_path = Path(td) / "config.json"
            config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")

            proc = subprocess.Popen(
                [xray_bin, "run", "-config", str(config_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            if not wait_port("127.0.0.1", socks_port, proc, timeout=5.0):
                err_text = ""
                if proc.poll() is not None:
                    try:
                        _, err = proc.communicate(timeout=2)
                        err_text = decode_output(err).strip()[:300]
                    except Exception as e:
                        err_text = str(e)[:300]
                return LinkResult(index=index, name=name, link=link, error=f"xray did not start/listen: {err_text}", elapsed=time.time() - started)

            cfg = curl_test(CONFIG_LATENCY_URL, socks_port, socks_user, socks_pass, timeout, head=True, curl_bin=curl_bin)
            ip = curl_test(DEFAULT_TESTS["ip"], socks_port, socks_user, socks_pass, timeout, capture_body=True, curl_bin=curl_bin)

            google = TestResult()
            yt = TestResult()
            ig = TestResult()
            tg = TestResult()
            wa = TestResult()

            if ip.ok or do_all_tests:
                service_names = ["google", "youtube", "instagram", "telegram", "whatsapp"]
                service_results: Dict[str, TestResult] = {}
                max_service_workers = max(1, min(service_workers, len(service_names)))
                with ThreadPoolExecutor(max_workers=max_service_workers) as tex:
                    futures = {
                        tex.submit(
                            curl_test,
                            DEFAULT_TESTS[name],
                            socks_port,
                            socks_user,
                            socks_pass,
                            timeout,
                            head=use_head,
                            capture_body=False,
                            curl_bin=curl_bin,
                        ): name
                        for name in service_names
                    }
                    for fut in as_completed(futures):
                        service_results[futures[fut]] = fut.result()

                google = service_results.get("google", TestResult())
                yt = service_results.get("youtube", TestResult())
                ig = service_results.get("instagram", TestResult())
                tg = service_results.get("telegram", TestResult())
                wa = service_results.get("whatsapp", TestResult())

            if mode == "light":
                ok = ip.ok and google.ok and yt.ok
            else:
                ok = ip.ok and google.ok and yt.ok and ig.ok and tg.ok and wa.ok

            errors = [cfg.error, ip.error, google.error, yt.error, ig.error, tg.error, wa.error]
            err = "; ".join(x for x in errors if x)[:500]
            return LinkResult(
                index=index,
                name=name,
                link=link,
                ok=ok,
                ip_ok=ip.ok,
                google_ok=google.ok,
                youtube_ok=yt.ok,
                instagram_ok=ig.ok,
                telegram_ok=tg.ok,
                whatsapp_ok=wa.ok,
                ip_http=ip.http_code,
                google_http=google.http_code,
                youtube_http=yt.http_code,
                instagram_http=ig.http_code,
                telegram_http=tg.http_code,
                whatsapp_http=wa.http_code,
                config_time=cfg.time_total,
                latency_score=time_to_float(cfg.time_total),
                ip_body=ip.body_preview,
                error=err,
                elapsed=time.time() - started,
            )

    except Exception as e:
        return LinkResult(index=index, name=name, link=link, error=str(e)[:500], elapsed=time.time() - started)
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
    ("host", ("host",), None, False),
    ("path", ("path",), None, False),
    ("headerType", ("headerType",), None, False),
    ("serviceName", ("serviceName",), None, False),
    ("authority", ("authority",), None, False),
    ("mode", ("mode",), None, False),
    ("mldsa65Verify", ("mldsa65Verify",), None, False),
]


def first_q(q: Dict[str, List[str]], keys: Tuple[str, ...], default: Optional[str] = None) -> Optional[str]:
    for key in keys:
        if key in q and q[key]:
            return urllib.parse.unquote(str(q[key][0]))
    return default


def clean_vless_link(link: str) -> str:
    try:
        p = urllib.parse.urlsplit(link.strip())
        if p.scheme.lower() != "vless":
            return link.strip()
        q = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        params: List[Tuple[str, str]] = []
        for out_key, in_keys, default, always in CLIENT_QUERY_ORDER:
            value = first_q(q, in_keys, default)
            if value is None:
                continue
            if value == "" and not always:
                continue
            params.append((out_key, value))
        query = urllib.parse.urlencode(params, doseq=False)
        user = p.username or ""
        host = p.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = f"{user}@{host}"
        if p.port:
            netloc += f":{p.port}"
        fragment = urllib.parse.quote(urllib.parse.unquote(p.fragment or ""), safe="")
        return urllib.parse.urlunsplit(("vless", netloc, "", query, fragment))
    except Exception:
        return link.strip()


def result_sort_key(r: LinkResult) -> Tuple[int, float, int]:
    return (0 if r.ok else 1, r.latency_score, r.index)


def write_csv(path: str, results: Iterable[LinkResult], clean_links: bool = True) -> None:
    rows = sorted(results, key=result_sort_key)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([
            "index", "name", "all_ok",
            "vless_ip_ok", "google_ok", "youtube_ok", "instagram_ok", "telegram_ok", "whatsapp_ok",
            "ip_http", "google_http", "youtube_http", "instagram_http", "telegram_http", "whatsapp_http",
            "config_latency_ms", "ip_body", "elapsed_sec", "error", "link",
        ])
        for r in rows:
            w.writerow([
                r.index, r.name, int(r.ok),
                int(r.ip_ok), int(r.google_ok), int(r.youtube_ok), int(r.instagram_ok), int(r.telegram_ok), int(r.whatsapp_ok),
                r.ip_http, r.google_http, r.youtube_http, r.instagram_http, r.telegram_http, r.whatsapp_http,
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


def choose_input_source() -> Tuple[str, Optional[str], Optional[str]]:
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
                return custom, None, None
        print("Invalid choice. Enter 1, 2 or 3.")


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


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Check VLESS links for IP, Google, YouTube, Instagram, Telegram and WhatsApp access. cfg_ms uses gstatic generate_204."
    )
    ap.add_argument("--input", "-i", help="local .txt file or URL with VLESS links/subscription; if omitted, an interactive CIDR/SNI menu is shown")
    ap.add_argument("--mode", choices=["normal", "light"], default=None, help="normal = strict; light = IP + Google + YouTube required only")
    ap.add_argument("--output", "-o", default=None, help="CSV result path; default: source/mode-specific file")
    ap.add_argument("--working-output", default=None, help="TXT file for working VLESS links only; default: source/mode-specific file")
    ap.add_argument("--save-failed", action="store_true", help="include failed links in CSV too; default CSV contains only working links")
    ap.add_argument("--workers", "-w", type=int, default=12, help="parallel xray processes; default = 12; reduce to 4-8 on a weak server/Mac")
    ap.add_argument("--service-workers", type=int, default=6, help="parallel site checks inside each working VLESS link; default = 6")
    ap.add_argument("--timeout", "-t", type=int, default=8, help="per-request timeout seconds; default = 8; increase to 12 for fewer false FAIL results")
    ap.add_argument("--limit", type=int, default=0, help="check only N links; default = 0 = all")
    ap.add_argument("--offset", type=int, default=0, help="skip first N links before applying --limit; useful for batches")
    ap.add_argument("--all-tests-even-if-ip-fails", action="store_true", help="still test services if ipify check fails")
    ap.add_argument("--no-head", action="store_true", help="use GET instead of faster HEAD for service checks")
    ap.add_argument("--show-links", action="store_true", help="print full VLESS links in console; unsafe for public logs")
    ap.add_argument("--raw-output", action="store_true", help="save original links instead of cleaned v2rayNG/Happ-compatible links")
    ap.add_argument("--local-dir", default=str(DEFAULT_LOCAL_SOURCE_DIR), help=f"folder for GitHub fallback/cache files; default: {DEFAULT_LOCAL_SOURCE_DIR}")
    args = ap.parse_args()

    source_label: Optional[str] = None
    local_fallback: Optional[str] = None
    if not args.input:
        args.input, source_label, local_fallback = choose_input_source()

    if args.mode is None:
        args.mode = choose_mode()
    else:
        print(f"Selected mode: {args.mode}")

    if args.output is None:
        args.output = f"vless_check_results_{safe_filename_part(source_label)}_{args.mode}.csv" if source_label else f"vless_check_results_{args.mode}.csv"
    if args.working_output is None:
        args.working_output = f"working_vless_{safe_filename_part(source_label)}_{args.mode}.txt" if source_label else f"working_vless_{args.mode}.txt"

    xray_bin = shutil.which("xray")
    curl_bin = shutil.which("curl")
    if not xray_bin:
        print("ERROR: xray not found in PATH. Install xray-core first.", file=sys.stderr)
        return 2
    if not curl_bin:
        print("ERROR: curl not found in PATH.", file=sys.stderr)
        return 2

    try:
        text = read_input(args.input, local_fallback=local_fallback, local_source_dir=Path(args.local_dir).expanduser())
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    links = extract_vless_links(text)
    if args.offset and args.offset > 0:
        links = links[args.offset:]
    if args.limit and args.limit > 0:
        links = links[:args.limit]

    if not links:
        print("ERROR: no vless:// links found. If this is a subscription, make sure it is plain text or base64.", file=sys.stderr)
        return 1

    offset_note = f", offset={args.offset}" if args.offset else ""
    log(
        f"Found {len(links)} VLESS links{offset_note}. "
        f"mode={args.mode}, workers={args.workers}, service_workers={args.service_workers}, "
        f"timeout={args.timeout}s, site_method={'GET' if args.no_head else 'HEAD'}"
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
            status_raw = "OK" if r.ok else "FAIL"
            status = color_text(status_raw, COLOR_GREEN if r.ok else COLOR_RED)
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
    print(f"  mode:            {args.mode}")
    print(f"  vless/ip ok:     {ip_ok}")
    print(f"  google ok:       {google_ok}")
    print(f"  youtube ok:      {yt_ok}")
    print(f"  instagram ok:    {ig_ok}")
    print(f"  telegram ok:     {tg_ok}")
    print(f"  whatsapp ok:     {wa_ok}")
    if working_results:
        fastest = sorted(working_results, key=result_sort_key)[0]
        print(f"  fastest config:  {time_to_ms(fastest.config_time)} ms  ({fastest.name})")
    print("  sort:            fastest configs first by gstatic generate_204 latency")
    print(f"  local dir:       {Path(args.local_dir).expanduser()}")
    print(f"  txt working:     {args.working_output}" + (" (clean client links)" if clean_links else " (raw links)"))
    print(f"  csv:             {args.output}" + (" (all results)" if args.save_failed else " (working only)"))

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
