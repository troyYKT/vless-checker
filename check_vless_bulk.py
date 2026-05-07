#!/usr/bin/env python3
"""
Bulk VLESS checker for CIDR/SNI subscription files.

Features:
  - CIDR/SNI menu, or custom --input
  - GitHub download with local fallback
  - normal/light check modes
  - temporary xray-core client per VLESS link
  - checks IP, Google, YouTube, Instagram, Telegram, WhatsApp
  - config latency via https://www.gstatic.com/generate_204
  - fastest working links are saved first
  - Windows/macOS/Linux compatible
"""

from __future__ import annotations

import argparse
import base64
import csv
import json
import os
import platform
import random
import re
import shutil
import socket
import string
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

SOURCE_PRESETS = {
    "CIDR": {
        "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
        "filename": "WHITE-CIDR-RU-all.txt",
    },
    "SNI": {
        "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU-all.txt",
        "filename": "WHITE-SNI-RU-all.txt",
    },
}

TESTS = {
    "cfg": "https://www.gstatic.com/generate_204",
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


def default_local_dir() -> Path:
    if os.name == "nt":
        return Path.home() / "vless_checker"
    if platform.system().lower() == "darwin":
        return Path.home() / "vless_checker"
    if os.geteuid() == 0 if hasattr(os, "geteuid") else False:
        return Path("/root/vless_checker")
    return Path.home() / "vless_checker"


def color_enabled() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def ctext(text: str, color: str) -> str:
    if not color_enabled():
        return text
    codes = {"red": "31", "green": "32", "yellow": "33", "cyan": "36"}
    return f"\033[{codes.get(color, '0')}m{text}\033[0m"


@dataclass
class TestResult:
    ok: bool
    http_code: str = "000"
    time_total: str = ""
    error: str = ""

    @property
    def ms(self) -> Optional[int]:
        try:
            return int(float(self.time_total) * 1000)
        except Exception:
            return None


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
    error: str
    elapsed: float


def log(msg: str) -> None:
    with PRINT_LOCK:
        print(msg, flush=True)


def decode_output(data) -> str:
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)


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


def read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def download_url(url: str, timeout: int = 30) -> str:
    url = github_blob_to_raw(url)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
    return data.decode("utf-8", errors="replace")


def read_source(source: str, local_dir: Path, fallback_filename: Optional[str] = None, timeout: int = 30) -> str:
    """Read from URL or local path. For URL, try GitHub first, then local fallback."""
    script_dir = Path(__file__).resolve().parent

    if re.match(r"^https?://", source, re.I):
        try:
            log(f"Downloading source: {github_blob_to_raw(source)}")
            text = download_url(source, timeout=timeout)
            if fallback_filename:
                try:
                    local_dir.mkdir(parents=True, exist_ok=True)
                    (local_dir / fallback_filename).write_text(text, encoding="utf-8")
                    log(f"Saved local copy: {local_dir / fallback_filename}")
                except Exception as e:
                    log(f"Warning: could not save local copy: {e}")
            return text
        except Exception as e:
            log(f"Download failed: {e}")
            candidates: List[Path] = []
            if fallback_filename:
                candidates.extend([local_dir / fallback_filename, script_dir / fallback_filename, Path.cwd() / fallback_filename])
            for p in candidates:
                if p.exists():
                    log(f"Using local fallback: {p}")
                    return read_text_file(p)
            where = ", ".join(str(p) for p in candidates) if candidates else "no fallback filename"
            raise RuntimeError(f"Could not download source and local fallback was not found: {where}") from e

    p = Path(source).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p
    return read_text_file(p)


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
            if line not in seen:
                seen.add(line)
                links.append(line)
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


def parse_curl_meta(stdout: str) -> Tuple[str, str]:
    """Parse curl -w metadata robustly on Windows/Linux/macOS."""
    # Our new curl command writes only this marker to stdout.
    m = re.search(r"__CURL_META__\s*(\d{3})\s+([0-9.]+)", stdout)
    if m:
        return m.group(1), m.group(2)
    # Backward compatibility: marker after body, with actual newline or literal \n.
    m = re.search(r"(?:\n|\\n)__CURL_META__\s*(\d{3})\s+([0-9.]+)", stdout)
    if m:
        return m.group(1), m.group(2)
    # Last resort: curl output may contain only '204 0.123456'.
    m = re.search(r"(?m)^\s*(\d{3})\s+([0-9.]+)\s*$", stdout.strip())
    if m:
        return m.group(1), m.group(2)
    return "000", ""


def curl_test(curl_bin: str, url: str, socks_port: int, socks_user: str, socks_pass: str, timeout: int) -> TestResult:
    proxy = f"socks5h://{urllib.parse.quote(socks_user)}:{urllib.parse.quote(socks_pass)}@127.0.0.1:{socks_port}"
    # Important: use -o os.devnull so stdout contains ONLY metadata.
    # This fixes Windows cases where body bytes broke parsing and produced g=0(000) while curl returned 0.
    fmt = "__CURL_META__ %{http_code} %{time_total}"
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
        "-o",
        os.devnull,
        "-w",
        fmt,
        url,
    ]
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=False, timeout=timeout + 3)
    except subprocess.TimeoutExpired:
        return TestResult(ok=False, error="curl process timeout")

    stdout = decode_output(p.stdout).strip()
    stderr = decode_output(p.stderr).strip()
    http_code, time_total = parse_curl_meta(stdout)

    # For access checking, any real HTTP response means the target service was reachable.
    # 400/403/404/429 still prove connectivity; 000 means no HTTP response.
    ok = p.returncode == 0 and http_code != "000"
    if not ok:
        if stderr:
            error = stderr
        elif p.returncode != 0:
            error = f"curl return code {p.returncode}"
        else:
            error = f"curl returned 0 but HTTP code was not parsed; stdout={stdout[:120]!r}"
    else:
        error = ""
    return TestResult(ok=ok, http_code=http_code, time_total=time_total, error=error)


def check_one(
    index: int,
    link: str,
    timeout: int,
    xray_bin: str,
    curl_bin: str,
    mode: str,
    service_workers: int,
    do_all_tests: bool,
) -> LinkResult:
    started = time.time()
    socks_port = free_port()
    socks_user = f"u{os.getpid()}_{index}_{random.randint(1000, 9999)}"
    socks_pass = "".join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
    name = f"link-{index}"
    proc: Optional[subprocess.Popen] = None

    empty = TestResult(False)

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
                err_text = ""
                if proc.poll() is not None:
                    try:
                        _, err = proc.communicate(timeout=2)
                        err_text = decode_output(err).strip()[:300]
                    except Exception:
                        pass
                return LinkResult(index, name, link, False, False, False, False, False, False, False, False,
                                  "000", "000", "000", "000", "000", "000", "000", None,
                                  f"xray did not start/listen: {err_text}", time.time() - started)

            # Run tests concurrently through the same temporary SOCKS proxy.
            requested = ["cfg", "ip", "google", "youtube", "instagram", "telegram", "whatsapp"]
            results: Dict[str, TestResult] = {k: empty for k in requested}
            with ThreadPoolExecutor(max_workers=max(1, service_workers)) as ex:
                futs = {
                    ex.submit(curl_test, curl_bin, TESTS[k], socks_port, socks_user, socks_pass, timeout): k
                    for k in requested
                }
                for fut in as_completed(futs):
                    k = futs[fut]
                    try:
                        results[k] = fut.result()
                    except Exception as e:
                        results[k] = TestResult(False, error=str(e)[:300])

            cfg = results["cfg"]
            ip = results["ip"]
            google = results["google"]
            yt = results["youtube"]
            ig = results["instagram"]
            tg = results["telegram"]
            wa = results["whatsapp"]

            if mode == "light":
                ok = ip.ok and google.ok and yt.ok
            else:
                ok = ip.ok and google.ok and yt.ok and ig.ok and tg.ok and wa.ok

            err = "; ".join(x for x in [cfg.error, ip.error, google.error, yt.error, ig.error, tg.error, wa.error] if x)[:700]
            return LinkResult(
                index=index,
                name=name,
                link=link,
                ok=ok,
                cfg_ok=cfg.ok,
                ip_ok=ip.ok,
                google_ok=google.ok,
                youtube_ok=yt.ok,
                instagram_ok=ig.ok,
                telegram_ok=tg.ok,
                whatsapp_ok=wa.ok,
                cfg_http=cfg.http_code,
                ip_http=ip.http_code,
                google_http=google.http_code,
                youtube_http=yt.http_code,
                instagram_http=ig.http_code,
                telegram_http=tg.http_code,
                whatsapp_http=wa.http_code,
                cfg_ms=cfg.ms,
                error=err,
                elapsed=time.time() - started,
            )

    except Exception as e:
        return LinkResult(index, name, link, False, False, False, False, False, False, False, False,
                          "000", "000", "000", "000", "000", "000", "000", None,
                          str(e)[:700], time.time() - started)
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
        query = urllib.parse.urlencode(clean_params, doseq=False, safe=",-/")
        name = urllib.parse.unquote(parsed.fragment or "") or host
        fragment = urllib.parse.quote(name, safe="")
        return f"vless://{urllib.parse.quote(uuid, safe='-')}@{host_part}:{port}?{query}#{fragment}"
    except Exception:
        return link.strip()


def sort_key(r: LinkResult):
    return (r.cfg_ms is None, r.cfg_ms if r.cfg_ms is not None else 10**12, r.index)


def write_csv(path: str, results: Iterable[LinkResult], clean_links: bool = True) -> None:
    rows = sorted(results, key=sort_key)
    with open(path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow([
            "index", "name", "all_ok", "mode_ok",
            "cfg_ms", "cfg_ok", "cfg_http",
            "vless_ip_ok", "google_ok", "youtube_ok", "instagram_ok", "telegram_ok", "whatsapp_ok",
            "ip_http", "google_http", "youtube_http", "instagram_http", "telegram_http", "whatsapp_http",
            "elapsed_sec", "error", "link",
        ])
        for r in rows:
            w.writerow([
                r.index, r.name, int(r.ok), int(r.ok),
                r.cfg_ms if r.cfg_ms is not None else "", int(r.cfg_ok), r.cfg_http,
                int(r.ip_ok), int(r.google_ok), int(r.youtube_ok), int(r.instagram_ok), int(r.telegram_ok), int(r.whatsapp_ok),
                r.ip_http, r.google_http, r.youtube_http, r.instagram_http, r.telegram_http, r.whatsapp_http,
                f"{r.elapsed:.2f}", r.error,
                clean_vless_link(r.link) if clean_links else r.link,
            ])


def write_links(path: str, results: Iterable[LinkResult], clean_links: bool = True) -> None:
    rows = sorted(results, key=sort_key)
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            out_link = clean_vless_link(r.link) if clean_links else r.link.rstrip()
            f.write(out_link + "\n")


def choose_source_interactive() -> Tuple[str, str, str]:
    print("Choose VLESS source:")
    print("  1) CIDR")
    print("  2) SNI")
    print("  3) Enter custom URL or local file path")
    choice = input("Select source [1-3]: ").strip() or "1"
    if choice == "1":
        p = SOURCE_PRESETS["CIDR"]
        return "CIDR", p["url"], p["filename"]
    if choice == "2":
        p = SOURCE_PRESETS["SNI"]
        return "SNI", p["url"], p["filename"]
    custom = input("Enter URL or local file path: ").strip()
    return "CUSTOM", custom, Path(custom).name if custom else "links.txt"


def choose_mode_interactive() -> str:
    print("Choose check mode:")
    print("  1) normal - strict: IP + Google + YouTube + Instagram + Telegram + WhatsApp")
    print("  2) light  - soft: IP + Google + YouTube; other services are shown but not required")
    choice = input("Select mode [1-2]: ").strip() or "1"
    return "light" if choice == "2" else "normal"


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Check VLESS links from CIDR/SNI txt subscriptions")
    ap.add_argument("--input", "-i", help="local .txt file or URL with VLESS links/subscription")
    ap.add_argument("--source", choices=["CIDR", "SNI", "cidr", "sni"], help="use built-in source without menu")
    ap.add_argument("--mode", choices=["normal", "light"], help="normal=strict all services; light=IP+Google+YouTube")
    ap.add_argument("--local-dir", default=str(default_local_dir()), help="local fallback/cache directory for source txt files")
    ap.add_argument("--output", help="CSV output path. Default depends on source/mode")
    ap.add_argument("--working-output", help="TXT output path for working links. Default depends on source/mode")
    ap.add_argument("--limit", type=int, default=0, help="max links to check; 0 means all. Default: 0")
    ap.add_argument("--offset", type=int, default=0, help="skip first N links before applying limit")
    ap.add_argument("--workers", type=int, default=12, help="parallel VLESS configs. Default: 12")
    ap.add_argument("--service-workers", type=int, default=6, help="parallel service checks per config. Default: 6")
    ap.add_argument("--timeout", type=int, default=8, help="curl timeout seconds. Default: 8")
    ap.add_argument("--show-links", action="store_true", help="print full VLESS links in console")
    ap.add_argument("--save-failed", action="store_true", help="save failed rows to CSV too")
    ap.add_argument("--raw-output", action="store_true", help="save original links instead of cleaned client links")
    ap.add_argument("--all-tests-even-if-ip-fails", action="store_true", help="kept for compatibility; all tests are currently run in parallel")
    return ap


def main() -> int:
    args = build_parser().parse_args()

    xray_bin = shutil.which("xray") or shutil.which("xray.exe")
    curl_bin = shutil.which("curl") or shutil.which("curl.exe")
    if not xray_bin:
        print("ERROR: xray not found in PATH. Install xray-core first.", file=sys.stderr)
        return 2
    if not curl_bin:
        print("ERROR: curl not found in PATH.", file=sys.stderr)
        return 2

    fallback_filename = None
    if args.input:
        source_name = "CUSTOM"
        source = args.input
        if Path(source).name:
            fallback_filename = Path(source).name
    elif args.source:
        source_name = args.source.upper()
        preset = SOURCE_PRESETS[source_name]
        source = preset["url"]
        fallback_filename = preset["filename"]
    elif sys.stdin.isatty():
        source_name, source, fallback_filename = choose_source_interactive()
    else:
        source_name = "CIDR"
        preset = SOURCE_PRESETS[source_name]
        source = preset["url"]
        fallback_filename = preset["filename"]

    mode = args.mode
    if not mode:
        mode = choose_mode_interactive() if sys.stdin.isatty() else "normal"
    log(f"Selected source: {source_name}")
    log(f"Selected mode: {mode}")

    local_dir = Path(args.local_dir).expanduser()
    text = read_source(source, local_dir=local_dir, fallback_filename=fallback_filename, timeout=30)
    links = extract_vless_links(text)

    if args.offset > 0:
        links = links[args.offset:]
    if args.limit and args.limit > 0:
        links = links[:args.limit]

    if not links:
        print("ERROR: no vless:// links found. If this is a subscription, make sure it is plain text or base64.", file=sys.stderr)
        return 1

    output = args.output or f"vless_check_results_{source_name}_{mode}.csv"
    working_output = args.working_output or f"working_vless_{source_name}_{mode}.txt"

    log(f"Found {len(links)} VLESS links. Checking with workers={args.workers}, service-workers={args.service_workers}, timeout={args.timeout}s")
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
                mode,
                args.service_workers,
                args.all_tests_even_if_ip_fails,
            ): (i, link)
            for i, link in enumerate(links, start=1 + max(0, args.offset))
        }
        total = len(futures)
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            shown = r.link if args.show_links else mask_link(r.link)
            status = ctext("OK", "green") if r.ok else ctext("FAIL", "red")
            cfg = f"{r.cfg_ms}ms" if r.cfg_ms is not None else "-ms"
            log(
                f"[{r.index}/{(args.offset if args.offset else 0) + total}] {status} cfg={cfg} "
                f"ip={int(r.ip_ok)}({r.ip_http}) g={int(r.google_ok)}({r.google_http}) "
                f"yt={int(r.youtube_ok)}({r.youtube_http}) ig={int(r.instagram_ok)}({r.instagram_http}) "
                f"tg={int(r.telegram_ok)}({r.telegram_http}) wa={int(r.whatsapp_ok)}({r.whatsapp_http}) {shown}"
                + (f" | {r.error}" if r.error else "")
            )

    working_results = [r for r in results if r.ok]
    csv_results = results if args.save_failed else working_results
    clean_links = not args.raw_output
    write_csv(output, csv_results, clean_links=clean_links)
    write_links(working_output, working_results, clean_links=clean_links)

    total = len(results)
    all_ok = len(working_results)
    ip_ok = sum(1 for r in results if r.ip_ok)
    google_ok = sum(1 for r in results if r.google_ok)
    yt_ok = sum(1 for r in results if r.youtube_ok)
    ig_ok = sum(1 for r in results if r.instagram_ok)
    tg_ok = sum(1 for r in results if r.telegram_ok)
    wa_ok = sum(1 for r in results if r.whatsapp_ok)
    cfg_ok = sum(1 for r in results if r.cfg_ok)
    fastest = min((r.cfg_ms for r in working_results if r.cfg_ms is not None), default=None)

    print("\nSummary")
    print(f"  total checked:   {total}")
    print(f"  working saved:   {all_ok}")
    print(f"  mode:            {mode}")
    print(f"  cfg latency ok:  {cfg_ok}")
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
    print(f"  txt working:     {working_output}" + (" (clean client links)" if clean_links else " (raw links)"))
    print(f"  csv:             {output}" + (" (all results)" if args.save_failed else " (working only)"))

    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
