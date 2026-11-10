#!/usr/bin/env python3
"""Collect public VMess share links from explicitly listed source files.
Filters links whose decoded VMess JSON uses network=grpc.
Country and TCP latency are informational hints, not proof that a proxy works.
"""
import base64
import concurrent.futures
import json
import re
import socket
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

SOURCES_FILE = Path("sources.txt")
OUT_FILE = Path("results.txt")
TIMEOUT = 4
LINK_RE = re.compile(r"vmess://[A-Za-z0-9+/=_-]+", re.I)

def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "VMess-GRPC-Scanner/1.0"})
    with urllib.request.urlopen(req, timeout=15) as response:
        return response.read().decode("utf-8", errors="ignore")

def decode_vmess(link):
    raw = link[len("vmess://"):]
    raw += "=" * (-len(raw) % 4)
    try:
        data = base64.urlsafe_b64decode(raw.encode()).decode("utf-8", errors="strict")
        obj = json.loads(data)
        if str(obj.get("net", "")).lower() != "grpc":
            return None
        host = obj.get("add", "")
        port = int(obj.get("port", 0))
        if not host or not (1 <= port <= 65535):
            return None
        return obj, host, port
    except Exception:
        return None

def tcp_latency(host, port):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return round((time.perf_counter() - start) * 1000)
    except Exception:
        return None

def country_for(host):
    # Best-effort country lookup; the IP geolocation service may rate-limit requests.
    try:
        ip = socket.gethostbyname(host)
        url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode"
        with urllib.request.urlopen(url, timeout=5) as response:
            data = json.loads(response.read().decode())
        if data.get("status") == "success":
            return data.get("country", "Unknown"), data.get("countryCode", "")
    except Exception:
        pass
    return "Unknown", ""

def main():
    urls = [line.strip() for line in SOURCES_FILE.read_text().splitlines()
            if line.strip() and not line.lstrip().startswith("#")]
    found = set()
    for url in urls:
        try:
            content = fetch(url)
            found.update(LINK_RE.findall(content))
        except Exception as exc:
            print(f"[WARN] Source failed: {url} ({exc})")

    records = []
    for link in found:
        parsed = decode_vmess(link)
        if not parsed:
            continue
        obj, host, port = parsed
        records.append({"link": link, "name": obj.get("ps", "VMess-gRPC"),
                        "host": host, "port": port})

    # A TCP handshake is only a basic reachability/latency hint.
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
        futures = [pool.submit(tcp_latency, r["host"], r["port"]) for r in records]
        for record, future in zip(records, futures):
            record["latency_ms"] = future.result()

    # Geolocation is done after deduplication and may return Unknown.
    for record in records:
        record["country"], record["country_code"] = country_for(record["host"])

    records.sort(key=lambda r: (
        r["country"].lower(),
        r["latency_ms"] is None,
        r["latency_ms"] if r["latency_ms"] is not None else 10**9
    ))

    lines = [
        "# Public VMess gRPC links collected from sources.txt",
        "# TCP latency is not an end-to-end proxy speed test.",
        "# Use only servers you are authorized to use.",
        ""
    ]
    for r in records:
        latency = f'{r["latency_ms"]} ms' if r["latency_ms"] is not None else "unreachable/timeout"
        lines.append(f'# {r["country"]} | {r["name"]} | TCP: {latency} | {r["host"]}:{r["port"]}')
        lines.append(r["link"])
        lines.append("")

    OUT_FILE.write_text("\n".join(lines), encoding="utf-8")
    print(f"Saved {len(records)} VMess gRPC link(s) to {OUT_FILE}")

if __name__ == "__main__":
    main()
