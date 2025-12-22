#!/usr/bin/env python3

"""
Fast LAN scanner for macOS/Linux using asyncio with ping-based discovery.

Features
- Ping discovery (like the shell version) or TCP/nmap discovery
- Parallel port scan with timeouts and bounded concurrency
- Defaults to 192.168.0.0/24, or auto-detects local /24
- Reverse DNS hostname resolution and ARP MAC lookup (best-effort)
- Output formats: text, csv, json; optional SSH hints

Notes
- Ping discovery matches the shell script behavior and populates ARP for MAC lookups.
- TCP discovery is available as a fallback if ping is unavailable.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import json
import os
import re
import shlex
import socket
import subprocess
import math
import platform
from typing import Dict, List, Optional, Set, Tuple, Iterable


DEFAULT_PORTS = [
    22, 80, 443, 53, 139, 445, 548, 631, 5353, 8000, 8080, 8443,
    3389, 5432, 5900, 1883, 3306, 9100, 32400, 27017, 5000, 21, 23, 25,
]

# Ports used to detect liveness in TCP discovery mode
DEFAULT_PROBE_PORTS = [22, 80, 443, 53, 445, 139, 5353]


def parse_ports(s: str) -> List[int]:
    ports: Set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            for p in range(a, b + 1):
                if 1 <= p <= 65535:
                    ports.add(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(ports)


def normalize_prefix(subnet: str) -> str:
    # Accept: 192.168.0.0/24, 192.168.0., 192.168.0.0
    subnet = subnet.strip()
    if subnet.endswith("/24"):
        base = subnet.split("/")[0]
        parts = base.split(".")
        if len(parts) != 4:
            raise ValueError(f"Invalid subnet: {subnet}")
        return ".".join(parts[:3]) + "."
    if subnet.endswith("."):
        parts = subnet.split(".")
        if len(parts) != 4:  # e.g. [192,168,0,""]
            raise ValueError(f"Invalid prefix: {subnet}")
        return subnet
    parts = subnet.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + "."
    raise ValueError(f"Unsupported subnet format: {subnet}")


def find_private_ipv4_from_ifconfig() -> Optional[str]:
    try:
        out = subprocess.check_output(["ifconfig"], text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return None
    # Match inet addresses, exclude 127.0.0.1
    candidates: List[str] = []
    for line in out.splitlines():
        m = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\b", line)
        if not m:
            continue
        ip = m.group(1)
        if ip.startswith("127."):
            continue
        candidates.append(ip)
    # Choose first private-range address
    for ip in candidates:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private:
                return ip
        except ValueError:
            continue
    return candidates[0] if candidates else None


def autodetect_prefix() -> Optional[str]:
    ip = find_private_ipv4_from_ifconfig()
    if not ip:
        return None
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    return ".".join(parts[:3]) + "."


async def probe_port(ip: str, port: int, timeout: float, sem: asyncio.Semaphore) -> Tuple[str, int, str]:
    # Returns (ip, port, status) where status is "open", "refused", or "timeout"
    async with sem:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            try:
                writer.close()
                if hasattr(writer, "wait_closed"):
                    await writer.wait_closed()
            except Exception:
                pass
            return (ip, port, "open")
        except asyncio.TimeoutError:
            return (ip, port, "timeout")
        except (ConnectionRefusedError, OSError):
            # Refused means host reachable but port closed
            return (ip, port, "refused")

async def ping_one(ip: str, timeout: float, sem: asyncio.Semaphore) -> Tuple[str, bool]:
    """Ping one host using system ping. Returns (ip, alive)."""
    system = platform.system()
    if system == "Darwin":
        # macOS: -n numeric, -c 1 one probe, -t 64 TTL
        cmd = ["ping", "-n", "-c", "1", "-t", "64", ip]
        proc_timeout = timeout
    else:
        # Linux (iputils): -W wait seconds for reply
        w = max(1, int(math.ceil(timeout)))
        cmd = ["ping", "-n", "-c", "1", "-W", str(w), ip]
        proc_timeout = timeout + 0.2
    async with sem:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                await asyncio.wait_for(proc.communicate(), timeout=proc_timeout)
            except asyncio.TimeoutError:
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
                return ip, False
            return ip, (proc.returncode == 0)
        except FileNotFoundError:
            # ping missing
            return ip, False


async def discover_hosts(prefix: str, mode: str, timeout: float, host_concurrency: int) -> List[str]:
    """Return list of alive IPs in the /24 for the given prefix (A.B.C.)."""
    targets = [f"{prefix}{i}" for i in range(1, 255)]
    sem = asyncio.Semaphore(host_concurrency)

    if mode == "ping":
        tasks = [ping_one(ip, timeout, sem) for ip in targets]
        alive = []
        for chunk_start in range(0, len(tasks), 512):
            chunk = tasks[chunk_start:chunk_start + 512]
            for ip, ok in await asyncio.gather(*chunk):
                if ok:
                    alive.append(ip)
        return alive

    if mode == "nmap":
        try:
            proc = await asyncio.create_subprocess_exec(
                "nmap", "-n", "-sn", f"{prefix}0/24", "-oG", "-",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await proc.communicate()
            if proc.returncode == 0 and out:
                lines = out.decode().splitlines()
                ips = [line.split()[1] for line in lines if "Status: Up" in line]
                return ips
        except FileNotFoundError:
            pass
        # fallback to ping if nmap missing
        return await discover_hosts(prefix, "ping", timeout, host_concurrency)

    # TCP discovery: try a few typical ports; consider refused as alive
    ports = DEFAULT_PROBE_PORTS
    conn_sem = asyncio.Semaphore(host_concurrency)
    tasks = [probe_port(ip, p, timeout, conn_sem) for ip in targets for p in ports]
    alive_set: Set[str] = set()
    for chunk_start in range(0, len(tasks), 4096):
        chunk = tasks[chunk_start:chunk_start + 4096]
        for ip, _p, st in await asyncio.gather(*chunk):
            if st in ("open", "refused"):
                alive_set.add(ip)
    return sorted(alive_set, key=lambda s: int(ipaddress.IPv4Address(s)))


def reverse_dns(ip: str) -> str:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        return name.rstrip('.')
    except Exception:
        return "-"


def arp_mac(ip: str) -> str:
    # Try `arp -n ip` first, then fallback to `arp -a` search
    try:
        out = subprocess.check_output(["arp", "-n", ip], text=True, stderr=subprocess.DEVNULL)
        # macOS: ? (192.168.0.10) at a1:b2:c3:d4:e5:f6 on en0 ifscope [ethernet]
        m = re.search(r"\bat\s+([0-9a-f:]{11,})\b", out, re.IGNORECASE)
        if m:
            return m.group(1)
    except Exception:
        pass
    try:
        out = subprocess.check_output(["arp", "-a"], text=True, stderr=subprocess.DEVNULL)
        # line like: hostname (192.168.0.10) at a1:b2:c3:d4:e5:f6 on en0 ...
        ip_pat = re.escape(f"({ip})")
        pat = re.compile(ip_pat + r"\s+at\s+([0-9a-f:]{11,})", re.IGNORECASE)
        for line in out.splitlines():
            m = pat.search(line)
            if m:
                return m.group(1)
    except Exception:
        pass
    return "-"


def print_text(rows: List[Dict[str, object]]) -> None:
    header = ("IP", "Hostname", "MAC", "Open TCP Ports")
    print(f"{header[0]:15}  {header[1]:32}  {header[2]:17}  {header[3]}")
    for r in rows:
        ip = r["ip"]
        name = r["hostname"]
        mac = r["mac"]
        ports = ",".join(str(p) for p in r["open_tcp_ports"]) if r["open_tcp_ports"] else ""
        print(f"{ip:15}  {name:32}  {mac:17}  {ports}")


def print_csv(rows: List[Dict[str, object]]) -> None:
    print("IP,Hostname,MAC,OpenTCPPorts")
    for r in rows:
        name = str(r["hostname"]).replace('"', '""')
        ports = ",".join(str(p) for p in r["open_tcp_ports"]) if r["open_tcp_ports"] else ""
        print(f'"{r["ip"]}","{name}","{r["mac"]}","{ports}"')


def print_json(rows: List[Dict[str, object]]) -> None:
    print(json.dumps(rows, indent=2))


async def main_async(args: argparse.Namespace) -> int:
    # Determine prefix
    if args.auto and not args.subnet:
        prefix = autodetect_prefix() or "192.168.0."
        if not prefix:
            print("[!] Could not auto-detect local subnet; defaulting to 192.168.0.0/24")
            prefix = "192.168.0."
    else:
        prefix = normalize_prefix(args.subnet)

    ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
    timeout = args.timeout
    host_conc = max(1, args.host_concurrency)
    conn_conc = max(1, args.conn_concurrency)

    print(f"[+] Discovering hosts on {prefix}0/24 via {args.discovery}")
    alive_ips = await discover_hosts(prefix, args.discovery, timeout, host_conc)
    print(f"[+] Live hosts found: {len(alive_ips)}")

    if not alive_ips and not args.include_unresponsive:
        print("[+] Done")
        return 0

    # Port scan only alive (unless include_unresponsive)
    scan_ips: Iterable[str] = alive_ips if not args.include_unresponsive else [f"{prefix}{i}" for i in range(1,255)]

    print(f"[+] Scanning TCP ports ({len(ports)} ports) with concurrency={conn_conc}, timeout={timeout}s")
    sem = asyncio.Semaphore(conn_conc)
    port_tasks = [probe_port(ip, p, timeout, sem) for ip in scan_ips for p in ports]
    open_map: Dict[str, List[int]] = {ip: [] for ip in scan_ips}
    for chunk_start in range(0, len(port_tasks), 8192):
        chunk = port_tasks[chunk_start:chunk_start + 8192]
        for ip, port, st in await asyncio.gather(*chunk):
            if st == "open":
                open_map.setdefault(ip, []).append(port)

    # Build rows
    rows: List[Dict[str, object]] = []
    for ip in scan_ips:
        hostname = reverse_dns(ip)
        mac = arp_mac(ip)
        ports_open = sorted(open_map.get(ip, []))
        if ip not in alive_ips and not args.include_unresponsive:
            continue
        rows.append({
            "ip": ip,
            "hostname": hostname,
            "mac": mac,
            "open_tcp_ports": ports_open,
        })

    rows.sort(key=lambda r: int(ipaddress.IPv4Address(r["ip"])) )

    if args.output == "text":
        print_text(rows)
    elif args.output == "csv":
        print_csv(rows)
    elif args.output == "json":
        print_json(rows)
    else:
        print_text(rows)

    if args.ssh and rows:
        print("\n[SSH suggestions]")
        for r in rows:
            if 22 in r["open_tcp_ports"]:
                host_label = r["hostname"] if r["hostname"] != "-" else r["ip"]
                print(f"ssh {r['ip']}  # {host_label}")

    print("[+] Done")
    return 0


def build_argparser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Fast parallel LAN scanner (asyncio)")
    p.add_argument("--subnet", "-s", default="192.168.0.0/24",
                   help="Subnet (CIDR /24 or prefix like 192.168.0.)")
    p.add_argument("--auto", action="store_true",
                   help="Auto-detect local /24 from active interface")
    p.add_argument("--ports", "-p",
                   help="Comma-separated ports or ranges (e.g., 22,80,443 or 1-1024)")
    p.add_argument("--timeout", "-t", type=float, default=0.8,
                   help="Timeout for ping/connect in seconds (default: 0.8)")
    p.add_argument("--host-concurrency", type=int, default=256,
                   help="Concurrent hosts during discovery (default: 256)")
    p.add_argument("--conn-concurrency", type=int, default=1024,
                   help="Concurrent TCP connects during port scan (default: 1024)")
    p.add_argument("--discovery", choices=["ping", "tcp", "nmap"], default="ping",
                   help="Discovery method (default: ping)")
    p.add_argument("--output", "-o", choices=["text", "csv", "json"], default="text",
                   help="Output format (default: text)")
    p.add_argument("--ssh", action="store_true", help="Print SSH commands for hosts with 22 open")
    p.add_argument("--include-unresponsive", action="store_true",
                   help="Include IPs without any response (rare, based on timeouts)")
    return p


def main() -> int:
    args = build_argparser().parse_args()
    try:
        return asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
