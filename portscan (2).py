#!/usr/bin/env python3
"""portscan.py - a small nmap-style TCP port scanner.

Uses only the Python 3 standard library. Performs a plain TCP connect scan,
looks up service names, and can grab a short banner from open ports.

Only scan systems you own or have written permission to test.

Examples:
    python3 portscan.py 127.0.0.1
    python3 portscan.py 192.168.1.10 -p 1-1024 --banner
    python3 portscan.py scanme.nmap.org -p 22,80,443
    python3 portscan.py 192.168.1.0/24 --top 100
    python3 portscan.py 10.0.0.5 -p- --workers 300 --json results.json
"""

import argparse
import csv
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Commonly used ports, roughly ordered by how often they turn up.
TOP_PORTS = [
    80, 443, 22, 21, 25, 53, 110, 143, 3389, 445, 139, 135, 3306, 8080, 23,
    993, 995, 587, 5900, 1723, 111, 8443, 5432, 1433, 6379, 27017, 9200, 11211,
    5060, 389, 636, 873, 2049, 5000, 5985, 5986, 8000, 8008, 8081, 8888, 9000,
    9090, 10000, 1521, 2222, 3000, 4443, 5601, 6000, 7001, 9100, 49152, 161,
    162, 123, 69, 67, 68, 514, 548, 631, 993, 465, 119, 79, 88, 179, 427,
    554, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1900, 2000, 2001, 3128,
    3306, 3690, 4899, 5001, 5002, 5003, 5004, 5009, 5051, 5101, 5190, 5357,
    5631, 5666, 5800, 6001, 6646, 7070, 8009, 8010, 8082, 8180, 8400, 8800,
]

# Drop repeated entries (keeping order) so --top N really means N ports.
TOP_PORTS = list(dict.fromkeys(TOP_PORTS))

MAX_HOSTS = 1024
NOTICE = "Only scan systems you own or have written permission to test."

# Fallback names for systems without a services file (some containers, minimal OSes).
COMMON_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 631: "ipp", 636: "ldaps", 993: "imaps", 995: "pop3s",
    1433: "ms-sql-s", 1521: "oracle", 2049: "nfs", 3306: "mysql",
    3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}


def parse_ports(spec):
    """Turn '22,80,1000-1010' (or '-' for every port) into a sorted list."""
    if spec == "-":
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            lo, hi = int(lo), int(hi)
            if lo > hi:
                raise ValueError(f"bad range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"port out of range (1-65535): {bad[0]}")
    return sorted(ports)


def expand_targets(target):
    """Return a list of host strings from a hostname, IP, or CIDR block."""
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return [target]  # treat as hostname
    hosts = [str(h) for h in net.hosts()] or [str(net.network_address)]
    if len(hosts) > MAX_HOSTS:
        raise ValueError(
            f"{target} covers {len(hosts)} hosts; limit is {MAX_HOSTS}. "
            "Scan a smaller block."
        )
    return hosts


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return COMMON_SERVICES.get(port, "unknown")


def grab_banner(sock, port, timeout):
    """Listen briefly for a greeting (SSH, FTP, SMTP speak first). If the
    service stays silent, send one harmless HTTP HEAD request and read the reply."""
    data = b""
    try:
        sock.settimeout(min(timeout, 0.5))
        try:
            data = sock.recv(256)
        except socket.timeout:
            data = b""
        if not data:
            sock.settimeout(timeout)
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(256)
    except OSError:
        pass
    text = data.decode("utf-8", errors="replace").strip()
    return " ".join(text.split())[:120]


def scan_port(host, port, timeout, want_banner):
    """Return (port, state, banner). State is open, closed or filtered."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((host, port))
        if code == 0:
            banner = grab_banner(sock, port, timeout) if want_banner else ""
            return port, "open", banner
        # ECONNREFUSED means the host answered with a reset.
        if code in (111, 10061):
            return port, "closed", ""
        return port, "filtered", ""
    except socket.timeout:
        return port, "filtered", ""
    except OSError:
        return port, "filtered", ""
    finally:
        sock.close()


def scan_host(host, ports, timeout, workers, want_banner, show_closed):
    try:
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        return {"host": host, "ip": None, "error": "could not resolve", "ports": []}

    results = []
    pool = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = [
            pool.submit(scan_port, ip, p, timeout, want_banner) for p in ports
        ]
        for fut in as_completed(futures):
            port, state, banner = fut.result()
            if state == "open" or show_closed:
                results.append(
                    {
                        "port": port,
                        "state": state,
                        "service": service_name(port),
                        "banner": banner,
                    }
                )
    except KeyboardInterrupt:
        # Drop the queued ports so Ctrl+C stops within about one timeout.
        try:
            pool.shutdown(wait=False, cancel_futures=True)  # Python 3.9+
        except TypeError:
            for fut in futures:
                fut.cancel()
            pool.shutdown(wait=False)
        raise
    else:
        pool.shutdown()
    results.sort(key=lambda r: r["port"])
    return {"host": host, "ip": ip, "error": None, "ports": results}


def print_report(report, scanned, elapsed):
    host = report["host"]
    ip = report["ip"]
    label = host if ip is None or host == ip else f"{host} ({ip})"
    print(f"\nScan report for {label}")
    if report["error"]:
        print(f"  {report['error']}")
        return
    if not report["ports"]:
        print(f"  No open ports found among {scanned} scanned.")
        return
    print(f"  {'PORT':<12}{'STATE':<10}{'SERVICE':<18}BANNER")
    for r in report["ports"]:
        print(
            f"  {str(r['port']) + '/tcp':<12}{r['state']:<10}"
            f"{r['service']:<18}{r['banner']}"
        )
    opened = sum(1 for r in report["ports"] if r["state"] == "open")
    print(f"  {opened} open of {scanned} scanned in {elapsed:.1f}s")


def write_outputs(reports, json_path, csv_path):
    if json_path:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(reports, f, indent=2)
        print(f"\nSaved JSON to {json_path}")
    if csv_path:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["host", "ip", "port", "state", "service", "banner"])
            for rep in reports:
                for r in rep["ports"]:
                    w.writerow(
                        [rep["host"], rep["ip"], r["port"], r["state"],
                         r["service"], r["banner"]]
                    )
        print(f"Saved CSV to {csv_path}")


def build_parser():
    p = argparse.ArgumentParser(
        description="Small nmap-style TCP connect port scanner. " + NOTICE
    )
    p.add_argument("target", help="hostname, IP address, or CIDR block (e.g. 192.168.1.0/24)")
    group = p.add_mutually_exclusive_group()
    group.add_argument("-p", "--ports", default=None,
                       help="ports to scan: 22,80 or 1-1024 or - for all (default: 1-1024)")
    group.add_argument("--top", type=int, metavar="N",
                       help="scan the N most common ports (max %d)" % len(TOP_PORTS))
    p.add_argument("-t", "--timeout", type=float, default=1.0,
                   help="seconds to wait per port (default 1.0)")
    p.add_argument("-w", "--workers", type=int, default=100,
                   help="parallel connections (default 100, max 1000)")
    p.add_argument("-b", "--banner", action="store_true",
                   help="try to read a short banner from open ports")
    p.add_argument("--show-closed", action="store_true",
                   help="also list closed and filtered ports")
    p.add_argument("--json", metavar="FILE", help="write results to a JSON file")
    p.add_argument("--csv", metavar="FILE", help="write results to a CSV file")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    try:
        if args.top is not None:
            if not 1 <= args.top <= len(TOP_PORTS):
                raise ValueError(f"--top must be between 1 and {len(TOP_PORTS)}")
            ports = sorted(set(TOP_PORTS[: args.top]))
        else:
            ports = parse_ports(args.ports or "1-1024")
        hosts = expand_targets(args.target)
    except ValueError as err:
        print(f"error: {err}", file=sys.stderr)
        return 2

    workers = max(1, min(args.workers, 1000))
    print(f"portscan: {len(hosts)} host(s), {len(ports)} port(s). {NOTICE}")

    reports = []
    try:
        for host in hosts:
            start = time.time()
            rep = scan_host(host, ports, args.timeout, workers,
                            args.banner, args.show_closed)
            reports.append(rep)
            # Skip silent hosts in big sweeps so the output stays readable.
            if len(hosts) > 1 and not rep["ports"] and not rep["error"]:
                continue
            print_report(rep, len(ports), time.time() - start)
    except KeyboardInterrupt:
        print("\nInterrupted. Saving the hosts that finished.")

    write_outputs(reports, args.json, args.csv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
