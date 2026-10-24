from __future__ import annotations

import argparse
import ctypes
import json
import socket
import sys
import time
from pathlib import Path

import dns.flags
import dns.message
import dns.query
import dns.rdatatype
import dns.resolver

HOSTS_FILE = Path(r"C:\Windows\System32\drivers\etc\hosts")
HOSTS_MARKER = "# dns-defender"
SCAN_INTERVAL_SEC = 30
STATUS_FILE = Path("attack_status.json")

WATCHLIST = [
    ("www.example.com", "93.184.216.34"),
]


def resolve_ip(domain: str) -> str | None:
    try:
        return socket.gethostbyname(domain)
    except OSError:
        return None


def check_dnssec(domain: str, nameserver: str = "8.8.8.8") -> bool:
    try:
        query = dns.message.make_query(domain, dns.rdatatype.A, want_dnssec=True)
        response = dns.query.udp(query, nameserver, timeout=5)
        return bool(response.flags & dns.flags.AD)
    except Exception:
        return False


def report(domain: str, resolved_ip: str, trusted_ip: str, dnssec_ok: bool, is_attack: bool) -> None:
    print(f"\n--- {domain} ---")
    print(f"resolved: {resolved_ip}  trusted: {trusted_ip}")
    print(f"DNSSEC:   {'validated' if dnssec_ok else 'not validated'}")

    if is_attack:
        print(f"[!] MISMATCH -- possible spoofing/tunnel redirect for {domain}")
    else:
        print("[+] IP matches trusted baseline")


def write_status_file(domain: str, resolved_ip: str) -> None:
    STATUS_FILE.write_text(json.dumps({
        "attack_detected": True,
        "domain": domain,
        "malicious_ip": resolved_ip,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }))


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def block_domain(domain: str) -> bool:
    """Append a hosts-file entry redirecting domain to localhost. Requires admin."""
    if not is_admin():
        print("[!] Not running as admin -- can't edit hosts file")
        return False
    try:
        text = HOSTS_FILE.read_text()
        if domain in text and HOSTS_MARKER in text:
            return True
        with HOSTS_FILE.open("a") as f:
            f.write(f"127.0.0.1 {domain} {HOSTS_MARKER}\n")
        print(f"[+] Blocked {domain} via hosts file")
        return True
    except OSError as e:
        print(f"[-] Could not write hosts file: {e}")
        return False


def unblock_all() -> None:
    if not is_admin() or not HOSTS_FILE.exists():
        return
    try:
        lines = HOSTS_FILE.read_text().splitlines()
        kept = [line for line in lines if HOSTS_MARKER not in line]
        HOSTS_FILE.write_text("\n".join(kept) + "\n")
    except OSError:
        pass


def scan(watchlist: list[tuple[str, str]], block: bool) -> None:
    for domain, trusted_ip in watchlist:
        resolved = resolve_ip(domain)
        if resolved is None:
            print(f"[-] Could not resolve {domain}")
            continue
            
        dnssec_ok = check_dnssec(domain)
        is_attack = (resolved != trusted_ip)
        
        report(domain, resolved, trusted_ip, dnssec_ok, is_attack)
        
        if is_attack:
            write_status_file(domain, resolved)
            if block:
                block_domain(domain)


def main() -> None:
    parser = argparse.ArgumentParser(description="DNS Security Defender")
    parser.add_argument("--once", action="store_true", help="run a single scan and exit")
    parser.add_argument("--block", action="store_true", help="block flagged domains via hosts file (needs admin)")
    parser.add_argument("--interval", type=int, default=SCAN_INTERVAL_SEC, help="seconds between scans")
    args = parser.parse_args()

    print("DNS Security Defender")
    print(f"watching {len(WATCHLIST)} domain(s), blocking={'on' if args.block else 'off'}\n")

    try:
        while True:
            scan(WATCHLIST, block=args.block)
            if args.once:
                break
            print(f"\nnext scan in {args.interval}s (Ctrl+C to stop)")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nstopping, cleaning up...")
        if args.block:
            unblock_all()
        sys.exit(0)


if __name__ == "__main__":
    main()
