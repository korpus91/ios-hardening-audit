#!/usr/bin/env python3
"""
ios-hardening-audit: offline security hardening audit of Cisco IOS / IOS-XE configurations.

Feed it saved running-configs (one or many files) and get a per-device findings
list with severity, the evidence line, and the fix. Pure text parsing, standard
library only, never connects to a device.

Rules cover common baseline items found in CIS Cisco IOS benchmarks and vendor
hardening guides: AAA, credential storage, management-plane access, SNMP,
HTTP server, logging, NTP and banners. A missing line is reported as "not
found in config"; some defaults vary by IOS release, so verify against yours.

Exit codes: 0 no high findings, 1 high findings present, 2 error.
"""
import argparse
import csv
import json
import re
import sys
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class Finding:
    device: str
    rule: str
    severity: str  # high | medium | low
    title: str
    evidence: str
    fix: str


def blocks(lines, header_re):
    """Yield (header, body_lines) for every block whose header matches header_re."""
    rx = re.compile(header_re)
    i = 0
    while i < len(lines):
        if rx.match(lines[i]):
            hdr, body = lines[i], []
            i += 1
            while i < len(lines) and lines[i].startswith(" "):
                body.append(lines[i].strip())
                i += 1
            yield hdr, body
        else:
            i += 1


def audit_config(name: str, text: str) -> list:
    lines = [l.rstrip() for l in text.splitlines()]
    top = [l for l in lines if l and not l.startswith(" ")]
    has = lambda rx: next((l for l in top if re.match(rx, l)), None)
    f = []
    add = lambda rule, sev, title, ev, fix: f.append(Finding(name, rule, sev, title, ev, fix))

    # Credentials
    if has(r"^enable password\b"):
        add("H01", "high", "enable password in use", "enable password <redacted>",
            "Remove 'enable password'; use 'enable algorithm-type scrypt secret <secret>'.")
    es = has(r"^enable secret\b")
    if not es:
        add("H02", "high", "No enable secret", "not found in config",
            "Configure 'enable algorithm-type scrypt secret <secret>'.")
    elif re.match(r"^enable secret 5 ", es):
        add("H03", "medium", "enable secret uses MD5 (type 5)", "enable secret 5 <hash>",
            "Re-set with 'enable algorithm-type scrypt secret' (type 9) or sha256 (type 8).")
    for l in top:
        m = re.match(r"^username (\S+) .*\bpassword (\d )?", l)
        if m:
            add("H04", "high", f"Local user '{m.group(1)}' stored with password, not secret",
                f"username {m.group(1)} ... password <redacted>",
                f"Re-create as 'username {m.group(1)} algorithm-type scrypt secret <secret>'.")
        m = re.match(r"^username (\S+) .*\bsecret 5 ", l)
        if m:
            add("H05", "medium", f"Local user '{m.group(1)}' secret uses MD5 (type 5)",
                f"username {m.group(1)} ... secret 5 <hash>", "Re-set with algorithm-type scrypt.")
    if not has(r"^service password-encryption"):
        add("H06", "low", "service password-encryption not enabled", "not found in config",
            "Enable it so any remaining type 0 passwords are at least obfuscated (type 7 is reversible, so prefer secrets).")

    # AAA
    if not has(r"^aaa new-model"):
        add("H07", "medium", "AAA not enabled", "not found in config",
            "Enable 'aaa new-model' with TACACS+ or RADIUS authentication and a local fallback.")
    elif not has(r"^aaa authentication login\b"):
        add("H08", "medium", "No AAA login authentication list", "not found in config",
            "Define 'aaa authentication login default group <tacacs-group> local'.")
    if has(r"^aaa new-model") and not has(r"^aaa accounting (exec|commands)\b"):
        add("H09", "low", "No AAA accounting for exec or commands", "not found in config",
            "Add 'aaa accounting exec default start-stop group <group>' and command accounting.")

    # Management plane
    if not has(r"^ip ssh version 2"):
        add("H10", "medium", "SSH version 2 not explicitly set", "not found in config",
            "Configure 'ip ssh version 2'.")
    http = has(r"^ip http server")
    if http:
        add("H11", "medium", "HTTP server enabled", http,
            "Use 'no ip http server'; keep 'ip http secure-server' only if a controller or WebUI needs it.")
    for hdr, body in blocks(lines, r"^line (vty|con)\b"):
        ti = next((b for b in body if b.startswith("transport input")), None)
        if hdr.startswith("line vty"):
            if ti is None:
                add("H12", "medium", f"{hdr}: transport input not set", "not found in block",
                    "Set 'transport input ssh' explicitly; defaults differ by release.")
            elif re.search(r"\b(telnet|all)\b", ti):
                add("H13", "high", f"{hdr}: Telnet allowed", ti, "Set 'transport input ssh'.")
            if not any(b.startswith("access-class") for b in body):
                add("H14", "medium", f"{hdr}: no access-class", "not found in block",
                    "Restrict management sources with 'access-class <acl> in'.")
        if any(re.match(r"exec-timeout 0( 0)?$", b) for b in body):
            add("H15", "medium", f"{hdr}: session never times out", "exec-timeout 0 0",
                "Set 'exec-timeout 10 0' or lower.")

    # SNMP
    for l in top:
        m = re.match(r"^snmp-server community (\S+)(.*)", l)
        if not m:
            continue
        comm, rest = m.group(1), m.group(2)
        ev = f"snmp-server community <redacted>{rest}"
        if comm.lower() in ("public", "private"):
            add("H16", "high", "Default SNMP community string", f"snmp-server community {comm}{rest}",
                "Remove it. Prefer SNMPv3 authPriv; at minimum use a strong community with an ACL.")
        if re.search(r"\bRW\b", rest):
            add("H17", "high", "SNMP read-write community", ev, "Remove RW communities; use SNMPv3 with views if writes are needed.")
        if not re.search(r"\b(RO|RW)\s+\S+", rest) or re.search(r"\b(RO|RW)\s*$", rest):
            add("H18", "medium", "SNMP community without an ACL", ev, "Append an access list: 'snmp-server community <c> RO <acl>'.")

    # Logging, time, banner
    if not has(r"^logging (host|server)\b"):
        add("H19", "medium", "No remote syslog server", "not found in config", "Configure 'logging host <collector>'.")
    if not has(r"^service timestamps log datetime"):
        add("H20", "low", "Log timestamps not set", "not found in config",
            "Configure 'service timestamps log datetime msec localtime show-timezone'.")
    if not has(r"^ntp server\b"):
        add("H21", "medium", "No NTP server", "not found in config",
            "Configure 'ntp server <ip>' so logs correlate; add NTP authentication where supported.")
    if not has(r"^banner (login|motd)\b"):
        add("H22", "low", "No login banner", "not found in config",
            "Add a legal-notice 'banner login' approved by the client's legal team.")
    if not has(r"^login block-for\b"):
        add("H23", "low", "No login brute-force protection", "not found in config",
            "Configure 'login block-for 120 attempts 5 within 60'.")
    return f


SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Offline Cisco IOS / IOS-XE hardening audit")
    p.add_argument("configs", nargs="+", help="saved running-config files (globs allowed)")
    p.add_argument("--csv", help="write findings to CSV")
    p.add_argument("--json", help="write findings to JSON")
    p.add_argument("--min-severity", choices=["high", "medium", "low"], default="low")
    a = p.parse_args(argv)

    files = []
    for pat in a.configs:
        hits = sorted(Path().glob(pat)) if any(c in pat for c in "*?[") else [Path(pat)]
        files.extend(h for h in hits if h.is_file())
    if not files:
        print("error: no config files found", file=sys.stderr)
        return 2

    limit = SEV_ORDER[a.min_severity]
    findings = []
    for fp in files:
        try:
            text = fp.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"error: {fp}: {e}", file=sys.stderr)
            return 2
        findings += [x for x in audit_config(fp.stem, text) if SEV_ORDER[x.severity] <= limit]
    findings.sort(key=lambda x: (x.device, SEV_ORDER[x.severity], x.rule))

    for dev in sorted({x.device for x in findings} | {f.stem for f in files}):
        mine = [x for x in findings if x.device == dev]
        counts = {s: sum(1 for x in mine if x.severity == s) for s in SEV_ORDER}
        print(f"\n{dev}: {counts['high']} high, {counts['medium']} medium, {counts['low']} low")
        for x in mine:
            print(f"  [{x.severity.upper():6}] {x.rule} {x.title}\n           evidence: {x.evidence}\n           fix: {x.fix}")

    if a.csv:
        with open(a.csv, "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=list(Finding.__dataclass_fields__))
            w.writeheader()
            w.writerows(asdict(x) for x in findings)
    if a.json:
        Path(a.json).write_text(json.dumps([asdict(x) for x in findings], indent=2), encoding="utf-8")

    return 1 if any(x.severity == "high" for x in findings) else 0


if __name__ == "__main__":
    sys.exit(main())