# ios-hardening-audit

[![ci](https://github.com/korpus91/ios-hardening-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/korpus91/ios-hardening-audit/actions/workflows/ci.yml) [![PyPI](https://img.shields.io/pypi/v/ios-hardening-audit)](https://pypi.org/project/ios-hardening-audit/)

Offline security hardening audit for Cisco IOS and IOS-XE running-configs. Point it at one config or a folder of fifty and get, per device, every gap with severity, the evidence line and the exact fix.

```bash
pip install ios-hardening-audit
ios-harden configs/*.cfg --csv findings.csv
```

## Rules

| ID | Severity | Check |
|---|---|---|
| H01 | high | `enable password` in use |
| H02 | high | no `enable secret` |
| H03 | medium | `enable secret` stored as MD5 (type 5) |
| H04 | high | local user stored with `password` instead of `secret` |
| H05 | medium | local user secret stored as MD5 (type 5) |
| H06 | low | `service password-encryption` not enabled |
| H07 | medium | AAA not enabled |
| H08 | medium | no AAA login authentication list |
| H09 | low | no AAA exec or command accounting |
| H10 | medium | SSH version 2 not explicitly set |
| H11 | medium | HTTP server enabled |
| H12 | medium | vty `transport input` not set |
| H13 | high | Telnet allowed on vty |
| H14 | medium | vty without `access-class` |
| H15 | medium | `exec-timeout 0 0` on console or vty |
| H16 | high | default SNMP community (`public` / `private`) |
| H17 | high | SNMP read-write community |
| H18 | medium | SNMP community without an ACL |
| H19 | medium | no remote syslog |
| H20 | low | log timestamps not set |
| H21 | medium | no NTP server |
| H22 | low | no login banner |
| H23 | low | no `login block-for` brute-force protection |

The rules follow common baseline items from CIS Cisco IOS benchmarks and vendor hardening guides. A missing line is reported as "not found in config". Some defaults vary by IOS release, so confirm against the client's version before calling a finding.

## Safety

Text parsing only, standard library only, never connects to a device. Passwords, secrets and community strings are redacted from the evidence column, so reports are safe to share. The one exception is the literal default communities `public` and `private`, which are shown because they are the finding.

## Usage

```bash
ios-harden sw1.cfg
ios-harden "configs/*.cfg" --min-severity medium --json findings.json
```

Exit codes: `0` no high findings, `1` high findings present, `2` error, so it gates a CI pipeline or a scheduled job cleanly.

Pairs with [cisco-config-drift](https://github.com/korpus91/cisco-config-drift): pull the configs read-only, then audit them offline.

## Tests

```bash
pip install pytest && python -m pytest
```

## License

MIT. See LICENSE. Security reports: see SECURITY.md.