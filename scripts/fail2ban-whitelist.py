#!/usr/bin/env python3
"""Idempotently add ovpn_mgr's OpenVPN IPv4 pool to Fail2Ban DEFAULT ignoreip."""
import ipaddress
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime

if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} OPENVPN_CONF JAIL_LOCAL", file=sys.stderr)
    sys.exit(2)

conf_path, jail_path = sys.argv[1:]
try:
    conf_text = open(conf_path, encoding="utf-8").read()
except OSError as exc:
    print(f"Cannot read OpenVPN config {conf_path}: {exc}", file=sys.stderr)
    sys.exit(1)

network = None
for line in conf_text.splitlines():
    match = re.match(r"^\s*server\s+(\S+)\s+(\S+)", line)
    if match:
        try:
            network = str(ipaddress.IPv4Network(f"{match.group(1)}/{match.group(2)}", strict=False))
            break
        except (ipaddress.AddressValueError, ipaddress.NetmaskValueError):
            continue
if not network:
    print("Could not determine a valid IPv4 OpenVPN 'server <network> <netmask>' pool; Fail2Ban whitelist unchanged.", file=sys.stderr)
    sys.exit(1)

try:
    original = open(jail_path, encoding="utf-8").read() if os.path.exists(jail_path) else ""
except OSError as exc:
    print(f"Cannot read {jail_path}: {exc}", file=sys.stderr)
    sys.exit(1)

lines = original.splitlines()
section_start = section_end = None
for idx, line in enumerate(lines):
    if re.match(r"^\s*\[\s*DEFAULT\s*\]\s*(?:[;#].*)?$", line, re.I):
        section_start = idx
        section_end = len(lines)
        for j in range(idx + 1, len(lines)):
            if re.match(r"^\s*\[", lines[j]):
                section_end = j
                break
        break

if section_start is None:
    if lines and lines[-1].strip():
        lines.append("")
    lines.extend(["[DEFAULT]", f"ignoreip = 127.0.0.1/8 ::1 {network}"])
else:
    ignore_idx = None
    for idx in range(section_start + 1, section_end):
        if re.match(r"^\s*ignoreip\s*=", lines[idx], re.I):
            ignore_idx = idx
            break
    if ignore_idx is None:
        lines.insert(section_end, f"ignoreip = 127.0.0.1/8 ::1 {network}")
    else:
        # Keep any inline comment and all pre-existing ignore entries intact.
        before_comment, sep, comment = lines[ignore_idx].partition("#")
        if not sep:
            before_comment, sep, comment = before_comment.partition(";")
        match = re.match(r"^(\s*ignoreip\s*=\s*)(.*)$", before_comment, re.I)
        value = match.group(2).strip() if match else ""
        entries = value.split()
        if network not in entries:
            lines[ignore_idx] = match.group(1) + (value + " " if value else "") + network
            if sep:
                lines[ignore_idx] += " " + sep + comment

updated = "\n".join(lines).rstrip() + "\n"
if updated == original:
    print(f"Fail2Ban already includes OpenVPN pool {network} in {jail_path}.")
    print(network)
    sys.exit(0)

os.makedirs(os.path.dirname(jail_path) or ".", exist_ok=True)
if os.path.exists(jail_path):
    backup = jail_path + ".ovpn_mgr.bak"
    if not os.path.exists(backup):
        shutil.copy2(jail_path, backup)
    mode = os.stat(jail_path).st_mode & 0o777
else:
    mode = 0o644
fd, tmp = tempfile.mkstemp(prefix=".jail.local.", dir=os.path.dirname(jail_path) or ".", text=True)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(updated)
    os.chmod(tmp, mode)
    os.replace(tmp, jail_path)
except Exception:
    try:
        os.unlink(tmp)
    except OSError:
        pass
    raise
print(f"Added OpenVPN pool {network} to {jail_path} [DEFAULT] ignoreip.")
print(network)
