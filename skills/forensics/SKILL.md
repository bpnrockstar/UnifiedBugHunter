---
name: forensics
description: Digital forensics methodology for disk, memory, and network analysis. Covers timeline analysis (plaso/log2timeline), file carving (foremost/photorec), memory forensics (Volatility 3), network forensics (tshark/Wireshark), registry analysis, and IOC extraction. Use when investigating a compromised system, analyzing forensic artifacts, or performing incident response.
---

# Digital Forensics Methodology

## Phase 1: Artifact Type Identification

```bash
file evidence.dd       # raw disk image
file evidence.mem      # memory dump
file evidence.pcap     # packet capture
file evidence.e01      # EnCase image
file evidence.raw      # raw format
```

## Phase 2: Timeline Analysis

```bash
# Using plaso (log2timeline)
log2timeline.py --storage timeline.plaso evidence.dd
psort.py -o l2tcsv -w timeline.csv timeline.plaso

# Manual timeline anomalies to look for:
# - Files modified before creation date
# - Access times outside business hours
# - MFT entry with suspicious filename patterns
```

## Phase 3: File Carving

```bash
foremost -i evidence.dd -o carved/
photorec /d recovered/ /log evidence.dd
strings evidence.dd | grep -iE "http|https|\.exe|\.dll|\.ps1|cmd" | head -50
```

## Phase 4: Memory Forensics (Volatility 3)

```bash
vol -f evidence.mem windows.info
vol -f evidence.mem windows.pslist
vol -f evidence.mem windows.netscan
vol -f evidence.mem windows.malfind
vol -f evidence.mem windows.cmdline
vol -f evidence.mem windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Run"
```

## Phase 5: Network Forensics

```bash
# Top talkers
tshark -r evidence.pcap -T fields -e ip.src | sort | uniq -c | sort -rn | head -10

# DNS queries (potential C2)
tshark -r evidence.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u

# HTTP object extraction
tshark -r evidence.pcap --export-objects http,extracted/

# Suspicious port detection
tshark -r evidence.pcap -Y "tcp.dstport in {4444 1337 31337 6667 8080 8443}"
```

## Phase 6: IOC Extraction

```bash
grep -ohE "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" evidence.dd | sort -u > ioc_ips.txt
grep -ohE "[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" evidence.dd | sort -u > ioc_domains.txt
grep -ohE "[a-fA-F0-9]{64}" evidence.dd | sort -u > ioc_sha256.txt
```

## IOC Sharing Format

```json
{
    "iocs": {
        "ips": ["1.2.3.4"],
        "domains": ["evil.com"],
        "hashes": {"sha256": ["abc...def"]},
        "yara": "rule ... { ... }"
    },
    "type": "malware_infection",
    "tlp": "AMBER"
}
```
