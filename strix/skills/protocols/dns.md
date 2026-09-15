---
name: dns
description: DNS service security covering enumeration, recursion, transfer controls, DNSSEC, split horizon, and rebinding-relevant behavior
version: "1.0"
required_tools: "dig, dnsrecon, nmap"
supported_targets: "domains and authorized DNS servers"
safety_class: active
freshness: "2026-09-15"
---

# DNS security

Map authoritative servers, record types, delegation, DNSSEC, CAA, mail policy, and internal/external answer differences. Attempt AXFR/IXFR only against authoritative servers in scope. Test recursion with unrelated control names and distinguish cached answers from open recursion. Rate-limit brute-force enumeration and use discovered names as evidence, not proof of exposure. Check dangling records against current provider ownership rules before reporting takeover risk.
