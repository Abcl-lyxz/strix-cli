---
name: service_protocols
description: Evidence-led SSH, SNMP, RDP, SMTP/IMAP/POP, FTP, and other non-HTTP service assessment
version: "1.0"
required_tools: "nmap, snmpwalk, onesixtyone, openssl"
supported_targets: "authorized hosts and service ports"
safety_class: active
freshness: "2026-09-15"
---

# Network service protocols

Fingerprint before testing and select the protocol-specific client. Check anonymous/default access, information disclosure, authentication modes, encryption requirements, downgrade behavior, and authorization boundaries using operator-provided credentials. For SNMP, restrict community checks to supplied or very small approved candidates; do not spray. For SSH/RDP/mail/FTP, never brute force. Record banner/version confidence separately from a confirmed vulnerable behavior, and enrich versions with `query_vulnerability_intel` only after exact product/version evidence exists.
