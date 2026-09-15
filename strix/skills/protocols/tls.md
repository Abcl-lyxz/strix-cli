---
name: tls
description: TLS posture testing for certificates, protocol versions, cipher policy, client authentication, SNI, and service-specific trust
version: "1.0"
required_tools: "sslscan, testssl, openssl"
supported_targets: "authorized TLS endpoints"
safety_class: active
freshness: "2026-09-15"
---

# TLS security

Capture the endpoint, SNI, certificate chain, validity, SANs, key type, signature, protocol versions, and accepted cipher suites. Test with and without SNI and across each distinct listener. Treat scanner heuristics as leads: confirm material downgrade, hostname, trust, weak-key, or client-certificate failures with a second tool and the exact handshake. Do not report a merely supported cipher without explaining realistic impact and server preference.
