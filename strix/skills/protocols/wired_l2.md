---
name: wired_l2
description: Authorized wired Ethernet L2 discovery, segmentation validation, ARP observations, VLAN boundaries, and packet evidence
version: "1.0"
required_tools: "arp-scan, tcpdump, tshark, scapy"
supported_targets: "linux lan profile, explicit wired interface and CIDR"
safety_class: privileged
freshness: "2026-09-15"
---

# Wired Ethernet L2 assessment

Use only with the `lan` sandbox profile after the operator supplied an interface, CIDR, and authorization acknowledgement. Wireless, flooding, spoofing, poisoning, denial-of-service, and lateral movement are outside this workflow.

1. Record interface, addresses, routes, VLAN visibility, scope CIDR, timestamp, and capture filter.
2. Start with passive packet observation. Identify ARP, IPv6 neighbor discovery, DHCP, LLDP/CDP, STP, mDNS, and broadcast domains without transmitting payloads.
3. Use rate-limited ARP discovery only inside the supplied CIDR. Deduplicate MAC/IP pairs and separate gateways, infrastructure, and endpoints.
4. Validate segmentation with ordinary connection attempts to explicitly allowed services. Do not infer isolation from missing ICMP alone.
5. Preserve a bounded PCAP and command transcript. Report a control failure only when packets or connections cross a boundary that policy says should be isolated.

Stop if the effective interface, route, or network differs from the preflight record.
