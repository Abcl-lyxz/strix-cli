#!/bin/sh
set -eu

packs="${STRIX_TOOL_PACK:-core,network,identity,cloud,mobile,firmware}"
failed=0
check() {
  path="$(command -v "$1" 2>/dev/null || true)"
  if [ -z "$path" ]; then
    echo "missing: $1" >&2
    failed=1
    return
  fi
  printf '%s\tavailable\t%s\n' "$1" "$path"
}

echo "$packs" | grep -q core && for tool in httpx katana ffuf nuclei sqlmap semgrep bandit trivy gitleaks trufflehog agent-browser caido-cli; do check "$tool"; done
echo "$packs" | grep -q network && for tool in nmap naabu masscan arp-scan netdiscover tcpdump tshark scapy dig dnsrecon snmpwalk onesixtyone ike-scan sslscan testssl socat; do check "$tool"; done
echo "$packs" | grep -q identity && for tool in netexec enum4linux-ng smbclient ldapsearch kerbrute impacket-GetUserSPNs bloodhound-python; do check "$tool"; done
echo "$packs" | grep -q cloud && for tool in trivy prowler scout kubectl kube-bench kube-hunter; do check "$tool"; done
echo "$packs" | grep -q mobile && for tool in jadx apktool apksigner adb frida-ps; do check "$tool"; done
echo "$packs" | grep -q firmware && for tool in binwalk unsquashfs yara qemu-aarch64-static; do check "$tool"; done
exit "$failed"
