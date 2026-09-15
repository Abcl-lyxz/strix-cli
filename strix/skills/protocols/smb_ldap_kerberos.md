---
name: smb_ldap_kerberos
description: Safe SMB, LDAP, Kerberos, NTLM, and Active Directory enumeration with authorization-bound evidence
version: "1.0"
required_tools: "netexec, smbclient, ldapsearch, impacket, bloodhound-python"
supported_targets: "authorized Windows domains and hosts"
safety_class: active
freshness: "2026-09-15"
---

# SMB, LDAP, Kerberos, and AD

Begin with domain controllers, naming contexts, signing/channel-binding state, anonymous access, shares, and the privileges of supplied credentials. Prefer read-only LDAP and SMB enumeration. Roasting or graph collection requires explicit credentials and must remain within named domains. Do not spray passwords, coerce authentication, relay NTLM, modify directory objects, dump credentials, or move laterally under this skill. Confirm every escalation path from object ACLs and effective membership; a BloodHound edge alone is not a finding.
