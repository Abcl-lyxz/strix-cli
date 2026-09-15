---
name: firmware
description: Offline firmware extraction and analysis for filesystems, credentials, services, update trust, and unsafe native code
version: "1.0"
required_tools: "binwalk, unsquashfs, yara, qemu-user"
supported_targets: "firmware images supplied by the operator"
safety_class: read-only
freshness: "2026-09-15"
---

# Firmware analysis

Hash the original image and work on extracted copies. Identify container/filesystem formats, architecture, init scripts, services, web roots, certificates, credentials, update manifests, and privileged native binaries. Preserve extraction paths and hashes. Emulation is opt-in and uses no external network by default. Do not flash devices or run extracted startup scripts on the host. Confirm secrets, vulnerable versions, and unsafe update paths with exact artifacts and distinguish factory defaults from deployed state.
