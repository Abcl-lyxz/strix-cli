---
name: mobile
description: Android application static and operator-approved device testing for exported components, storage, TLS, WebViews, and backend trust
version: "1.0"
required_tools: "jadx, apktool, apksigner, adb, frida-tools"
supported_targets: "APK files and explicitly connected test devices"
safety_class: device-required
freshness: "2026-09-15"
---

# Mobile application security

For APKs, record hashes and signer information, then inspect the manifest, exported components, deep links, network security config, WebViews, native libraries, secrets, storage, and backend endpoints. Static strings are leads, not automatically live credentials. Dynamic testing requires an explicitly connected test device or emulator and must not alter unrelated apps or user data. Correlate mobile findings with server-side authorization tests; client-side restrictions are never an authorization control.
