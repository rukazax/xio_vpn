# Help and FAQ

[Русский](../ru/faq.md) · [Home](../../README.md)

**Cannot connect.** Check VPS reachability, profile validity, ports, device clock and the test site. Open Settings → Connection → Diagnostics. Never post a full access profile or SSH password with a log.

**The tunnel works, but XIO switches protocols.** The VPS may be unable to reach the test site. Try https://example.com while diagnosing the problem, then choose a suitable site.

**Where are protocols, help and the licence?** Under Settings → About XIO. All engine entries are grouped under Protocols.

**Where is Diagnostics?** Settings → Connection → Diagnostics.

**Why is there no IPA?** iPhone builds require a Mac, Xcode, an Apple Developer team and signed NetworkExtension provisioning. This release includes source, not an installable IPA.

**Can XIO import any VPN?** Only supported formats and engines. Availability differs by platform.

**Can I share an administrative export?** Yes, but it includes secrets and server-management access. Share a user profile for ordinary VPN access.

**Why is user status not continuously refreshed?** Statistics load once when the app launches. They are a snapshot rather than constant monitoring.

**What does cleanup remove?** XIO-owned VPN components and configuration covered by the installer. It cannot guarantee erasure from provider backups or all system logs.

**Does a VPN guarantee anonymity?** No. Your provider, VPS operator and destination services can see different metadata. HTTPS protects content separately from the VPN.
