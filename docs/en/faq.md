# Questions and answers

[Русский](../ru/faq.md) · [Guide](guide.md)

**Why do all protocols fail?** Check entry IP reachability, SSH, DNS, device time and Connection diagnostics. Protocol changes do not restore a blocked IP. A timeout alone does not identify filtering.

**Where are protocols?** Settings → Connection → Protocols. Automatic selection uses available platform engines and configurations belonging to the selected user.

**Why did a previous profile disappear?** Version 0.22 removes standalone WireGuard, OpenVPN, IKEv2, Shadowsocks and Tailscale. Import a supported profile. Internal OpenVPN for Cloak remains.

**Does ordinary VPN require root?** No. Android VPN tethering requires root. A stock phone displays “Root required”; a switch cannot add this system capability.

**How do I verify tethering?** Check the external IP from the tethered device and loss of access after VPN disconnect. Restart the hotspot after the offload setting changes. Vendor bypasses of netfilter need separate validation. Windows ICS is experimental and requires administrator rights and an active hotspot.

**Does the server update with the client?** Managed-server maintenance runs at startup/administration when the VPN is off, saved SSH works and the host key matches. Active VPN defers it. Recipe 19 disables legacy XIO services; a service-start failure triggers rollback.

**Where is the iOS app?** A source project is available; there is no signed IPA yet.

**Is circumvention guaranteed?** No. This build has no Russian-operator field measurements or independent RIVET audit. Entry reachability and transport camouflage are separate problems.
