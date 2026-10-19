# XIO 0.22 verification / Проверки

| Проверка / Check | Результат / Result | Предел / Limit |
|---|---|---|
| Flutter analyze + tests | Clean; 105 passed, 4 conditional skips; actual signed metadata validated | Local automated tests |
| Go race detector | All current packages pass | No independent crypto audit |
| XHTTP TLS + VLESS Encryption | 80 local exchanges, 20 per mode: auto, packet-up, stream-up, stream-one | No CDN or operator/DPI trial |
| Retired engines | Dependency inventory excludes Tailscale and Shadowsocks proxy engines; client registry rejects retired profiles | AWG/Wintun and internal Cloak OpenVPN remain |
| Server updater | Real VM: bad binary rollback, recipe 18→19, users/keys preserved, repeat is idempotent, user creation after migration | Isolated Ubuntu 24.04; no real VPS modified |
| Fresh server | Recipe19, five advertised protocols, no bare SS/OpenVPN UDP/IKE/mesh service; Cloak backend loopback | Ubuntu VM, not every supported distro |
| Android tether routing | IPv4 forwarding, disconnect blocking, reconnect, missing-rule recovery, IPv6 blocking, owned cleanup | Linux netfilter namespaces in VM, not Android vendor offload |
| Android package | Launcher aliases, native ELF matching, signatures and 16 KiB alignment | API26 emulator launch; no new physical-device proof |
| Windows | Windows-target kernel, four helper engines, archive extraction under Wine | Wintun/UAC/ICS not verified on native Windows |
| iOS | Updated shared client/source | No Mac/Xcode build, signed IPA or physical Apple test |

Раздача экспериментальная. Android без root сообщает «Необходим root». Работа netfilter в Linux VM не доказывает отсутствие аппаратного/BPF обхода на конкретной прошивке. На подключённом устройстве нужно проверить внешний IP и отключение при потере VPN.

Tethering is experimental. Stock Android displays “Root required”. Linux VM netfilter tests do not establish vendor hardware/BPF offload behaviour. Verify external IP and loss of connectivity on VPN disconnect from the tethered device.

[Network limitations / Ограничения](../docs/blog/2026-10-19-restricted-networks.md). No universal allowlist bypass, traffic indistinguishability or Russian-operator coverage is claimed.
