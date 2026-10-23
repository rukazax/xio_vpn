# XIO / XIO Client 0.22.3 — draft / черновик

RU: IPv4/IPv6 endpoint и защищённое разрешение A/AAAA; IPv6-пакеты RIVET/S1/H3; серверная ревизия 23 с обратимым IPv6 forwarding/NAT66 при реальном маршруте провайдера; RU/EN в клиенте. Субклиенты работают только по серверной квоте и ограниченному HTTPS-доступу, без root/admin ключей. [Описание, изображения и схемы](docs/dualstack/0.22.3.ru.md).

EN: IPv4/IPv6 endpoints with protected A/AAAA resolution, IPv6 payloads in RIVET/S1/H3, recipe-23 reversible IPv6 forwarding/NAT66 when provider routing exists, and RU/EN client UI. Subclients retain server-enforced quotas and scoped HTTPS access without root/admin keys. [Guide, previews and diagrams](docs/dualstack/0.22.3.en.md).

**NOT COMPLETE / НЕ ЗАВЕРШЕНО:** physical Android and public IPv6 acceptance remain pending. No physical screenshot is presented. Previews use synthetic profiles. Cloak transport authentication passed, but its full Android OpenVPN flow remains pending. See the guides for exact test scope; APK integrity does not prove a working physical-device VPN.
