# XIO Cascade: IPv4 entry → IPv6 exit (SSH transport)

Проверено на реальной паре: **bridge `81.177.142.37`** (Debian 12, только IPv4) и
**exit `2a0c:b641:1a0:800::2a2`** (Ubuntu 22.04, только IPv6).

## Почему не WireGuard поверх IPv6

Прежний вариант `feature/cascade` поднимал `wg0` до `[exit]:port` по IPv6. На этом bridge
IPv6 нет вообще: провайдер не отдаёт ни RA, ни DHCPv6 (проверено `dhclient -6 -v enp3s0`), и
прямого пути между IPv4- и IPv6-хостом не существует. Поэтому транспорт — **SSH-туннель L3
через IPv4-прокси провайдера exit** (`vps-721137.ssh.vps1euro.fr:9046`), который уже открыт
и завершается на exit.

```
клиент ──AWG/UDP 51821──▶ bridge ──ssh -w 0:0 (TCP 9046)──▶ exit ──NAT66──▶ IPv6-интернет
```

## Что настраивается

### exit

```sh
sysctl -w net.ipv6.conf.all.forwarding=1
# SSH: PermitTunnel yes (drop-in /etc/ssh/sshd_config.d/50-xio-cascade.conf)
ip6tables -I FORWARD -i tun0 -j ACCEPT
ip6tables -I FORWARD -o tun0 -j ACCEPT
ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

Ключ bridge (`xio-cascade-bridge`) добавляется в `/root/.ssh/authorized_keys`.

### bridge

`/usr/local/sbin/xio-cascade-tunnel.sh` держит туннель и владеет устройством:

```sh
ip link del tun0 2>/dev/null || true          # рестарт не настраивает старый tun0
ssh -i /root/.ssh/id_ed25519_cascade -p 9046 -w 0:0 root@vps-721137.ssh.vps1euro.fr \
  "ip addr replace fd00:201::2/126 dev tun0; ip link set tun0 up; exec sleep infinity" &
for _ in $(seq 1 60); do ip link show tun0 >/dev/null 2>&1 && break; sleep 1; done
ip addr replace fd00:201::1/126 dev tun0
ip -6 route replace default via fd00:201::2 dev tun0
wait
```

`xio-cascade.service` — `Type=simple`, `Restart=always`, `RestartSec=5`.

## Маршрутизация клиентов

XIO на bridge сам строит правила: для каждой транспортной подсети
(`fd78:1::/64` AWG, `fd79:1::/64` RIVET, `fd80:1::/64` OpenVPN) есть
`FORWARD -s … -i <iface> -o tun0 -j ACCEPT`, а IPv6 по умолчанию уходит в `tun0`.
 Поэтому каскад работает для **любого** протокола, а не только для AWG.

## Границы

- IPv6-интернет клиентов выходит **через exit** (NAT66), подтверждено `curl -6` → `2a0c:…::2a2`.
- IPv4-интернет выходит через **сам bridge** (его NAT): у exit нет ни одного IPv4-адреса,
  NAT64 без IPv4-пула физически невозможен.
- Пропускная способность ограничена SSH-over-TCP; для эталонной проверки годится,
  для нагруженного продакшена лучше отдельный UDP-транспорт, если у bridge появится IPv6.

## Проверка

```sh
# на bridge
systemctl is-active xio-cascade
ip -6 route show default            # default via fd00:201::2 dev tun0
ping -6 -c2 2606:4700:4700::1111
# на клиенте с выданным AWG-конфигом
curl -4 -s https://api.ipify.org    # 81.177.142.37
curl -6 -s https://ifconfig.co      # 2a0c:b641:1a0:800::2a2
```

Замеры 03.11.2026: bridge → интернет через exit 68–77 мс; клиент AWG (Debian, `awg-quick` +
`amneziawg-go`) — рукопожатие есть, IPv4 `81.177.142.37`, IPv6 `2a0c:b641:1a0:800::2a2`.
