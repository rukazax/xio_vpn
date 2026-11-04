# Каскад: IPv4 клиентов через `tun0` (bridge → exit → NAT64)

Дополнение к `README.md` (там — прямой путь `awg0 → vpn4`). Здесь — вторая часть:
IPv4 клиентов AmneziaWG, которые подключены к **bridge** (`nv-144442`,
`81.177.142.37`), должен выходить в интернет через IPv4-адрес NAT64 **exit**
(`VPS-721137`, `2a0c:b641:1a0:800::2a2`), а не через публичный IPv4 bridge.

```
AWG client 10.78.0.x ── xioawg0 ── bridge
                                      │ ip rule: from 10.78.0.0/24 → table 78
                                      │ table 78: default dev tun0
                                      │ SNAT → 10.200.0.1
                                      ▼
                                tun0 (ssh -w)  fd00:201::/126 + 10.200.0.0/30
                                      ▼
exit tun0 10.200.0.2 ── nat PREROUTING -i tun0 REDIRECT → vpn4:19192
                                      ▼
                    [2a01:4f8:c2c:123f:64:5 + IPv4]:port → NAT64
```

## Файлы

| Файл | Сторона | Что делает |
|---|---|---|
| `xio-nat64-exit.sh` | exit | `10.200.0.2/30` на `tun0`; `REDIRECT -i tun0` TCP→19192, UDP/53→5353; тег `xio-nat64-tun0` |
| `xio-nat64-exit.service` | exit | oneshot |
| `xio-nat64-exit.timer` | exit | повтор 60 с: `ssh -w` пересоздаёт `tun0` при каждом reconnect |
| `xio-nat64-bridge.sh` | bridge | `10.200.0.1/30` на `tun0`; policy `from 10.78.0.0/24 lookup 78`; `default dev tun0`; `MASQUERADE -o tun0`; `RETURN` на `enp3s0`; `FORWARD xioawg0→tun0`; тег `xio-nat64` |
| `xio-nat64-bridge.service` | bridge | oneshot |
| `xio-nat64-bridge.timer` | bridge | повтор 60 с |
| `e2e-cascade-test.sh` | bridge | временный пир `10.78.0.99`, клиент в netns, `wget -4` |

## Почему policy routing, а не маршрут на подсеть

`ip route replace 10.78.0.0/24 dev tun0` — маршрут по **destination**, он не отправит в туннель
пакеты клиентов, у которых destination — интернет. Нужна политика по **source**:
`ip rule add from 10.78.0.0/24 lookup 78` + `default dev tun0` в таблице 78.

## Что с NAT44

Правило `xio-managed-awg` `-s 10.78.0.0/24 -o enp3s0 MASQUERADE` **не удаляется** (чужой
сервис). Оно перекрыто:

* tagged `RETURN` на `enp3s0` — fail-closed, наружу без NAT пакеты не уйдут;
* source-политикой — пакеты уходят в `tun0`, а не в `enp3s0`.

Единственный NAT для этой подсети — `MASQUERADE -o tun0` (tag `xio-nat64`), т.е. NAT44 сужен
до одного адреса внутри туннеля.

## Проверка

```bash
# exit
systemctl is-enabled xio-nat64-exit.timer
ip -4 addr show dev tun0 | grep 10.200.0.2
iptables -t nat -S PREROUTING | grep xio-nat64-tun0

# bridge
systemctl is-enabled xio-nat64-bridge.timer
ip -4 rule show | grep '10.78.0.0/24 lookup 78'
ip -4 route show table 78
iptables -t nat -S POSTROUTING | grep xio-nat64
iptables -S FORWARD | grep xio-nat64

# реальный клиент (временный пир, удаляется автоматически)
./e2e-cascade-test.sh CHECK
# ожидается: ip=159.69.108.193 (NAT64), ICMP 100% loss
```

## Откат

См. раздел «Откат» в `work/nat64-apply-20261105.md` (общий отчёт) или:

```bash
systemctl disable --now xio-nat64-bridge.timer xio-nat64-bridge.service
ip -4 rule del from 10.78.0.0/24 lookup 78; ip -4 route flush table 78
iptables -t nat -D POSTROUTING -s 10.78.0.0/24 -o tun0 -j MASQUERADE
iptables -t nat -D POSTROUTING -s 10.78.0.0/24 -o enp3s0 -j RETURN
iptables -D FORWARD -i xioawg0 -o tun0 -j ACCEPT
systemctl disable --now xio-nat64-exit.timer xio-nat64-exit.service   # exit
```
