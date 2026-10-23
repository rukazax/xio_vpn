#!/usr/bin/env python3
"""Public implementation diagrams; synthetic labels, no deployment data."""
from pathlib import Path
from html import escape
ROOT=Path(__file__).resolve().parents[2]
TEXT={
 'ru':{
  'ownerTitle':'Полный XIO: управление сервером и подключение',
  'clientTitle':'XIO Client: подключение и ограниченные субклиенты',
  'owner':[[['Полный XIO','Защищённое хранилище','SSH-ключей владельца'],['SSH: IPv4 или IPv6','Проверка отпечатка','серверного ключа'],['Свой VPS','Обновление служб','Пользователи и квоты'],['Клиентский профиль','VPN-ключи пользователя','Без root/admin SSH']], [['Полный XIO','Выбранный VPN-профиль'],['A и AAAA','DNS физической сети','Вне VPN-туннеля'],['VPN: IPv4 / IPv6','Транспорт и IP-пакеты','Проверка HTTPS'],['Выход через VPS','IPv4 / IPv6 назначения','Зависит от сети VPS']]],
  'client':[[['XIO Client','Импорт готового профиля','Без SSH-управления'],['A и AAAA','DNS физической сети','Защищённые сокеты'],['VPN: IPv4 / IPv6','Выбор адреса и протокола','Проверка HTTPS'],['Существующий VPS','Выход IPv4 / IPv6','Согласно профилю']], [['Профиль аккаунта','Ограниченный токен','Не root/admin SSH'],['HTTPS API','Закреплённый сертификат','Только свои субклиенты'],['Серверная квота','Права и отзыв на сервере','Лимит не повысить локально'],['Новый субклиент','Свои VPN-ключи','Без токена родителя']]],
  'ownerRows':['Управление: ключи остаются у владельца','Подключение: тот же VPN-контур, что в клиенте'],
  'clientRows':['Подключение к уже настроенному серверу','Дополнительная функция: только при выданном праве'],
  'direct':'Исключённый трафик → напрямую, если Android разрешает',
  'footer':['IPv6-выход требует IPv6-маршрута на VPS. IPv4-сайты с IPv6-only VPS требуют IPv4-выхода или трансляции NAT64.','Схема показывает реализацию. Подтверждённые сценарии и ограничения указаны отдельно в отчёте проверки.']},
 'en':{
  'ownerTitle':'Full XIO: server administration and VPN connections',
  'clientTitle':'XIO Client: connections and scoped subclients',
  'owner':[[['Full XIO','Owner’s encrypted','SSH credential vault'],['SSH: IPv4 or IPv6','Server host-key','fingerprint verification'],['Owned VPS','Service maintenance','Accounts and quotas'],['Client profile','User VPN credentials','No root/admin SSH keys']], [['Full XIO','Selected VPN profile'],['A and AAAA','Physical-network DNS','Outside the VPN tunnel'],['VPN: IPv4 / IPv6','Carrier and IP packets','HTTPS connectivity check'],['Exit via VPS','IPv4 / IPv6 destinations','Depends on VPS network']]],
  'client':[[['XIO Client','Import an existing profile','No SSH administration'],['A and AAAA','Physical-network DNS','Protected physical sockets'],['VPN: IPv4 / IPv6','Address/protocol selection','HTTPS connectivity check'],['Existing VPS','IPv4 / IPv6 exit','As configured in profile']], [['Account profile','Scoped account token','No root/admin SSH keys'],['HTTPS API','Exact certificate pin','Only this account’s children'],['Server-enforced quota','Permissions and revocation','No local quota escalation'],['New subclient','Own VPN credentials','No parent account token']]],
  'ownerRows':['Administration: server SSH keys remain with the owner','Connection: the same VPN path used by the client'],
  'clientRows':['Connecting to an already configured server','Optional: only for explicitly entitled accounts'],
  'direct':'Excluded traffic → direct, if allowed by Android',
  'footer':['IPv6 egress requires an IPv6 route on the VPS. IPv4-only sites from an IPv6-only VPS need IPv4 egress or NAT64.','This diagram describes implementation. Verified scenarios and remaining limits are recorded separately.']}}

def diagram(kind,lang):
 data=TEXT[lang];xs=[44,348,652,956];width=264
 out=['<svg xmlns="http://www.w3.org/2000/svg" width="1264" height="660" viewBox="0 0 1264 660">', '<defs><marker id="arrow" markerWidth="10" markerHeight="10" refX="8" refY="5" orient="auto"><path d="M0 0L10 5L0 10" fill="none" stroke="#456a30" stroke-width="2"/></marker></defs>', '<rect width="1264" height="660" rx="24" fill="#f3f6ee"/>',f'<text x="44" y="49" fill="#19251b" font-family="sans-serif" font-size="28" font-weight="700">{escape(data[kind+"Title"])}</text>']
 for row,boxes in enumerate(data[kind]):
  y=122+row*256
  out.append(f'<text x="44" y="{y-19}" fill="#456a30" font-family="sans-serif" font-size="20">{escape(data[kind+"Rows"][row])}</text>')
  for column,lines in enumerate(boxes):
   x=xs[column];out.append(f'<rect x="{x}" y="{y}" width="{width}" height="118" rx="18" fill="white" stroke="#456a30" stroke-width="2"/>')
   for line,text in enumerate(lines):out.append(f'<text x="{x+width/2}" y="{y+32+line*28}" text-anchor="middle" font-family="sans-serif" font-size="{20 if line==0 else 17}" font-weight="{700 if line==0 else 400}" fill="#19251b">{escape(text)}</text>')
   if column<3:out.append(f'<path d="M{x+width+7} {y+58}H{xs[column+1]-9}" stroke="#456a30" stroke-width="2" marker-end="url(#arrow)"/>')
 if kind=='client':out.append(f'<path d="M176 244V281H1058" fill="none" stroke="#7b8177" stroke-width="2" stroke-dasharray="7 5" marker-end="url(#arrow)"/><text x="202" y="309" fill="#555f52" font-family="sans-serif" font-size="18">{escape(data["direct"])}</text>')
 for i,text in enumerate(data['footer']):out.append(f'<text x="44" y="{568+i*31}" fill="#555f52" font-family="sans-serif" font-size="16">{escape(text)}</text>')
 out.append('</svg>');return '\n'.join(out)+'\n'
if __name__=='__main__':
 import xml.etree.ElementTree as ET
 for language in TEXT:
  for kind in ['owner','client']:
   value=diagram(kind,language);ET.fromstring(value);p=ROOT/f'docs/images/dualstack-{kind}-{language}.svg';p.write_text(value)
 print('Four RU/EN implementation diagrams generated')
