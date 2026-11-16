#!/usr/bin/env bash
# XIO MTProto-прокси (mtg) — установка и обновление, идемпотентно.
#
# Что делает:
#   1. скачивает официальный релиз mtg (github.com/9seconds/mtg) для linux-amd64;
#   2. кладёт бинарь в /usr/local/lib/xio-mtproto/mtg;
#   3. генерирует FakeTLS-секрет под домен маскировки (один раз, дальше переиспользует);
#   4. пишет /etc/xio-mtproto/config.toml и systemd-юнит xio-mtproto.service;
#   5. запускает службу с автоперезапуском и печатает ссылку tg://proxy?...
#
# Повторный запуск только с проверенной квитанцией владения: версия не перекачивается,
# существующий секрет не перегенерируется, служба перезапускается только
# если изменились бинарь, конфиг или юнит.
#
# Примеры:
#   sudo ./xio-mtproto-setup.sh                       # порт 8444, маскировка 79e.ru
#   sudo MTG_PORT=443 MTG_DOMAIN=example.org ./xio-mtproto-setup.sh
#   sudo ./xio-mtproto-setup.sh --print-link          # только напечатать ссылку
#   sudo ./xio-mtproto-setup.sh --uninstall           # снять службу и файлы
#
# Переменные окружения:
#   MTG_VERSION    версия релиза mtg                (по умолчанию 2.3.0)
#   MTG_PORT       TCP-порт прокси                  (по умолчанию 8444)
#   MTG_DOMAIN     домен маскировки FakeTLS         (по умолчанию 79e.ru)
#   MTG_PUBLIC_IP  публичный IPv4 для ссылки        (по умолчанию определяется)
#   MTG_IP_FAMILY  prefer-ip для mtg                (по умолчанию автотест)
#   MTG_SOCKS5     upstream socks5://host:port      (необязательно)
#   MTG_DNS        DNS для mtg, "" = системный      (по умолчанию пусто)
#
# Порт прокси НЕ занимает 443/8443: на бридже там nginx и xio-rivet.
#
# Секрет НЕ хранится в репозитории: он создаётся на сервере в /etc/xio-mtproto/secret.

set -euo pipefail

MTG_VERSION=${MTG_VERSION:-2.3.0}
MTG_PORT=${MTG_PORT:-8444}
MTG_DOMAIN=${MTG_DOMAIN:-79e.ru}
MTG_PUBLIC_IP=${MTG_PUBLIC_IP:-}
MTG_IP_FAMILY=${MTG_IP_FAMILY:-}
MTG_SOCKS5=${MTG_SOCKS5:-}
MTG_DNS=${MTG_DNS-}

MTG_LIB=/usr/local/lib/xio-mtproto
MTG_ETC=/etc/xio-mtproto
MTG_BIN=$MTG_LIB/mtg
MTG_CONF=$MTG_ETC/config.toml
MTG_SECRET_FILE=$MTG_ETC/secret
MTG_STATE=$MTG_ETC/state
MTG_USER=xio-mtproto
UNIT=/etc/systemd/system/xio-mtproto.service

log() { printf '\033[1;32m[xio-mtproto]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[xio-mtproto]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[xio-mtproto]\033[0m %s\n' "$*" >&2; exit 1; }

# Ownership is administrative evidence, not protection against concurrent root.
# Pending installs/updates require manual recovery; only removals are resumable.
OWNER_DIR=/var/lib/xio-mtproto-owner
OWNER_RECEIPT=$OWNER_DIR/receipt
OWNER_LOCK=$OWNER_DIR/lock
SYSTEM_ETC=/etc/systemd/system
SYSTEM_RUN=/run/systemd/system
UNIT_VENDOR_DIRS=(/usr/local/lib/systemd/system /usr/lib/systemd/system /lib/systemd/system)
ENABLE_LINK=$SYSTEM_ETC/multi-user.target.wants/xio-mtproto.service
LOCAL_PASSWD=/etc/passwd
LOCAL_GROUP=/etc/group
OWNER_KEYS=(group user lib etc bin license release secret conf port domain state unit link)
declare -A OP OS OI
OWNER_PHASE= OWNER_GEN= OWNER_DEPS=0 OWNER_STOP=0 OWNER_CONTROL= OWNER_LOCK_ID=

ownership_error() { die "ownership cannot be proved; preserved for manual recovery ($1)"; }
exists() { [ -e "$1" ] || [ -L "$1" ]; }

# Inspect each component without canonicalizing away a symlink.
trusted_path() {
  local path=$1 allow_leaf=${2:-no} part current= mode uid
  local -a components
  [[ "$path" = /* && "$path" != *'/../'* && "$path" != *'/./'* ]] || ownership_error path
  IFS=/ read -r -a components <<< "$path"
  for part in "${components[@]}"; do
    [ -n "$part" ] || continue
    current=$current/$part
    if ! exists "$current"; then
      [ "$allow_leaf" = yes ] && [ "$current" = "$path" ] && return 0
      ownership_error missing-parent
    fi
    [ ! -L "$current" ] || ownership_error symlink
    uid=$(stat -c %u -- "$current") || ownership_error stat
    mode=$(stat -c %a -- "$current") || ownership_error stat
    [[ "$uid" = 0 && "$mode" =~ ^[0-7]{3,4}$ ]] || ownership_error owner
    (( (8#$mode & 0022) == 0 )) || ownership_error writable-path
    if [ "$current" != "$path" ]; then [ -d "$current" ] || ownership_error parent-type; fi
  done
}

owner_paths() {
  OP[lib]=$MTG_LIB OP[etc]=$MTG_ETC OP[bin]=$MTG_BIN OP[license]=$MTG_LIB/LICENSE
  OP[release]=$MTG_ETC/release.sha256 OP[secret]=$MTG_SECRET_FILE OP[conf]=$MTG_CONF
  OP[port]=$MTG_ETC/port OP[domain]=$MTG_ETC/domain OP[state]=$MTG_STATE
  OP[unit]=$UNIT OP[link]=$ENABLE_LINK
}

change_stamp() {
  local stamp digest
  stamp=$(TZ=UTC stat -c %z -- "$1") || ownership_error change-time
  digest=$(printf '%s' "$stamp" | sha256sum | awk '{print $1}') || ownership_error change-time-hash
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || ownership_error change-time-hash
  printf '%s\n' "$digest"
}
lock_identity() {
  local identity stamp
  identity=$(stat -c '%d:%i:%u:%g:%a' "$OWNER_LOCK") || ownership_error lock-stat
  stamp=$(change_stamp "$OWNER_LOCK") || exit 1
  printf '%s:%s\n' "$identity" "$stamp"
}
file_identity() {
  local key=$1 path=${OP[$1]} result digest stamp
  if [ "$key" = link ]; then
    trusted_path "${path%/*}"
    [ -L "$path" ] && [ "$(readlink -- "$path")" = "$UNIT" ] || ownership_error enable-link
    [ "$(stat -c %u -- "$path")" = 0 ] || ownership_error link-owner
    result=$(stat -c '%d:%i:%u:%g:%a' -- "$path") || ownership_error link-stat
    stamp=$(change_stamp "$path") || exit 1
    printf '%s:%s\n' "$result" "$stamp"
    return
  fi
  trusted_path "$path"
  case "$key" in
    lib|etc)
      [ -d "$path" ] || ownership_error directory
      result=$(stat -c '%d:%i:%u:%g:%a' -- "$path") || ownership_error stat
      # Child changes legitimately alter directory ctime. Bind it only once
      # removal intent is published, after all our child operations are done.
      case "${OS[$key]:-owned}" in
        intent|removed) stamp=$(change_stamp "$path") || exit 1; result=$result:$stamp ;;
      esac
      printf '%s\n' "$result" ;;
    *) [ -f "$path" ] && [ "$(stat -c %h -- "$path")" = 1 ] || ownership_error regular-file
       result=$(stat -c '%d:%i:%u:%g:%a:%h:%s' -- "$path") || ownership_error stat
       digest=$(sha256sum -- "$path" | awk '{print $1}') || ownership_error file-hash
       [[ "$digest" =~ ^[0-9a-f]{64}$ ]] || ownership_error file-hash
       stamp=$(change_stamp "$path") || exit 1
       printf '%s:%s:%s\n' "$result" "$digest" "$stamp" ;;
  esac
}

# NSS enumeration and local databases must agree. Enumeration failure is not absence.
account_snapshot() {
  NSS_PASSWD=$(getent passwd) || ownership_error passwd-query
  NSS_GROUP=$(getent group) || ownership_error group-query
  FILE_PASSWD=$(cat "$LOCAL_PASSWD") || ownership_error local-passwd
  FILE_GROUP=$(cat "$LOCAL_GROUP") || ownership_error local-group
}
account_line() { printf '%s\n' "$1" | awk -F: -v n="$2" '$1==n {print}'; }
lookup_absent() {
  local result rc
  if result=$(getent "$1" "$2"); then ownership_error occupied-nss-key
  else
    rc=$?
    [ "$rc" = 2 ] && [ -z "$result" ] || ownership_error uncertain-nss-absence
  fi
}
account_absent() {
  account_snapshot
  lookup_absent passwd "$MTG_USER"
  lookup_absent group "$MTG_USER"
  [ -z "$(account_line "$NSS_PASSWD" "$MTG_USER")$(account_line "$FILE_PASSWD" "$MTG_USER")$(account_line "$NSS_GROUP" "$MTG_USER")$(account_line "$FILE_GROUP" "$MTG_USER")" ] || ownership_error account-collision
}
account_identity() {
  local key=$1 line local_line uid gid name pass gecos home shell members reverse
  account_snapshot
  if [ "$key" = user ]; then
    line=$(account_line "$NSS_PASSWD" "$MTG_USER")
    local_line=$(account_line "$FILE_PASSWD" "$MTG_USER")
    [ -n "$line" ] && [ "$line" = "$local_line" ] && [[ "$line" != *$'\n'* ]] || ownership_error local-user
    IFS=: read -r name pass uid gid gecos home shell <<< "$line"
    [[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]] || ownership_error ids
    [ "$gecos" = "xio-mtproto-$OWNER_GEN" ] && [ "$home" = "$MTG_LIB" ] && [ "$shell" = /usr/sbin/nologin ] || ownership_error user-fields
    reverse=$(getent passwd "$uid") || ownership_error uid-query
    [ "$reverse" = "$line" ] || ownership_error uid-reuse
    [ "$(printf '%s\n' "$NSS_PASSWD" | awk -F: -v n="$uid" '$3==n {print}')" = "$line" ] || ownership_error duplicate-uid
    [ "$(printf '%s\n' "$FILE_PASSWD" | awk -F: -v n="$uid" '$3==n {print}')" = "$line" ] || ownership_error duplicate-local-uid
    reverse=$(getent passwd "$MTG_USER") || ownership_error user-name-query
    [ "$reverse" = "$line" ] || ownership_error user-name-mapping
    [ -z "$(printf '%s\n%s\n' "$NSS_GROUP" "$FILE_GROUP" | awk -F: -v n="$MTG_USER" '{c=split($4,a,","); for(i=1;i<=c;i++) if(a[i]==n) print}')" ] || ownership_error foreign-supplementary-group
    printf '%s:%s:%s\n' "$uid" "$gid" "$OWNER_GEN"
  else
    line=$(account_line "$NSS_GROUP" "$MTG_USER")
    local_line=$(account_line "$FILE_GROUP" "$MTG_USER")
    [ -n "$line" ] && [ "$line" = "$local_line" ] && [[ "$line" != *$'\n'* ]] || ownership_error local-group
    IFS=: read -r name pass gid members <<< "$line"
    [[ "$gid" =~ ^[0-9]+$ ]] && [ -z "$members" ] || ownership_error group-members
    reverse=$(getent group "$gid") || ownership_error gid-query
    [ "$reverse" = "$line" ] || ownership_error gid-reuse
    reverse=$(getent group "$MTG_USER") || ownership_error group-name-query
    [ "$reverse" = "$line" ] || ownership_error group-name-mapping
    [ "$(printf '%s\n' "$NSS_GROUP" | awk -F: -v n="$gid" '$3==n {print}')" = "$line" ] || ownership_error duplicate-gid
    [ "$(printf '%s\n' "$FILE_GROUP" | awk -F: -v n="$gid" '$3==n {print}')" = "$line" ] || ownership_error duplicate-local-gid
    [ -z "$(printf '%s\n%s\n' "$NSS_PASSWD" "$FILE_PASSWD" | awk -F: -v g="$gid" -v n="$MTG_USER" '$4==g && $1!=n {print}')" ] || ownership_error foreign-primary-gid
    printf '%s\n' "$gid"
  fi
}
resource_identity() {
  case "$1" in user|group) account_identity "$1" ;; *) file_identity "$1" ;; esac
}
resource_absent() {
  local key=$1 numeric parent
  case "$key" in
    user|group)
      account_snapshot
      if [ "$key" = user ]; then
        [ -z "$(account_line "$NSS_PASSWD" "$MTG_USER")$(account_line "$FILE_PASSWD" "$MTG_USER")" ] || return 1
        numeric=${OI[user]%%:*}
        lookup_absent passwd "$MTG_USER"
        [ "$numeric" = - ] || lookup_absent passwd "$numeric"
        [ -z "$(printf '%s\n%s\n' "$NSS_PASSWD" "$FILE_PASSWD" | awk -F: -v n="$numeric" '$3==n {print}')" ] || ownership_error retired-uid-reused
      else
        [ -z "$(account_line "$NSS_GROUP" "$MTG_USER")$(account_line "$FILE_GROUP" "$MTG_USER")" ] || return 1
        numeric=${OI[group]}
        lookup_absent group "$MTG_USER"
        [ "$numeric" = - ] || lookup_absent group "$numeric"
        [ -z "$(printf '%s\n%s\n' "$NSS_GROUP" "$FILE_GROUP" | awk -F: -v n="$numeric" '$3==n {print}')" ] || ownership_error retired-gid-reused
        [ -z "$(printf '%s\n%s\n' "$NSS_PASSWD" "$FILE_PASSWD" | awk -F: -v n="$numeric" '$4==n {print}')" ] || ownership_error retired-primary-gid
      fi ;;
    *) parent=${OP[$key]%/*}
       while ! exists "$parent"; do parent=${parent%/*}; [ -n "$parent" ] || parent=/; done
       trusted_path "$parent"
       ! exists "${OP[$key]}" ;;
  esac
}

owner_save() {
  local tmp key
  trusted_path "$OWNER_DIR"
  trusted_path "$OWNER_RECEIPT" yes
  trusted_path "$OWNER_LOCK"
  [ "$OWNER_CONTROL" = "$(stat -c '%d:%i:%u:%g:%a' "$OWNER_DIR")" ] && [ "$OWNER_LOCK_ID" = "$(lock_identity)" ] || ownership_error control-drift
  if exists "$OWNER_RECEIPT"; then
    [ -f "$OWNER_RECEIPT" ] && [ "$(stat -c '%u:%a:%h' "$OWNER_RECEIPT")" = 0:600:1 ] || ownership_error receipt-mode
  fi
  tmp=$(mktemp "$OWNER_DIR/.receipt.XXXXXXXX") || ownership_error journal-create
  chmod 0600 "$tmp" || ownership_error journal-mode
  {
    printf 'xio-mtproto-owner-v1\n%s\n%s\n%s\n%s\n%s\n%s\n' "$OWNER_GEN" "$OWNER_PHASE" "$OWNER_DEPS" "$OWNER_STOP" "$OWNER_CONTROL" "$OWNER_LOCK_ID"
    for key in "${OWNER_KEYS[@]}"; do printf '%s|%s|%s\n' "$key" "${OS[$key]}" "${OI[$key]}"; done
  } > "$tmp" || ownership_error journal-write
  mv -T -- "$tmp" "$OWNER_RECEIPT" || ownership_error journal-publish
}
owner_load() {
  local -a lines
  local key got status identity extra index=7
  trusted_path "$OWNER_RECEIPT"
  [ -f "$OWNER_RECEIPT" ] && [ "$(stat -c '%u:%a:%h' "$OWNER_RECEIPT")" = 0:600:1 ] || ownership_error receipt-mode
  [ "$(stat -c %s "$OWNER_RECEIPT")" -le 16384 ] || ownership_error receipt-size
  mapfile -t lines < "$OWNER_RECEIPT"
  [ "${#lines[@]}" = 21 ] && [ "${lines[0]}" = xio-mtproto-owner-v1 ] || ownership_error receipt-schema
  OWNER_GEN=${lines[1]} OWNER_PHASE=${lines[2]} OWNER_DEPS=${lines[3]} OWNER_STOP=${lines[4]}
  OWNER_CONTROL=${lines[5]} OWNER_LOCK_ID=${lines[6]}
  [[ "$OWNER_GEN" =~ ^[0-9a-f]{32}$ && "$OWNER_DEPS" =~ ^[01]$ && "$OWNER_STOP" =~ ^(0|intent|done)$ ]] || ownership_error receipt-header
  case "$OWNER_PHASE" in
    install-pending|update-pending|ready) [ "$OWNER_STOP" = 0 ] || ownership_error receipt-stop-state ;;
    uninstalling) ;;
    uninstalled) [ "$OWNER_STOP" = done ] || ownership_error receipt-stop-state ;;
    *) ownership_error receipt-stage ;;
  esac
  [ "$OWNER_CONTROL" = "$(stat -c '%d:%i:%u:%g:%a' "$OWNER_DIR")" ] && [ "$OWNER_LOCK_ID" = "$(lock_identity)" ] || ownership_error control-replaced
  for key in "${OWNER_KEYS[@]}"; do
    IFS='|' read -r got status identity extra <<< "${lines[$index]}"
    [ "$got" = "$key" ] && [ "${lines[$index]}" = "$got|$status|$identity" ] || ownership_error receipt-key
    case "$status" in absent|owned|intent|removed) ;; *) ownership_error receipt-status ;; esac
    if [ "$status" = absent ]; then
      [ "$identity" = - ] && [ "$OWNER_PHASE" = install-pending ] || ownership_error absent-identity
    else
      case "$key" in
        group) [[ "$identity" =~ ^[0-9]+$ ]] ;;
        user) [[ "$identity" =~ ^[0-9]+:[0-9]+:[0-9a-f]{32}$ ]] && [ "${identity##*:}" = "$OWNER_GEN" ] ;;
        lib|etc)
          if [ "$status" = owned ]; then [[ "$identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}$ ]]
          else [[ "$identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}:[0-9a-f]{64}$ ]]; fi ;;
        link) [[ "$identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}:[0-9a-f]{64}$ ]] ;;
        *) [[ "$identity" =~ ^[0-9]+:[0-9]+:[0-9]+:[0-9]+:[0-7]{3,4}:1:[0-9]+:[0-9a-f]{64}:[0-9a-f]{64}$ ]] ;;
      esac || ownership_error receipt-identity
    fi
    case "$OWNER_PHASE" in
      ready|update-pending) [ "$status" = owned ] || ownership_error receipt-resource-state ;;
      uninstalled) [ "$status" = removed ] || ownership_error receipt-resource-state ;;
      install-pending) case "$status" in absent|owned) ;; *) ownership_error receipt-resource-state ;; esac ;;
      uninstalling)
        [ "$status" != absent ] || ownership_error receipt-resource-state
        if [ "$OWNER_STOP" != done ]; then [ "$status" = owned ] || ownership_error receipt-stop-order; fi ;;
    esac
    OS[$key]=$status OI[$key]=$identity
    index=$((index+1))
  done
}

unit_check() {
  local mode=$1 text key value load= fragment= drops= names= transient= state= count=0 link target
  local -A seen=()
  local directory suffix
  for directory in "$SYSTEM_ETC" "$SYSTEM_RUN" "${UNIT_VENDOR_DIRS[@]}"; do
    # Read-only collision detection; vendor aliases never authorize mutation.
    for suffix in service.d xio-.service.d xio-mtproto.service.d; do
      ! exists "$directory/$suffix" || ownership_error inherited-or-specific-dropin
    done
    if [ "$directory" != "$SYSTEM_ETC" ]; then
      ! exists "$directory/xio-mtproto.service" || ownership_error vendor-or-runtime-unit
    fi
  done
  text=$(systemctl show xio-mtproto.service --property=LoadState,FragmentPath,DropInPaths,Names,Transient,UnitFileState) || ownership_error unit-query
  while IFS='=' read -r key value; do
    [[ "$key" =~ ^[A-Za-z]+$ ]] && [ -z "${seen[$key]:-}" ] || ownership_error duplicate-unit-property
    seen[$key]=1
    case "$key" in
      LoadState) load=$value ;; FragmentPath) fragment=$value ;; DropInPaths) drops=$value ;;
      Names) names=$value ;; Transient) transient=$value ;; UnitFileState) state=$value ;;
      *) ownership_error unit-properties ;;
    esac
    count=$((count+1))
  done <<< "$text"
  [ "$count" = 6 ] && [ -z "$drops" ] && [ "$names" = xio-mtproto.service ] && [ "$transient" = no ] || ownership_error unit-identity
  if [ "$mode" = fresh ]; then
    [ "$load" = not-found ] && [ -z "$fragment$state" ] || ownership_error foreign-unit
  elif [ "$load" = not-found ] && [ "$mode" = removing ]; then
    [ -z "$fragment$state" ] || ownership_error absent-unit
  else
    [ "$load" = loaded ] && [ "$fragment" = "$UNIT" ] || ownership_error foreign-fragment
    case "$state" in enabled|disabled) ;; *) ownership_error unit-file-state ;; esac
  fi
  # No enable/disable sweep: all same-unit links except our exact link collide.
  local links canonical
  local -a link_roots=()
  local -A root_seen=()
  for directory in "$SYSTEM_ETC" "$SYSTEM_RUN" "${UNIT_VENDOR_DIRS[@]}"; do
    exists "$directory" || continue
    [ -d "$directory" ] || ownership_error unit-scan-directory
    case "$directory" in "$SYSTEM_ETC"|"$SYSTEM_RUN") trusted_path "$directory" ;; esac
    # Canonicalization is ONLY for read-only vendor collision detection/dedup.
    # In particular /lib -> /usr/lib never authorizes a managed write.
    canonical=$(readlink -e -- "$directory") || ownership_error unit-scan-root
    [ -n "$canonical" ] || ownership_error unit-scan-root
    if [ -z "${root_seen[$canonical]:-}" ]; then
      root_seen[$canonical]=1
      link_roots+=("$canonical")
    fi
  done
  # Default physical traversal: never recurse through child symlink directories.
  links=$(find "${link_roots[@]}" -type l -print) || ownership_error unit-links
  while IFS= read -r link; do
    [ -n "$link" ] || continue
    target=$(readlink -- "$link") || ownership_error readlink
    if [ "${link##*/}" = xio-mtproto.service ] || [ "${target##*/}" = xio-mtproto.service ]; then
      [ "$link" = "$ENABLE_LINK" ] || ownership_error foreign-unit-link
    fi
  done <<< "$links"
}
unknown_entries() {
  local directory path key known entries
  for directory in "$MTG_LIB" "$MTG_ETC"; do
    [ -d "$directory" ] || continue
    trusted_path "$directory"
    entries=$(find "$directory" -mindepth 1 -maxdepth 1 -print) || ownership_error directory-query
    while IFS= read -r path; do
      [ -n "$path" ] || continue
      known=0
      for key in "${OWNER_KEYS[@]}"; do [ "${OP[$key]:-}" = "$path" ] && known=1; done
      [ "$known" = 1 ] || ownership_error unknown-entry
    done <<< "$entries"
  done
}
owner_fresh_check() {
  local key
  account_absent
  for key in "${OWNER_KEYS[@]}"; do
    case "$key" in user|group) continue ;; esac
    # Child parents inside absent managed trees are checked at creation instead.
    case "$key" in lib|etc|unit|link) trusted_path "${OP[$key]%/*}" ;; esac
    ! exists "${OP[$key]}" || ownership_error fixed-path-collision
  done
  unit_check fresh
}
owner_validate() {
  local key status identity
  for key in "${OWNER_KEYS[@]}"; do
    status=${OS[$key]}
    if [ "$OWNER_PHASE" = ready ]; then [ "$status" = owned ] || ownership_error incomplete-ready; fi
    case "$status" in
      owned) identity=$(resource_identity "$key") || exit 1
             [ "$identity" = "${OI[$key]}" ] || ownership_error changed-resource ;;
      intent) if ! resource_absent "$key"; then
                identity=$(resource_identity "$key") || exit 1
                [ "$identity" = "${OI[$key]}" ] || ownership_error replaced-pending-resource
              fi ;;
      removed|absent) resource_absent "$key" || ownership_error replaced-retired-resource ;;
    esac
  done
  if [ "${OS[user]}" = owned ]; then
    [ "$(printf '%s' "${OI[user]}" | cut -d: -f2)" = "${OI[group]}" ] || ownership_error primary-group
  fi
  unknown_entries
  if [ "$OWNER_PHASE" = ready ]; then unit_check owned; else unit_check removing; fi
}
owner_begin() {
  local key bin
  owner_paths
  for bin in stat sha256sum flock getent find readlink awk od mktemp; do command -v "$bin" >/dev/null || ownership_error missing-safety-tool; done
  trusted_path "${OWNER_DIR%/*}"
  if ! exists "$OWNER_DIR"; then
    owner_fresh_check
    mkdir -m 0700 -- "$OWNER_DIR" || ownership_error exclusive-control-create
    (set -o noclobber; umask 077; : > "$OWNER_LOCK") || ownership_error exclusive-lock-create
    OWNER_CONTROL=$(stat -c '%d:%i:%u:%g:%a' "$OWNER_DIR")
    OWNER_LOCK_ID=$(lock_identity)
    OWNER_GEN=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
    OWNER_PHASE=install-pending OWNER_DEPS=0 OWNER_STOP=0
    for key in "${OWNER_KEYS[@]}"; do OS[$key]=absent OI[$key]=-; done
    exec {OWNER_FD}<"$OWNER_LOCK"
    flock -x "$OWNER_FD" || ownership_error lock
    owner_fresh_check
    owner_save
    OWNER_NEW=1
  else
    trusted_path "$OWNER_DIR"
    [ -d "$OWNER_DIR" ] && [ "$(stat -c '%u:%a' "$OWNER_DIR")" = 0:700 ] || ownership_error control-mode
    trusted_path "$OWNER_LOCK"
    [ -f "$OWNER_LOCK" ] && [ "$(stat -c '%u:%a:%h' "$OWNER_LOCK")" = 0:600:1 ] || ownership_error lock-mode
    exec {OWNER_FD}<"$OWNER_LOCK"
    flock -x "$OWNER_FD" || ownership_error lock
    owner_load
    OWNER_NEW=0
    case "$OWNER_PHASE" in install-pending|update-pending) ownership_error interrupted-install-or-update ;; esac
    owner_validate
  fi
}
owner_record() {
  OI[$1]=$(resource_identity "$1") || exit 1
  OS[$1]=owned
  owner_save
}
owner_prepare_install() {
  owner_begin
  case "$OWNER_PHASE" in
    ready) OWNER_PHASE=update-pending; owner_save ;;
    uninstalled)
      owner_fresh_check
      OWNER_GEN=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
      OWNER_PHASE=install-pending OWNER_DEPS=0 OWNER_STOP=0 OWNER_NEW=1
      local key; for key in "${OWNER_KEYS[@]}"; do OS[$key]=absent OI[$key]=-; done
      owner_save ;;
    install-pending) [ "$OWNER_NEW" = 1 ] || ownership_error pending ;;
    *) ownership_error removal-in-progress ;;
  esac
}
owner_after_dependencies() {
  if [ "$OWNER_NEW" = 1 ]; then owner_fresh_check
  else
    # Validate the previous owned generation again after possible package effects.
    OWNER_PHASE=ready; owner_validate; OWNER_PHASE=update-pending
  fi
}
owner_remove_one() {
  local key=$1
  [ "${OS[$key]}" != removed ] || return 0
  if [ "${OS[$key]}" = intent ] && resource_absent "$key"; then
    OS[$key]=removed; owner_save; return
  fi
  [ "$(resource_identity "$key")" = "${OI[$key]}" ] || ownership_error cleanup-drift
  if [ "${OS[$key]}" != intent ]; then
    case "$key" in lib|etc) OI[$key]=${OI[$key]}:$(change_stamp "${OP[$key]}") ;; esac
  fi
  OS[$key]=intent
  # Some userdel implementations also remove an empty same-name private group.
  # Authorize only the already verified owned group and retain its pending proof.
  if [ "$key" = user ]; then
    [ "$(account_identity group)" = "${OI[group]}" ] || ownership_error group-before-userdel
    OS[group]=intent
  fi
  owner_save
  case "$key" in
    user) userdel "$MTG_USER" || ownership_error userdel-failed ;;
    group) groupdel "$MTG_USER" || ownership_error groupdel-failed ;;
    lib|etc) rmdir -- "${OP[$key]}" || ownership_error directory-not-empty ;;
    *) rm -- "${OP[$key]}" || ownership_error unlink-failed ;;
  esac
  resource_absent "$key" || ownership_error cleanup-postcondition
  OS[$key]=removed; owner_save
}

# Слушатели указанного TCP-порта: строка `ss` без заголовка или пусто.
# `ss` печатает wildcard как `*:8444` или `0.0.0.0:8444`, поэтому фильтр
# встроенным выражением `sport =` ненадёжен — разбираем поле локального адреса.
listeners_on_port() {
  ss -Hltnp 2>/dev/null | awk -v want=":$1\$" '$4 ~ want'
}

need_root() { [ "$(id -u)" = 0 ] || die "нужен root (sudo)"; }

# Адрес и порт, которые попадут в ссылку tg://proxy. Их читает admin.py XIO
# (action=mtproto), поэтому приложение подставляет ссылку само. Пишем только
# при изменении значения: повторный запуск не трогает неизменившиеся файлы.
write_link_facts() {
  local name value path
  for name in port domain; do
    if [ "$name" = port ]; then value=$MTG_PORT; else value=$MTG_PUBLIC_IP; fi
    path=$MTG_ETC/$name
    if [ -f "$path" ] && [ "$(cat "$path")" = "$value" ]; then
      log "файл $path без изменений"
      continue
    fi
    printf '%s\n' "$value" > "$path"
    chown root:"$MTG_USER" "$path"
    chmod 0640 "$path"
    owner_record "$name"
    log "файл $path обновлён"
  done
}

detect_public_ip() {
  local ip
  for url in https://ifconfig.co https://api.ipify.org https://icanhazip.com; do
    ip=$(curl -fsS --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)
    if printf '%s' "$ip" | grep -Eq '^[0-9]{1,3}(\.[0-9]{1,3}){3}$'; then
      printf '%s' "$ip"
      return 0
    fi
  done
  return 1
}

print_link() {
  local secret ip port
  secret=$(sed -n 's/^secret *= *"\(.*\)"/\1/p' "$MTG_CONF" 2>/dev/null | head -1)
  [ -n "$secret" ] || die "конфиг $MTG_CONF не найден или в нём нет secret"
  ip=${MTG_PUBLIC_IP:-$(sed -n 's/^public-ipv4 *= *"\(.*\)"/\1/p' "$MTG_CONF" | head -1)}
  if [ -z "$ip" ]; then
    [ "${MTG_PRINT_ONLY:-0}" != 1 ] || die "missing public address: set MTG_PUBLIC_IP or restore recorded address"
    ip=$(detect_public_ip) || die "не удалось определить публичный IPv4"
  fi
  port=$(sed -n 's/^port=//p' "$MTG_STATE" 2>/dev/null | head -1 || true)
  [ -n "$port" ] || port=$(sed -n 's/^bind-to *= *".*:\([0-9]*\)"/\1/p' "$MTG_CONF" | head -1)
  [ -n "$port" ] || port=$MTG_PORT
  printf 'tg://proxy?server=%s&port=%s&secret=%s\n' "$ip" "$port" "$secret"
}

# A durable stop milestone is not live quiescence: a reboot can restart a
# still-enabled owned unit. Re-establish this on EVERY uninstall invocation.
owner_live_quiescence() {
  local identity active
  if exists "$UNIT"; then
    case "${OS[unit]}" in owned|intent) ;; *) ownership_error unexpected-live-unit ;; esac
    identity=$(resource_identity unit) || exit 1
    [ "$identity" = "${OI[unit]}" ] || ownership_error stop-unit-drift
    unit_check owned
    if [ "$OWNER_STOP" != done ]; then OWNER_STOP=intent; owner_save; fi
    systemctl stop xio-mtproto.service || ownership_error stop-failed
  else
    # Without the disk identity, never stop a possibly foreign loaded service.
    # Journal-proven absence permits only a read-only inactive check.
    case "${OS[unit]}" in intent|removed) ;; *) ownership_error missing-stop-unit ;; esac
    unit_check removing
  fi
  active=$(systemctl show xio-mtproto.service --property=ActiveState --value) || ownership_error stop-query
  [ "$active" = inactive ] || ownership_error current-quiescence-unproved
  if [ "$OWNER_STOP" != done ]; then OWNER_STOP=done; owner_save; fi
}

uninstall() {
  need_root
  exists "$OWNER_DIR" || ownership_error no-receipt
  owner_begin
  if [ "$OWNER_PHASE" = uninstalled ]; then
    owner_live_quiescence
    log "already uninstalled (ownership evidence retained)"
    return
  fi
  if [ "$OWNER_PHASE" = ready ]; then OWNER_PHASE=uninstalling; owner_save; fi
  [ "$OWNER_PHASE" = uninstalling ] || ownership_error removal-state
  owner_live_quiescence
  local key
  # Never invoke systemctl disable: it can sweep unowned aliases/links.
  for key in link unit; do owner_remove_one "$key"; done
  systemctl daemon-reload || ownership_error reload-failed
  unit_check fresh
  for key in bin license release secret conf port domain state lib etc user group; do owner_remove_one "$key"; done
  systemctl daemon-reload || ownership_error final-reload-failed
  owner_validate
  OWNER_PHASE=uninstalled; owner_save
  log "xio-mtproto removed; root-only ownership receipt and stable lock retained"
}

main() {
  case "${1:-}" in
    --print-link)
      need_root
      trusted_path "$MTG_CONF"
      [ -f "$MTG_CONF" ] && [ "$(stat -c %h "$MTG_CONF")" = 1 ] || ownership_error print-config
      if exists "$MTG_STATE"; then trusted_path "$MTG_STATE"; [ -f "$MTG_STATE" ] && [ "$(stat -c %h "$MTG_STATE")" = 1 ] || ownership_error print-state; fi
      MTG_PRINT_ONLY=1 print_link
      return 0
      ;;
    --uninstall)
      uninstall
      return 0
      ;;
    ''|--install) ;;
    *) die "неизвестный аргумент: $1 (см. --help)";;
  esac

  need_root

  umask 077
  owner_prepare_install

  # 1. Зависимости.
  for bin in curl tar sha256sum; do
    command -v "$bin" >/dev/null 2>&1 || {
      OWNER_DEPS=1; owner_save
      log "устанавливаю $bin"
      apt-get update -qq
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl tar coreutils
      break
    }
  done

  owner_after_dependencies

  # 2. Служебный пользователь.
  if [ "$OWNER_NEW" = 1 ]; then
    groupadd --system "$MTG_USER"
    owner_record group
    useradd --system --gid "$MTG_USER" --no-create-home --home-dir "$MTG_LIB" --shell /usr/sbin/nologin --comment "xio-mtproto-$OWNER_GEN" "$MTG_USER"
    owner_record user
    mkdir -m 0755 -- "$MTG_LIB"
    owner_record lib
    mkdir -m 0750 -- "$MTG_ETC"
    chown root:"$MTG_USER" "$MTG_ETC"
    owner_record etc
  fi

  # 3. Бинарь mtg нужной версии.
  # checksums.txt хеширует ТАРБОЛ, а не бинарь, поэтому «уже установлено»
  # проверяем по своему state: версия + sha256 установленного бинаря.
  local want_sha current_sha archive dir state_ver state_sha
  state_ver=$(sed -n 's/^version=//p' "$MTG_STATE" 2>/dev/null | head -1 || true)
  state_sha=$(sed -n 's/^binary-sha256=//p' "$MTG_STATE" 2>/dev/null | head -1 || true)
  current_sha=$(sha256sum "$MTG_BIN" 2>/dev/null | awk '{print $1}' || true)

  if [ "$state_ver" = "$MTG_VERSION" ] && [ -n "$state_sha" ] && [ "$state_sha" = "$current_sha" ]; then
    log "бинарь mtg ${MTG_VERSION} уже установлен (sha256 совпал)"
    changed_bin=0
  else
    log "скачиваю mtg ${MTG_VERSION} (linux-amd64)"
    want_sha=$(curl -fsSL --max-time 20 \
      "https://github.com/9seconds/mtg/releases/download/v${MTG_VERSION}/mtg-${MTG_VERSION}-checksums.txt" \
      | awk -v n="mtg-${MTG_VERSION}-linux-amd64.tar.gz" '$2==n || $2=="*"n {print $1}' | head -1)
    [ -n "$want_sha" ] || die "не нашёл контрольную сумму для mtg ${MTG_VERSION} (linux-amd64)"
    dir=$(mktemp -d)
    # Only our fresh private download staging tree is recursively cleaned.
    # Keep the path alive after main returns; never apply this to managed trees.
    MTG_DOWNLOAD_DIR=$dir
    trap '[ -z "${MTG_DOWNLOAD_DIR:-}" ] || rm -rf -- "$MTG_DOWNLOAD_DIR"' EXIT
    archive="$dir/mtg.tar.gz"
    curl -fsSL --max-time 120 -o "$archive" \
      "https://github.com/9seconds/mtg/releases/download/v${MTG_VERSION}/mtg-${MTG_VERSION}-linux-amd64.tar.gz" \
      || die "не удалось скачать релиз mtg ${MTG_VERSION}"
    echo "$want_sha  $archive" | sha256sum -c --status - \
      || die "контрольная сумма релиза не совпала"
    tar -xzf "$archive" -C "$dir"
    install -m 0755 "$dir/mtg-${MTG_VERSION}-linux-amd64/mtg" "$MTG_BIN"
    owner_record bin
    install -m 0644 "$dir/mtg-${MTG_VERSION}-linux-amd64/LICENSE" "$MTG_LIB/LICENSE"
    owner_record license
    printf '%s  %s\n' "$want_sha" "mtg-${MTG_VERSION}-linux-amd64.tar.gz" > "$MTG_ETC/release.sha256"
    owner_record release
    log "бинарь обновлён до ${MTG_VERSION}"
    changed_bin=1
  fi

  # 4. Секрет FakeTLS. Генерируется один раз и привязывается к домену маскировки.
  local secret domain_prev
  domain_prev=$(sed -n 's/^domain=//p' "$MTG_SECRET_FILE" 2>/dev/null | head -1 || true)
  secret=$(sed -n 's/^secret=//p' "$MTG_SECRET_FILE" 2>/dev/null | head -1 || true)
  if [ -z "$secret" ] || [ "$domain_prev" != "$MTG_DOMAIN" ]; then
    log "генерирую FakeTLS-секрет для домена $MTG_DOMAIN"
    secret=$("$MTG_BIN" generate-secret --hex "$MTG_DOMAIN")
    [ -n "$secret" ] || die "mtg generate-secret не вернул секрет"
    printf 'secret=%s\ndomain=%s\n' "$secret" "$MTG_DOMAIN" > "$MTG_SECRET_FILE"
    log "секрет сохранён в $MTG_SECRET_FILE (0600)"
  else
    log "секрет для домена $MTG_DOMAIN уже есть — переиспользую"
  fi
  chown root:"$MTG_USER" "$MTG_SECRET_FILE"
  chmod 0640 "$MTG_SECRET_FILE"
  owner_record secret

  # 5. Конфиг mtg.
  if [ -z "$MTG_PUBLIC_IP" ]; then
    MTG_PUBLIC_IP=$(sed -n 's/^public-ipv4 *= *"\(.*\)"/\1/p' "$MTG_CONF" 2>/dev/null | head -1 || true)
  fi
  if [ -z "$MTG_PUBLIC_IP" ]; then
    MTG_PUBLIC_IP=$(detect_public_ip) || die "укажите MTG_PUBLIC_IP: сервер не отдал свой внешний IPv4"
  fi

  # 5b. Порт и адрес ссылки для приложения XIO (их читает admin.py, action=mtproto).
  #     Адрес — тот же, что печатает --print-link: публичный IPv4 из конфига.
  write_link_facts

  # Семейство IP для выхода к Telegram. На российском бридже IPv4 к DC
  # Telegram режется провайдером (SYN без ответа), а IPv6 идёт через туннель
  # каскада (xio-cascade → exit). Поэтому по умолчанию пробуем сами и берём
  # то семейство, которое реально отвечает.
  local family fronting_host fronting_line=""
  family=${MTG_IP_FAMILY:-}
  if [ -z "$family" ]; then
    local v4=0 v6=0
    timeout 5 bash -c 'echo > /dev/tcp/149.154.175.50/443' 2>/dev/null && v4=1
    timeout 5 bash -c 'echo > /dev/tcp/2001:b28:f23d:f001::a/443' 2>/dev/null && v6=1
    case "$v4$v6" in
      11) family=prefer-ipv6 ;;
      10) family=only-ipv4 ;;
      01) family=only-ipv6 ;;
      *)  family=prefer-ipv6 ;;
    esac
    log "проверка выхода к Telegram: IPv4 $([ $v4 = 1 ] && echo ок || echo недоступен), IPv6 $([ $v6 = 1 ] && echo ок || echo недоступен) → prefer-ip = ${family}"
    [ "$v4$v6" = "00" ] && warn "ни IPv4, ни IPv6 к Telegram не отвечают: прокси поднимется, но трафик не пойдёт (нужен туннель/egress)"
  fi

  # Если домен маскировки указывает на этот же сервер, fronting-соединение
  # лучше диалать по литеральному IP: тогда маскировка работает и при
  # only-ipv6 (DNS-AAAA у домена может отсутствовать).
  fronting_host=$(getent ahostsv4 "$MTG_DOMAIN" 2>/dev/null | awk 'NR==1{print $1}')
  if [ "$fronting_host" = "$MTG_PUBLIC_IP" ]; then
    fronting_line="host = \"${MTG_PUBLIC_IP}\""
  fi

  local new_conf
  new_conf=$(mktemp)
  cat > "$new_conf" <<EOF
# XIO MTProto-прокси (mtg ${MTG_VERSION}). Файл создан xio-mtproto-setup.sh.
# Руками не редактировать: перезапуск скрипта перезапишет конфиг.
secret = "${secret}"
# hostname в bind-to запрещён: только литеральный IP.
bind-to = "0.0.0.0:${MTG_PORT}"
concurrency = 8192
# Определено автотестом выхода: IPv4 к Telegram на российском бридже режется,
# рабочий путь — IPv6 через туннель каскада до exit-сервера.
prefer-ip = "${family}"
public-ipv4 = "${MTG_PUBLIC_IP}"
auto-update = false
# Пустая строка = системный резолвер; DoH по умолчанию может быть недоступен.
dns = "${MTG_DNS}"
# Печать секрета в лог не нужна.
debug = false

[domain-fronting]
port = 443
${fronting_line}

[defense.blocklist]
enabled = false
EOF
  if [ -n "$MTG_SOCKS5" ]; then
    cat >> "$new_conf" <<EOF

# Весь исходящий трафик mtg идёт через этот socks5 (egress в сети, где
# Telegram не заблокирован). Пусто — прямой выход с этого хоста.
[network]
proxies = ["${MTG_SOCKS5}"]
EOF
  fi
  chown root:"$MTG_USER" "$new_conf"
  chmod 0640 "$new_conf"

  local changed_conf=0
  if ! cmp -s "$new_conf" "$MTG_CONF"; then
    mv "$new_conf" "$MTG_CONF"; changed_conf=1
    log "конфиг обновлён: $MTG_CONF"
  else
    rm -f "$new_conf"
    log "конфиг без изменений"
  fi

  owner_record conf

  # 6. systemd-юнит.
  local new_unit
  new_unit=$(mktemp)
  cat > "$new_unit" <<EOF
[Unit]
Description=XIO MTProto-прокси для Telegram (mtg)
Documentation=https://github.com/9seconds/mtg
After=network-online.target
Wants=network-online.target
# Больше 5 рестартов за минуту — что-то системное, дальше не долбим.
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
Type=simple
User=${MTG_USER}
Group=${MTG_USER}
ExecStart=${MTG_BIN} run ${MTG_CONF}
Restart=always
RestartSec=3
LimitNOFILE=65536
SyslogIdentifier=xio-mtproto
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ProtectClock=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes

[Install]
WantedBy=multi-user.target
EOF
  local changed_unit=0
  if ! cmp -s "$new_unit" "$UNIT"; then
    install -m 0644 "$new_unit" "$UNIT"; changed_unit=1
    log "юнит обновлён: $UNIT"
  else
    log "юнит без изменений"
  fi
  rm -f "$new_unit"
  owner_record unit
  systemctl daemon-reload
  unit_check owned

  # 7. Порт занят чужим процессом? Проверяем до запуска, чтобы не гадать по логам.
  if command -v ss >/dev/null 2>&1; then
    local busy
    busy=$(listeners_on_port "$MTG_PORT" | grep -v xio-mtproto || true)
    if [ -n "$busy" ] && ! systemctl is-active --quiet xio-mtproto; then
      die "порт ${MTG_PORT}/tcp уже занят: $busy — задайте другой MTG_PORT"
    fi
  fi

  # 8. Запуск и проверка. `is-active` становится true раньше, чем mtg
  # успевает занять порт, поэтому порт ждём отдельным опросом.
  if [ "$OWNER_NEW" = 1 ]; then
    trusted_path "${ENABLE_LINK%/*}"
    ! exists "$ENABLE_LINK" || ownership_error link-collision
    ln -s -- "$UNIT" "$ENABLE_LINK"
    owner_record link
    systemctl daemon-reload
  fi
  unit_check owned
  if [ "$changed_bin$changed_conf$changed_unit" != "000" ] || ! systemctl is-active --quiet xio-mtproto; then
    systemctl restart xio-mtproto.service
  fi

  local i listening=0
  for i in $(seq 1 40); do
    if systemctl is-active --quiet xio-mtproto.service &&
       { ! command -v ss >/dev/null 2>&1 || listeners_on_port "$MTG_PORT" | grep -q .; }; then
      listening=1
      break
    fi
    sleep 0.25
  done
  if ! systemctl is-active --quiet xio-mtproto.service; then
    die "служба не поднялась (см. journalctl -u xio-mtproto -n 50)"
  fi
  if [ "$listening" != 1 ]; then
    die "служба активна, но порт ${MTG_PORT}/tcp не слушается за 10 с"
  fi

  local new_state
  new_state=$(mktemp "$MTG_ETC/.state.XXXXXXXX")
  printf 'secret=%s\n' "$secret" > "$new_state"
  chmod 0600 "$new_state"
  printf 'version=%s\nport=%s\ndomain=%s\npublic-ipv4=%s\nbinary-sha256=%s\n' \
    "$MTG_VERSION" "$MTG_PORT" "$MTG_DOMAIN" "$MTG_PUBLIC_IP" \
    "$(sha256sum "$MTG_BIN" | awk '{print $1}')" >> "$new_state"
  if cmp -s "$new_state" "$MTG_STATE"; then rm -- "$new_state"
  else mv -T -- "$new_state" "$MTG_STATE"; fi

  owner_record state
  OWNER_PHASE=ready
  owner_validate
  owner_save

  log "служба активна, порт ${MTG_PORT}/tcp слушается"
  log "ссылка для Telegram:"
  print_link
  cat <<EOF

Дальше в Telegram: Настройки → Данные и память → Прокси → Добавить прокси →
MTProto → вставить ссылку выше → включить прокси.

Провека выхода к Telegram (без клиента):
  /usr/local/lib/xio-mtproto/mtg doctor /etc/xio-mtproto/config.toml

На этом бридже IPv4 к DC Telegram режет провайдер, рабочий путь — IPv6 через
туннель каскада (xio-cascade → exit). Если doctor показывает "i/o timeout",
проверьте, что туннель поднят: systemctl is-active xio-cascade и
ping6 -c1 2001:4860:4860::8888. Без туннеля прокси слушает порт, но до
Telegram не доходит.
EOF
}

if [[ "${BASH_SOURCE[0]}" = "$0" ]]; then main "$@"; fi
