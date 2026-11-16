"""Offline actual-shell S4 regression tests; root POSIX owned fixtures only.
Run: XIO_TEST_ROOT=/srv/archives/agent-mtproto-ownership-fix-20261106 python3 -B test_ownership.py
No actual account/service/package/network commands are executed. Shell filesystem
commands are guarded to this fixture; stat/chmod/flock operate on real POSIX files.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).with_name('xio-mtproto-setup.sh').resolve()
ROOT = Path(os.environ.get('XIO_TEST_ROOT', '')).resolve()
AUTHORIZED = Path('/srv/archives/agent-mtproto-ownership-fix-20261106')
SECRET = 'ee000102030405060708090a0b0c0d0e0f6578616d706c652e6f7267'

MOCKS = r'''
record() { printf '%s\n' "$*" >> "$FX/effects"; }
fail() { [ -f "$FX/fail-$1" ]; }
guard() { case "$1" in "$FX"|"$FX"/*) ;; *) printf 'UNSAFE fixture path\n' >&2; exit 96;; esac; }
id() { [ "$*" = -u ] && printf '0\n' || return 97; }
getent() {
  local db=$1 query=${2:-} file line
  case "$db" in
    passwd) file=$LOCAL_PASSWD ;; group) file=$LOCAL_GROUP ;;
    ahostsv4) record 'getent DNS mocked'; printf '192.0.2.40 STREAM synthetic\n'; return ;;
    *) return 97 ;;
  esac
  fail nss && return 9
  if [ -z "$query" ]; then /bin/cat "$file"; return; fi
  line=$(awk -F: -v q="$query" '$1==q || $3==q {print}' "$file")
  [ -n "$line" ] || return 2
  printf '%s\n' "$line"
}
groupadd() {
  record "groupadd $*"; fail groupadd && return 9
  printf 'xio-mtproto:x:42002:\n' >> "$LOCAL_GROUP"
  fail after-groupadd && exit 88
  return 0
}
useradd() {
  record 'useradd xio-mtproto'; fail useradd && return 9
  printf 'xio-mtproto:x:42001:42002:xio-mtproto-%s:%s:/usr/sbin/nologin\n' "$OWNER_GEN" "$MTG_LIB" >> "$LOCAL_PASSWD"
  fail after-useradd && exit 88
  return 0
}
userdel() {
  record "userdel $*"; fail userdel && return 9
  [ "$*" = xio-mtproto ] || exit 97
  /usr/bin/sed -i '/^xio-mtproto:/d' "$LOCAL_PASSWD"
  if fail implicit-group-delete; then /usr/bin/sed -i '/^xio-mtproto:/d' "$LOCAL_GROUP"; fi
  fail after-userdel && exit 88
  return 0
}
groupdel() {
  record "groupdel $*"; fail groupdel && return 9
  [ "$*" = xio-mtproto ] || exit 97
  /usr/bin/sed -i '/^xio-mtproto:/d' "$LOCAL_GROUP"
  return 0
}
systemctl() {
  local load=not-found fragment= drops= names=xio-mtproto.service transient=no state=
  case "$1" in
    show)
      fail show && return 9
      if [ "${3:-}" = --property=ActiveState ]; then
        if [ -f "$FX/active-state" ]; then /bin/cat "$FX/active-state"; else printf 'inactive\n'; fi
        return
      fi
      if [ -f "$UNIT" ]; then load=loaded; fragment=$UNIT; state=disabled; fi
      if [ -L "$ENABLE_LINK" ]; then state=enabled; fi
      if [ -f "$FX/unit-overrides" ]; then
        while IFS='=' read -r k v; do
          case "$k" in load) load=$v;; fragment) fragment=$v;; drops) drops=$v;; names) names=$v;; transient) transient=$v;; state) state=$v;; *) exit 97;; esac
        done < "$FX/unit-overrides"
      fi
      printf 'LoadState=%s\nFragmentPath=%s\nDropInPaths=%s\nNames=%s\nTransient=%s\nUnitFileState=%s\n' "$load" "$fragment" "$drops" "$names" "$transient" "$state"
      ;;
    is-active) [ -f "$FX/active-state" ] && [ "$(/bin/cat "$FX/active-state")" = active ] ;;
    daemon-reload|restart|stop)
      record "systemctl $*"; fail "$1" && return 9
      case "$1" in restart) printf 'active\n' > "$FX/active-state" ;; stop) printf 'inactive\n' > "$FX/active-state" ;; esac
      return 0 ;;
    *) record "UNEXPECTED systemctl $*"; exit 97 ;;
  esac
}
chown() { record 'chown mocked'; fail chown && return 9; return 0; }
apt-get() {
  record "apt-get $*"; fail apt && return 9
  if fail apt-collision; then printf 'foreign unit after package operation' > "$UNIT"; fi
  return 0
}
curl() {
  record 'curl mocked'; fail curl && return 9
  if [[ "$*" = *checksums.txt* ]]; then
    printf '%s  mtg-%s-linux-amd64.tar.gz\n' "$(printf 'synthetic archive' | /usr/bin/sha256sum | awk '{print $1}')" "$MTG_VERSION"
  else
    local previous= arg destination=
    for arg in "$@"; do [ "$previous" != -o ] || destination=$arg; previous=$arg; done
    [ -n "$destination" ] || exit 97
    guard "$destination"; printf 'synthetic archive' > "$destination"
  fi
}
tar() {
  record 'tar mocked'; fail tar && return 9
  local previous= arg destination=
  for arg in "$@"; do [ "$previous" != -C ] || destination=$arg; previous=$arg; done
  guard "$destination"
  /bin/mkdir -p "$destination/mtg-$MTG_VERSION-linux-amd64"
  printf '#!/bin/bash\nprintf "generate-secret mocked\\n" >> "$FX/effects"\nprintf "%%s\\n" "ee000102030405060708090a0b0c0d0e0f6578616d706c652e6f7267"\n' > "$destination/mtg-$MTG_VERSION-linux-amd64/mtg"
  printf 'synthetic license\n' > "$destination/mtg-$MTG_VERSION-linux-amd64/LICENSE"
}
ss() { printf 'LISTEN 0 8 0.0.0.0:%s 0.0.0.0:* users:(("xio-mtproto"))\n' "$MTG_PORT"; }
timeout() { record 'UNEXPECTED network timeout'; exit 97; }
journalctl() { record 'UNEXPECTED journalctl'; exit 97; }
sleep() { record 'UNEXPECTED sleep'; exit 97; }
install() {
  local destination=${@: -1}; guard "$destination"; record "install ${destination##*/}"
  fail install && return 9
  /usr/bin/install "$@"
}
rm() {
  local arg
  for arg in "$@"; do [[ "$arg" = -* ]] || guard "$arg"; done
  record 'rm fixture'; fail rm && return 9
  /bin/rm "$@"
  fail after-rm && exit 88
  return 0
}
rmdir() {
  local destination=${@: -1}; guard "$destination"; record 'rmdir fixture'
  fail rmdir && return 9
  if fail rmdir-add-entry; then printf 'synthetic unknown entry' > "$destination/foreign"; fi
  /bin/rmdir "$@"
}
mv() {
  local destination=${@: -1}; guard "$destination"
  if [ "$destination" = "$OWNER_RECEIPT" ]; then
    record 'journal publication'
    local count=0 stop_at=0
    [ ! -f "$FX/journal-count" ] || read -r count < "$FX/journal-count"
    count=$((count+1)); printf '%s\n' "$count" > "$FX/journal-count"
    [ ! -f "$FX/journal-stop-at" ] || read -r stop_at < "$FX/journal-stop-at"
    if [ "$count" = "$stop_at" ] && fail before-journal; then exit 88; fi
    fail journal && return 9
    if fail journal-final && [ "$OWNER_PHASE" = uninstalled ]; then return 9; fi
  fi
  /bin/mv "$@"
  if [ "$destination" = "$OWNER_RECEIPT" ] && [ "$OWNER_PHASE" = uninstalling ] && [ "$OWNER_STOP" = done ] && [ "${OS[link]}" = owned ] && fail after-stop-done; then exit 88; fi
  if [ "$destination" = "$OWNER_RECEIPT" ] && [ "$count" = "$stop_at" ] && fail after-journal; then exit 88; fi
  return 0
}
mkdir() {
  local destination=${@: -1}; guard "$destination"; record "mkdir ${destination##*/}"
  /bin/mkdir "$@"
}
ln() { local destination=${@: -1}; guard "$destination"; record 'ln owned'; fail ln && return 9; /bin/ln "$@"; }
mktemp() {
  local arg
  for arg in "$@"; do [[ "$arg" = -* ]] || guard "$arg"; done
  /usr/bin/mktemp "$@"
}
'''


class Fixture:
    def __init__(self):
        self.root = Path(tempfile.mkdtemp(prefix='case-', dir=ROOT))
        os.chmod(self.root, 0o700)
        for relative in ('home', 'tmp', 'var/lib', 'usr/local/lib', 'etc/systemd/system/multi-user.target.wants', 'run/systemd/system'):
            (self.root / relative).mkdir(parents=True, exist_ok=True)
        self.passwd = self.root / 'passwd'
        self.group = self.root / 'group'
        self.passwd.write_text('mtg:x:41990:41990:foreign:/synthetic/manual:/usr/sbin/nologin\n')
        self.group.write_text('mtg:x:41990:\n')
        self.effects = self.root / 'effects'
        self.effects.touch()
        self.receipt = self.root / 'var/lib/xio-mtproto-owner/receipt'
        self.lib = self.root / 'usr/local/lib/xio-mtproto'
        self.etc = self.root / 'etc/xio-mtproto'
        self.unit = self.root / 'etc/systemd/system/xio-mtproto.service'
        self.link = self.root / 'etc/systemd/system/multi-user.target.wants/xio-mtproto.service'
        self.env = dict(os.environ, FX=str(self.root), HOME=str(self.root / 'home'), TMPDIR=str(self.root / 'tmp'),
                        XDG_CACHE_HOME=str(self.root / 'home/cache'), BASH_ENV='', ENV='')
        self.header = f'''set -euo pipefail
source '{SOURCE}'
MTG_LIB="$FX/usr/local/lib/xio-mtproto"
MTG_ETC="$FX/etc/xio-mtproto"
MTG_BIN=$MTG_LIB/mtg
MTG_CONF=$MTG_ETC/config.toml
MTG_SECRET_FILE=$MTG_ETC/secret
MTG_STATE=$MTG_ETC/state
SYSTEM_ETC="$FX/etc/systemd/system"
SYSTEM_RUN="$FX/run/systemd/system"
UNIT_VENDOR_DIRS=("$FX/usr/lib/systemd/system")
UNIT=$SYSTEM_ETC/xio-mtproto.service
ENABLE_LINK=$SYSTEM_ETC/multi-user.target.wants/xio-mtproto.service
OWNER_DIR="$FX/var/lib/xio-mtproto-owner"
OWNER_RECEIPT=$OWNER_DIR/receipt
OWNER_LOCK=$OWNER_DIR/lock
LOCAL_PASSWD=$FX/passwd
LOCAL_GROUP=$FX/group
MTG_PUBLIC_IP=192.0.2.40
MTG_DOMAIN=example.org
MTG_IP_FAMILY=only-ipv4
'''+MOCKS

    def run(self, action='main --install', before=''):
        script = self.root / 'invoke.sh'
        script.write_text(self.header + '\n' + before + '\n' + action + '\n')
        return subprocess.run(['/bin/bash', '--noprofile', '--norc', str(script)], env=self.env,
                              cwd=self.root, capture_output=True, text=True, timeout=45)

    def clear(self):
        self.effects.write_text('')

    def flag(self, name):
        (self.root / ('fail-' + name)).touch()

    def unflag(self, name):
        (self.root / ('fail-' + name)).unlink()

    def trace(self):
        return self.effects.read_text()

    def phase(self):
        return self.receipt.read_text().splitlines()[2]

    def cleanup(self):
        assert self.root.parent == AUTHORIZED and self.root.name.startswith('case-')
        shutil.rmtree(self.root)


@unittest.skipUnless(ROOT == AUTHORIZED and os.name == 'posix' and os.geteuid() == 0,
                     'requires explicitly owned root POSIX fixture directory')
class OwnershipTests(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()
        self.addCleanup(self.fx.cleanup)

    def ok(self, result):
        self.assertEqual(result.returncode, 0, result.stderr[-1200:])

    def refused(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(SECRET, result.stderr)

    def installed(self):
        self.ok(self.fx.run())
        self.assertEqual(self.fx.phase(), 'ready')
        self.fx.clear()

    def test_full_install_repeat_update_uninstall_preserves_foreign_mtg(self):
        original = self.fx.passwd.read_text().splitlines()[0]
        self.installed()
        secret = (self.fx.etc / 'secret').read_bytes()
        self.ok(self.fx.run())
        self.assertEqual((self.fx.etc / 'secret').read_bytes(), secret)
        self.assertNotIn('curl', self.fx.trace())
        self.assertNotIn('generate-secret', self.fx.trace())
        self.assertNotIn('systemctl restart', self.fx.trace())
        self.ok(self.fx.run(before='MTG_VERSION=2.4.0'))
        self.assertEqual(self.fx.phase(), 'ready')
        lock = self.fx.receipt.with_name('lock').stat().st_ino
        self.ok(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.phase(), 'uninstalled')
        self.assertEqual(self.fx.passwd.read_text().strip(), original)
        self.assertFalse(self.fx.etc.exists())
        self.assertNotIn('systemctl disable', self.fx.trace())
        self.ok(self.fx.run('main --uninstall'))
        self.ok(self.fx.run())
        self.assertEqual(self.fx.receipt.with_name('lock').stat().st_ino, lock)

    def test_receiptless_uninstall_has_no_effects(self):
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.trace(), '')
        self.assertFalse(self.fx.receipt.parent.exists())

    def test_prefixed_user_collision_before_effects(self):
        with self.fx.passwd.open('a') as stream: stream.write('xio-mtproto:x:42001:42002:foreign:/foreign:/bin/false\n')
        self.refused(self.fx.run())
        self.assertEqual(self.fx.trace(), '')

    def test_prefixed_group_collision_before_effects(self):
        with self.fx.group.open('a') as stream: stream.write('xio-mtproto:x:42002:\n')
        self.refused(self.fx.run())
        self.assertEqual(self.fx.trace(), '')

    def test_fixed_path_collisions_and_dangling_link(self):
        for path in (self.fx.lib, self.fx.etc, self.fx.unit, self.fx.link):
            with self.subTest(path=path.name):
                path.symlink_to(self.fx.root / 'absent-target')
                self.refused(self.fx.run())
                self.assertEqual(self.fx.trace(), '')
                self.assertTrue(path.is_symlink())
                path.unlink()

    def test_parent_symlink_and_writable_parent(self):
        parent = self.fx.lib.parent
        os.chmod(parent, 0o777)
        self.refused(self.fx.run())
        self.assertEqual(self.fx.trace(), '')
        os.chmod(parent, 0o755)
        parent.rmdir()
        parent.symlink_to(self.fx.root / 'tmp', target_is_directory=True)
        self.refused(self.fx.run())
        self.assertEqual(self.fx.trace(), '')

    def test_effective_unit_collisions(self):
        for values in ('load=loaded\nfragment=/foreign/unit\nstate=enabled\n', 'load=masked\n',
                       'transient=yes\n', 'names=xio-mtproto.service alias.service\n',
                       'drops=/foreign/service.d/drop.conf\n'):
            with self.subTest(values=values):
                (self.fx.root / 'unit-overrides').write_text(values)
                self.refused(self.fx.run())
                self.assertEqual(self.fx.trace(), '')

    def test_unknown_same_target_enablement_link(self):
        link = self.fx.unit.parent / 'foreign.service'
        link.symlink_to(self.fx.unit)
        self.refused(self.fx.run())
        self.assertEqual(self.fx.trace(), '')
        self.assertTrue(link.is_symlink())

    def test_nss_failure_and_systemctl_query_failure(self):
        for flag in ('nss', 'show'):
            self.fx.flag(flag)
            self.refused(self.fx.run())
            self.assertEqual(self.fx.trace(), '')
            self.fx.unflag(flag)

    def test_uid_gecos_home_shell_and_primary_gid_drift(self):
        self.installed()
        original = self.fx.passwd.read_text()
        transformations = [lambda s: s.replace('42001', '42003'),
                           lambda s: s.replace('xio-mtproto-', 'recreated-'),
                           lambda s: s.replace(str(self.fx.lib), '/foreign-home'),
                           lambda s: s.replace('/usr/sbin/nologin', '/bin/sh'),
                           lambda s: s+'foreign:x:42009:42002:foreign:/foreign:/bin/false\n']
        for transform in transformations:
            with self.subTest(transform=transform):
                self.fx.passwd.write_text(transform(original))
                self.refused(self.fx.run('main --uninstall'))
                self.assertEqual(self.fx.trace(), '')
        self.fx.passwd.write_text(original)

    def test_file_drift_and_hardlink_rejected(self):
        self.installed()
        path = self.fx.etc / 'port'
        path.write_text('8445\n')
        self.refused(self.fx.run())
        self.assertEqual(self.fx.trace(), '')

    def test_unknown_files_preserved(self):
        self.installed()
        path = self.fx.etc / 'foreign'
        path.write_text('synthetic foreign')
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.trace(), '')
        self.assertTrue(path.exists())

    def test_malformed_receipt_and_lock_substitution(self):
        self.installed()
        original = self.fx.receipt.read_text()
        self.fx.receipt.write_text(original.replace('group|owned|42002', 'unknown|owned|42002'))
        self.refused(self.fx.run())
        self.assertEqual(self.fx.trace(), '')
        self.fx.receipt.write_text(original)
        lock = self.fx.receipt.with_name('lock')
        lock.unlink()
        lock.symlink_to(self.fx.root / 'effects')
        self.refused(self.fx.run())
        self.assertEqual(self.fx.trace(), '')

    def test_pending_install_after_account_creation_is_manual(self):
        self.fx.flag('after-useradd')
        self.refused(self.fx.run())
        self.assertEqual(self.fx.phase(), 'install-pending')
        self.assertIn('xio-mtproto:', self.fx.passwd.read_text())
        self.fx.clear()
        self.fx.unflag('after-useradd')
        self.refused(self.fx.run())
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.trace(), '')

    def test_failed_update_is_manual_not_adopted(self):
        self.installed()
        self.fx.flag('curl')
        self.refused(self.fx.run(before='MTG_VERSION=2.4.0'))
        self.assertEqual(self.fx.phase(), 'update-pending')
        self.fx.clear()
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.trace(), '')

    def test_stop_failure_preserves_payload_and_retries(self):
        self.installed()
        self.fx.flag('stop')
        self.refused(self.fx.run('main --uninstall'))
        self.assertTrue(self.fx.unit.exists())
        self.assertTrue((self.fx.lib / 'mtg').exists())
        self.assertEqual(self.fx.phase(), 'uninstalling')
        self.fx.unflag('stop')
        self.ok(self.fx.run('main --uninstall'))

    def test_userdel_failure_after_files_removed_retries(self):
        self.installed()
        self.fx.flag('userdel')
        self.refused(self.fx.run('main --uninstall'))
        self.assertFalse(self.fx.unit.exists())
        self.assertFalse(self.fx.etc.exists())
        self.assertEqual(self.fx.phase(), 'uninstalling')
        self.fx.unflag('userdel')
        self.fx.clear()
        self.ok(self.fx.run('main --uninstall'))
        self.assertNotIn('systemctl stop', self.fx.trace())

    def test_implicit_private_group_deletion_is_journaled(self):
        self.installed()
        self.fx.flag('implicit-group-delete')
        self.ok(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.phase(), 'uninstalled')

    def test_groupdel_failure_retries(self):
        self.installed()
        self.fx.flag('groupdel')
        self.refused(self.fx.run('main --uninstall'))
        self.fx.unflag('groupdel')
        self.ok(self.fx.run('main --uninstall'))

    def test_unlink_failure_retries(self):
        self.installed()
        self.fx.flag('rm')
        self.refused(self.fx.run('main --uninstall'))
        self.assertTrue(self.fx.link.is_symlink())
        self.fx.unflag('rm')
        self.ok(self.fx.run('main --uninstall'))

    def test_removed_path_replacement_is_preserved(self):
        self.installed()
        self.fx.flag('userdel')
        self.refused(self.fx.run('main --uninstall'))
        self.fx.unit.write_text('foreign same path')
        self.fx.clear()
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.unit.read_text(), 'foreign same path')
        self.assertEqual(self.fx.trace(), '')

    def test_journal_failure_stops_before_managed_effect(self):
        self.installed()
        self.fx.flag('journal')
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.phase(), 'ready')
        self.assertNotIn('systemctl stop', self.fx.trace())

    def test_final_journal_failure_retries(self):
        self.installed()
        self.fx.flag('journal-final')
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.phase(), 'uninstalling')
        self.fx.unflag('journal-final')
        self.ok(self.fx.run('main --uninstall'))

    def test_print_link_legacy_no_state_bootstrap_no_network(self):
        self.fx.etc.mkdir()
        (self.fx.etc / 'config.toml').write_text(f'secret = "{SECRET}"\npublic-ipv4 = "192.0.2.40"\nbind-to = "0.0.0.0:8444"\n')
        (self.fx.etc / 'state').write_text('port=8444\n')
        result = self.fx.run('main --print-link')
        self.ok(result)
        self.assertEqual(result.stdout.strip(), f'tg://proxy?server=192.0.2.40&port=8444&secret={SECRET}')
        self.assertFalse(self.fx.receipt.parent.exists())
        self.assertEqual(self.fx.trace(), '')
        (self.fx.etc / 'config.toml').write_text(f'secret = "{SECRET}"\n')
        result = self.fx.run('main --print-link', before='MTG_PUBLIC_IP=')
        self.refused(result)
        self.assertEqual(self.fx.trace(), '')

    def test_bad_argument_has_no_effects(self):
        self.refused(self.fx.run('main --unexpected'))
        self.assertEqual(self.fx.trace(), '')


    def test_dependency_attempt_is_journaled_and_revalidated(self):
        missing = 'command() { if [ "$*" = "-v curl" ]; then return 1; else builtin command "$@"; fi; }'
        self.fx.flag('apt-collision')
        self.refused(self.fx.run(before=missing))
        self.assertEqual(self.fx.phase(), 'install-pending')
        self.assertEqual(self.fx.receipt.read_text().splitlines()[3], '1')
        self.assertIn('apt-get', self.fx.trace())
        self.assertNotIn('useradd', self.fx.trace())
        self.assertIn('foreign unit', self.fx.unit.read_text())

    def test_missing_safety_tool_never_bootstraps_apt(self):
        missing = 'command() { if [ "$*" = "-v flock" ]; then return 1; else builtin command "$@"; fi; }'
        self.refused(self.fx.run(before=missing))
        self.assertEqual(self.fx.trace(), '')

    def test_real_hardlink_same_content_replacement_and_mode_drift(self):
        self.installed()
        path = self.fx.etc / 'port'
        old = path.read_bytes()
        saved = self.fx.root / 'old-port'
        path.rename(saved)
        path.write_bytes(old)
        os.chmod(path, 0o640)
        self.refused(self.fx.run())
        self.assertEqual(self.fx.trace(), '')
        path.unlink()
        saved.rename(path)
        os.link(path, saved)
        self.refused(self.fx.run())
        self.assertEqual(self.fx.trace(), '')
        saved.unlink()
        os.chmod(path, 0o666)
        self.refused(self.fx.run())
        self.assertEqual(self.fx.trace(), '')

    def test_group_members_gid_drift_and_duplicate_uid(self):
        self.installed()
        original = self.fx.group.read_text()
        for changed in (original.replace('42002:', '42003:'), original.replace('42002:', '42002:foreign')):
            self.fx.group.write_text(changed)
            self.refused(self.fx.run('main --uninstall'))
            self.assertEqual(self.fx.trace(), '')
        self.fx.group.write_text(original)
        with self.fx.passwd.open('a') as stream: stream.write('foreign:x:42001:41990:foreign:/foreign:/bin/false\n')
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.trace(), '')

    def test_inherited_dropins_and_vendor_unit_files(self):
        for name in ('service.d', 'xio-.service.d', 'xio-mtproto.service.d'):
            path = self.fx.unit.parent / name
            path.mkdir()
            self.refused(self.fx.run())
            self.assertEqual(self.fx.trace(), '')
            path.rmdir()
        vendor = self.fx.root / 'usr/lib/systemd/system/xio-mtproto.service'
        vendor.parent.mkdir(parents=True)
        vendor.write_text('foreign vendor')
        self.refused(self.fx.run())
        self.assertEqual(self.fx.trace(), '')

    def test_control_receipt_corruption_and_substitution(self):
        self.installed()
        original = self.fx.receipt.read_text()
        for corrupted in (original+'extra\n', original.replace('ready\n', 'unknown\n', 1),
                          original.replace('group|owned|42002', 'group|owned|$(touch /forbidden)'),
                          original.replace('group|owned|42002', 'group|owned|42002|'),
                          original.replace('user|owned|', 'group|owned|')):
            self.fx.receipt.write_text(corrupted)
            self.refused(self.fx.run())
            self.assertEqual(self.fx.trace(), '')
        self.fx.receipt.write_text(original)
        original_path = self.fx.root / 'receipt-saved'
        self.fx.receipt.rename(original_path)
        self.fx.receipt.symlink_to(original_path)
        self.refused(self.fx.run())
        self.assertEqual(self.fx.trace(), '')

    def test_uninstall_reload_and_rmdir_failures_retry(self):
        self.installed()
        self.fx.flag('daemon-reload')
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.phase(), 'uninstalling')
        self.fx.unflag('daemon-reload')
        self.fx.flag('rmdir')
        self.refused(self.fx.run('main --uninstall'))
        self.assertIn('xio-mtproto:', self.fx.passwd.read_text())
        self.fx.unflag('rmdir')
        self.ok(self.fx.run('main --uninstall'))

    def test_crash_after_unlink_accepts_only_journaled_absence(self):
        self.installed()
        self.fx.flag('after-rm')
        self.refused(self.fx.run('main --uninstall'))
        self.assertFalse(self.fx.link.is_symlink())
        self.assertIn('link|intent|', self.fx.receipt.read_text())
        self.fx.unflag('after-rm')
        self.ok(self.fx.run('main --uninstall'))

    def test_pending_unlink_foreign_replacement_is_not_adopted(self):
        self.installed()
        self.fx.flag('after-rm')
        self.refused(self.fx.run('main --uninstall'))
        self.fx.link.symlink_to(self.fx.unit)  # same target is NOT the old link identity
        self.fx.unflag('after-rm')
        self.fx.clear()
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.trace(), '')
        self.assertTrue(self.fx.link.is_symlink())

    def test_crash_after_userdel_with_numeric_reuse_refuses(self):
        self.installed()
        self.fx.flag('after-userdel')
        self.refused(self.fx.run('main --uninstall'))
        with self.fx.passwd.open('a') as stream: stream.write('foreign:x:42001:41990:foreign:/foreign:/bin/false\n')
        self.fx.clear()
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.trace(), '')

    def test_recreated_same_account_fields_different_marker_refuses_retry(self):
        self.installed()
        account = self.fx.passwd.read_text()
        self.fx.flag('after-userdel')
        self.refused(self.fx.run('main --uninstall'))
        self.fx.passwd.write_text(account.replace('xio-mtproto-', 'recreated-'))
        self.fx.clear()
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.trace(), '')

    def test_tombstone_foreign_resource_blocks_fresh_install(self):
        self.installed()
        self.ok(self.fx.run('main --uninstall'))
        self.fx.unit.write_text('foreign replacement')
        self.fx.clear()
        self.refused(self.fx.run())
        self.assertEqual(self.fx.trace(), '')
        self.assertEqual(self.fx.unit.read_text(), 'foreign replacement')

    def test_print_link_unsafe_path_and_missing_state(self):
        self.fx.etc.mkdir()
        config = self.fx.etc / 'config.toml'
        config.write_text(f'secret = "{SECRET}"\npublic-ipv4 = "192.0.2.40"\nbind-to = "0.0.0.0:8444"\n')
        self.ok(self.fx.run('main --print-link'))
        saved = self.fx.root / 'config-saved'
        config.rename(saved)
        config.symlink_to(saved)
        self.refused(self.fx.run('main --print-link'))
        self.assertEqual(self.fx.trace(), '')

    def test_all_install_journal_publication_interruptions_are_conservative(self):
        # Enumerate actual publication count, then fault before/after each one.
        self.installed()
        total = int((self.fx.root / 'journal-count').read_text())
        for direction in ('before', 'after'):
            for position in range(1, total+1):
                with self.subTest(direction=direction, position=position):
                    fx = Fixture()
                    try:
                        (fx.root / 'journal-stop-at').write_text(str(position)+'\n')
                        fx.flag(direction+'-journal')
                        self.refused(fx.run())
                        fx.unflag(direction+'-journal')
                        fx.clear()
                        if fx.receipt.exists() and fx.phase() == 'ready':
                            self.ok(fx.run())  # final ready publication was committed
                        else:
                            self.refused(fx.run())
                            self.assertEqual(fx.trace(), '')
                    finally:
                        fx.cleanup()

    def test_cooperating_waiters_keep_stable_lock_across_uninstall(self):
        import fcntl
        self.installed()
        lock = self.fx.receipt.with_name('lock')
        inode = lock.stat().st_ino
        with lock.open('rb') as descriptor:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            processes = []
            try:
                for index, action in enumerate(('main --uninstall', 'main --install')):
                    script = self.fx.root / f'concurrent-{index}.sh'
                    script.write_text(self.fx.header+'\n'+action+'\n')
                    processes.append(subprocess.Popen(['/bin/bash', str(script)], env=self.fx.env,
                                                      cwd=self.fx.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
                for process in processes:
                    with self.assertRaises(subprocess.TimeoutExpired):
                        process.communicate(timeout=0.15)
                self.assertEqual(self.fx.trace(), '')
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                for process in processes:
                    output, error = process.communicate(timeout=45)
                    self.assertEqual(process.returncode, 0, error[-1200:])
                self.assertEqual(lock.stat().st_ino, inode)
            finally:
                for process in processes:
                    if process.poll() is None: process.kill()
                    process.communicate()


    def test_foreign_supplementary_group_refuses_user_deletion(self):
        self.installed()
        with self.fx.group.open('a') as stream:
            stream.write('foreign:x:42009:xio-mtproto\n')
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.trace(), '')

    def test_unknown_entry_appearing_during_rmdir_is_preserved(self):
        self.installed()
        self.fx.flag('rmdir-add-entry')
        self.refused(self.fx.run('main --uninstall'))
        self.assertTrue((self.fx.lib / 'foreign').exists())
        self.assertIn('xio-mtproto:', self.fx.passwd.read_text())
        self.assertEqual(self.fx.phase(), 'uninstalling')
        self.fx.clear()
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.trace(), '')

    def test_all_update_journal_interruptions_preserve_pending_evidence(self):
        self.installed()
        start = int((self.fx.root / 'journal-count').read_text())
        self.ok(self.fx.run(before='MTG_VERSION=2.4.0; MTG_DOMAIN=changed.example.org; MTG_PORT=8445; MTG_PUBLIC_IP=192.0.2.41'))
        total = int((self.fx.root / 'journal-count').read_text()) - start
        for direction in ('before', 'after'):
            for position in range(1, total+1):
                with self.subTest(direction=direction, position=position):
                    fx = Fixture()
                    try:
                        self.ok(fx.run())
                        start = int((fx.root / 'journal-count').read_text())
                        (fx.root / 'journal-stop-at').write_text(str(start+position)+'\n')
                        fx.flag(direction+'-journal')
                        self.refused(fx.run(before='MTG_VERSION=2.4.0; MTG_DOMAIN=changed.example.org; MTG_PORT=8445; MTG_PUBLIC_IP=192.0.2.41'))
                        fx.unflag(direction+'-journal')
                        fx.clear()
                        if fx.phase() == 'ready':
                            # Before first or after final atomic publication.
                            self.ok(fx.run())
                        else:
                            self.assertEqual(fx.phase(), 'update-pending')
                            self.refused(fx.run())
                            self.refused(fx.run('main --uninstall'))
                            self.assertEqual(fx.trace(), '')
                    finally:
                        fx.cleanup()


    def test_reboot_after_stop_done_revalidates_current_quiescence(self):
        self.installed()
        self.fx.flag('after-stop-done')
        self.refused(self.fx.run('main --uninstall'))
        self.assertEqual(self.fx.receipt.read_text().splitlines()[4], 'done')
        self.assertTrue(self.fx.link.is_symlink())
        self.assertTrue(self.fx.unit.exists())
        self.fx.unflag('after-stop-done')
        # Ordinary reboot restarts the still-enabled exact owned unit.
        (self.fx.root / 'active-state').write_text('active\n')
        self.fx.clear()
        self.ok(self.fx.run('main --uninstall'))
        trace = self.fx.trace()
        self.assertIn('systemctl stop xio-mtproto.service', trace)
        self.assertLess(trace.index('systemctl stop'), trace.index('rm fixture'))
        self.assertEqual((self.fx.root / 'active-state').read_text(), 'inactive\n')

    def test_active_service_without_remaining_unit_proof_refuses_cleanup(self):
        self.installed()
        self.fx.flag('userdel')
        self.refused(self.fx.run('main --uninstall'))
        self.assertFalse(self.fx.unit.exists())
        self.fx.unflag('userdel')
        (self.fx.root / 'active-state').write_text('active\n')
        (self.fx.root / 'unit-overrides').write_text(f'load=loaded\nfragment={self.fx.unit}\nstate=disabled\n')
        self.fx.clear()
        self.refused(self.fx.run('main --uninstall'))
        self.assertIn('xio-mtproto:', self.fx.passwd.read_text())
        self.assertEqual(self.fx.trace(), '')


    def test_vendor_alias_to_future_unit_refuses_before_effects(self):
        for relative in (False, True):
            with self.subTest(relative=relative):
                fx = Fixture()
                self.addCleanup(fx.cleanup)
                vendor = fx.root / 'usr/lib/systemd/system'
                vendor.mkdir(parents=True)
                alias = vendor / 'foreign-alias.service'
                target = os.path.relpath(fx.unit, vendor) if relative else str(fx.unit)
                alias.symlink_to(target)
                self.refused(fx.run())
                self.assertEqual(fx.trace(), '')
                self.assertTrue(alias.is_symlink())


    def test_reactivated_retry_stop_failure_preserves_payload(self):
        self.installed()
        self.fx.flag('after-stop-done')
        self.refused(self.fx.run('main --uninstall'))
        self.fx.unflag('after-stop-done')
        (self.fx.root / 'active-state').write_text('active\n')
        self.fx.flag('stop')
        self.fx.clear()
        self.refused(self.fx.run('main --uninstall'))
        self.assertIn('systemctl stop', self.fx.trace())
        self.assertNotIn('rm fixture', self.fx.trace())
        self.assertNotIn('userdel', self.fx.trace())
        self.assertTrue(self.fx.unit.exists())
        self.assertTrue((self.fx.lib / 'mtg').exists())
        self.fx.unflag('stop')
        self.ok(self.fx.run('main --uninstall'))


    def test_vendor_scan_deduplicates_roots_without_following_child_directories(self):
        vendor = self.fx.root / 'usr/lib/systemd/system'
        vendor.mkdir(parents=True)
        alternate = self.fx.root / 'vendor-alias'
        alternate.symlink_to(vendor, target_is_directory=True)
        other = self.fx.root / 'not-a-vendor-root'
        other.mkdir()
        (other / 'foreign.service').symlink_to(self.fx.unit)
        (vendor / 'nested-directory-link').symlink_to(other, target_is_directory=True)
        before = 'UNIT_VENDOR_DIRS=("$FX/usr/lib/systemd/system" "$FX/vendor-alias"); find() { printf "%s\\n" "$@" >> "$FX/find-args"; /usr/bin/find "$@"; }'
        self.ok(self.fx.run('owner_paths; owner_fresh_check', before=before))
        self.assertEqual((self.fx.root / 'find-args').read_text().splitlines().count(str(vendor)), 1)
        self.assertEqual(self.fx.trace(), '')

    def test_unreadable_unit_link_scan_refuses_without_effects(self):
        self.refused(self.fx.run(before='find() { return 7; }'))
        self.assertEqual(self.fx.trace(), '')


if __name__ == '__main__':
    print('source_sha256=' + hashlib.sha256(SOURCE.read_bytes()).hexdigest(), flush=True)
    unittest.main(verbosity=2)
