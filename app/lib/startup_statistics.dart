import 'core.dart';
import 'credentials.dart';
import 'managed_service.dart';

/// One snapshot per application process, independent of page visits or resume.
class StartupStatistics {
  final Future<void> Function(AppStore, ManagedServer)? refreshServer;
  Future<void>? _pending;
  StartupStatistics({this.refreshServer});

  Future<void> run(AppStore store) => _pending ??= _run(store);
  Future<void> _run(AppStore store) async {
    if (!store.ready) return;
    for (final server in store.servers.toList()) {
      try {
        if (refreshServer != null) {
          await refreshServer!(store, server);
        } else {
          final saved = await CredentialVault.read(store.credentialId(server));
          if (saved == null) continue;
          final ssh = VpsService();
          try {
            await ssh.open(
              SshTarget(
                server.host,
                server.port,
                server.username,
                server.hostKey,
              ),
              saved['password'] ?? '',
              saved['key'] ?? '',
              saved['passphrase'] ?? '',
            );
            await ManagedService(ssh).refresh(store, server);
          } finally {
            await ssh.close();
          }
        }
      } catch (_) {
        // Retain the last successful snapshot when a server is unreachable.
        store.log('Не удалось обновить статистику пользователей');
      }
    }
  }
}
