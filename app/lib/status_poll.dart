/// Coalesces periodic reads; connection checks can explicitly require a new read
/// after any older read has finished, so they cannot consume a prior tunnel's state.
class StatusPoll {
  Future<void>? _pending;
  Future<void> run(Future<void> Function() read, {bool fresh = false}) async {
    while (_pending != null) {
      await _pending;
      if (!fresh) return;
    }
    final task = Future<void>.sync(read);
    _pending = task;
    try {
      await task;
    } finally {
      if (identical(_pending, task)) _pending = null;
    }
  }
}
