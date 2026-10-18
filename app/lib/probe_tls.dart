import 'dart:io';

import 'package:flutter/services.dart';

/// Preserve platform trust and hostname verification, adding four current public
/// roots missing on legacy Android. No per-request permissive callback is used.
class ProbeTls {
  static Future<SecurityContext>? _context;
  static Future<SecurityContext> get context => _context ??= _load();
  static Future<SecurityContext> _load() async {
    final context = SecurityContext(withTrustedRoots: true);
    final pem = await rootBundle.load('assets/security/probe-roots.pem');
    context.setTrustedCertificatesBytes(
      pem.buffer.asUint8List(pem.offsetInBytes, pem.lengthInBytes),
    );
    return context;
  }
}
