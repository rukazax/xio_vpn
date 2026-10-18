import 'dart:convert';

import 'package:crypto/crypto.dart';

const legalRevision = '2026-10-18';
const vpnDisclosureRevision = '2026-10-18';

class LegalRecord {
  final String revision, timestamp, textSha256, language;
  const LegalRecord(
    this.revision,
    this.timestamp,
    this.textSha256,
    this.language,
  );
  bool get current =>
      revision == legalRevision &&
      DateTime.tryParse(timestamp)?.isUtc == true &&
      RegExp(r'^[a-f0-9]{64}$').hasMatch(textSha256);
  factory LegalRecord.acknowledge(String text, String language) => LegalRecord(
    legalRevision,
    DateTime.now().toUtc().toIso8601String(),
    sha256.convert(utf8.encode(text)).toString(),
    language,
  );
  Map<String, String> toJson() => {
    'revision': revision,
    'timestamp': timestamp,
    'textSha256': textSha256,
    'language': language,
  };
  static LegalRecord? parse(dynamic value) {
    if (value is! Map) return null;
    final fields = ['revision', 'timestamp', 'textSha256', 'language'];
    if (fields.any((k) => value[k] is! String)) return null;
    final record = LegalRecord(
      value['revision'],
      value['timestamp'],
      value['textSha256'],
      value['language'],
    );
    return record.current ? record : null;
  }
}
