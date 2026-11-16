import 'dart:convert';

import 'issuance_canonical.dart';
import 'issuance_material_scope.dart';

/// Strict internal partial-receipt codec. One canonical JSON document; raw
/// duplicate keys, trailing data, wrong types and depth/node/byte overflow are
/// rejected before the journal sees a map.
final class IssuancePartialReceipt {
  IssuancePartialReceipt._({
    required this.operationId,
    required this.uid,
    required this.deploymentId,
    required this.phase,
    required this.replay,
    required this.capsuleId,
    required this.ciphertextDigest,
    required this.envelopeSha256,
    required this.envelopeSize,
    required this.csrPresent,
    required this.csrSha256,
    required this.csrSpkiSha256,
    required this.csrCn,
    required this.backends,
    required this.materialRequested,
    required this.materialPurpose,
    required this.materialKinds,
    required this.fence,
    required this.updatedAt,
  });

  final String operationId;
  final String uid;
  final String deploymentId;
  final String phase;
  final bool replay;
  final String capsuleId;
  final String ciphertextDigest;
  final String envelopeSha256;
  final int envelopeSize;
  final bool csrPresent;
  final String csrSha256;
  final String csrSpkiSha256;
  final String csrCn;
  final Map<String, String> backends;
  final bool materialRequested;
  final String materialPurpose;
  final List<String> materialKinds;
  final String fence;
  final int updatedAt;

  static const _phases = {
    'prepared',
    'dispatchIntent',
    'remotePending',
    'remoteComplete',
    'localStaged',
    'localDurableNativeUnconfirmed',
    'committed',
  };
  static const _fences = {'none', 'awaiting', 'held', 'unknown', 'repairRequired'};
  static const _purposes = {
    'none',
    'remoteResume',
    'localStage',
    'localCommit',
    'localRestart',
  };
  static const _states = {'pending', 'appliedVerified', 'failed', 'blocked'};
  static const _hex32 = r'^[a-f0-9]{32}$';
  static const _hex64 = r'^[a-f0-9]{64}$';
  static const _printable = r'^[\x20-\x7e]{1,128}$';

  static IssuancePartialReceipt parse(String raw) {
    if (raw.isEmpty || utf8.encode(raw).length > issuancePartialMaxBytes) {
      throw const FormatException('Partial receipt size out of bounds');
    }
    final decoded = _StrictJson.parse(raw);
    if (decoded is! Map<String, Object?>) {
      throw const FormatException('Partial receipt is not an object');
    }
    if (canonicalJsonV1(decoded) != raw) {
      throw const FormatException('Partial receipt is not canonical');
    }
    const fields = {
      'schema',
      'operationId',
      'uid',
      'deploymentId',
      'phase',
      'replay',
      'capsuleRef',
      'csr',
      'backends',
      'materialRequest',
      'fence',
      'updatedAt',
    };
    if (decoded.length != fields.length ||
        !decoded.keys.every(fields.contains) ||
        decoded['schema'] != 1 ||
        decoded['schema'] is! int) {
      throw const FormatException('Invalid partial receipt fields');
    }
    if (!_isString(decoded['operationId'], _hex32) ||
        !_isString(decoded['uid'], _hex32) ||
        !_isString(decoded['deploymentId'], _printable) ||
        !_phases.contains(decoded['phase']) ||
        decoded['replay'] is! bool ||
        !_fences.contains(decoded['fence']) ||
        decoded['updatedAt'] is! int ||
        (decoded['updatedAt'] as int) < 0 ||
        (decoded['updatedAt'] as int) > issuanceRevisionMax) {
      throw const FormatException('Invalid partial receipt scalar');
    }
    final capsule = decoded['capsuleRef'];
    if (capsule is! Map<String, Object?> ||
        capsule.length != 4 ||
        !capsule.keys.every(const {'capsuleId', 'ciphertextDigest', 'envelopeSha256', 'size'}.contains) ||
        !_isString(capsule['capsuleId'], _hex32) ||
        !_isString(capsule['ciphertextDigest'], _hex64) ||
        !_isString(capsule['envelopeSha256'], _hex64) ||
        capsule['size'] is! int ||
        (capsule['size'] as int) < 1 ||
        (capsule['size'] as int) > issuanceEnvelopeMaxBytes) {
      throw const FormatException('Invalid partial capsuleRef');
    }
    final csr = decoded['csr'];
    if (csr is! Map<String, Object?> ||
        csr.length != 4 ||
        !csr.keys.every(const {'present', 'sha256', 'spkiSha256', 'cn'}.contains) ||
        csr['present'] is! bool ||
        csr['sha256'] is! String ||
        csr['spkiSha256'] is! String ||
        csr['cn'] is! String) {
      throw const FormatException('Invalid partial csr');
    }
    final present = csr['present'] as bool;
    final sha = csr['sha256'] as String;
    final spki = csr['spkiSha256'] as String;
    final cn = csr['cn'] as String;
    if (present) {
      if (!_matches(sha, _hex64) ||
          !_matches(spki, _hex64) ||
          !_matches(cn, _printable)) {
        throw const FormatException('Invalid present partial csr');
      }
    } else if (sha.isNotEmpty || spki.isNotEmpty || cn.isNotEmpty) {
      throw const FormatException('Absent partial csr must be empty');
    }
    final backendsValue = decoded['backends'];
    if (backendsValue is! Map<String, Object?> ||
        backendsValue.isEmpty ||
        backendsValue.length > issuancePartialBackends.length) {
      throw const FormatException('Invalid partial backends');
    }
    final backends = <String, String>{};
    for (final entry in backendsValue.entries) {
      if (!issuancePartialBackends.contains(entry.key) ||
          entry.value is! String ||
          !_states.contains(entry.value)) {
        throw const FormatException('Invalid partial backend state');
      }
      backends[entry.key] = entry.value as String;
    }
    final request = decoded['materialRequest'];
    if (request is! Map<String, Object?> ||
        request.length != 3 ||
        !request.keys.every(const {'requested', 'purpose', 'kinds'}.contains) ||
        request['requested'] is! bool ||
        request['purpose'] is! String ||
        request['kinds'] is! List) {
      throw const FormatException('Invalid partial materialRequest');
    }
    final requested = request['requested'] as bool;
    final purpose = request['purpose'] as String;
    final kindsRaw = request['kinds'] as List;
    if (!_purposes.contains(purpose) || kindsRaw.length > 8) {
      throw const FormatException('Invalid partial material request');
    }
    final kinds = <String>[];
    for (final kind in kindsRaw) {
      if (kind is! String ||
          !kind.isNotEmpty ||
          kinds.contains(kind)) {
        throw const FormatException('Invalid partial material kind');
      }
      kinds.add(kind);
    }
    final sortedKinds = [...kinds]..sort();
    for (var i = 0; i < kinds.length; i++) {
      if (kinds[i] != sortedKinds[i]) {
        throw const FormatException('Partial kinds must be sorted');
      }
    }
    if (!requested && (purpose != 'none' || kinds.isNotEmpty)) {
      throw const FormatException('Unrequested material must be empty');
    }
    if (requested && (purpose == 'none' || kinds.isEmpty)) {
      throw const FormatException('Requested material must name purpose/kinds');
    }
    return IssuancePartialReceipt._(
      operationId: decoded['operationId'] as String,
      uid: decoded['uid'] as String,
      deploymentId: decoded['deploymentId'] as String,
      phase: decoded['phase'] as String,
      replay: decoded['replay'] as bool,
      capsuleId: capsule['capsuleId'] as String,
      ciphertextDigest: capsule['ciphertextDigest'] as String,
      envelopeSha256: capsule['envelopeSha256'] as String,
      envelopeSize: capsule['size'] as int,
      csrPresent: present,
      csrSha256: sha,
      csrSpkiSha256: spki,
      csrCn: cn,
      backends: Map.unmodifiable(backends),
      materialRequested: requested,
      materialPurpose: purpose,
      materialKinds: List.unmodifiable(kinds),
      fence: decoded['fence'] as String,
      updatedAt: decoded['updatedAt'] as int,
    );
  }

  static bool _matches(String value, String pattern) =>
      RegExp(pattern).hasMatch(value);
  static bool _isString(Object? value, String pattern) =>
      value is String && _matches(value, pattern);
}

/// Minimal strict JSON reader: rejects duplicate object keys, EOF/trailing
/// bytes, non-integer numbers, null, wrong escapes and depth/node overflow.
final class _StrictJson {
  _StrictJson(this._text) : _length = _text.length;

  final String _text;
  final int _length;
  int _index = 0;
  int _nodes = 0;

  static Object? parse(String text) {
    final reader = _StrictJson(text);
    final value = reader._value(0);
    reader._skip();
    if (reader._index != reader._length) {
      throw const FormatException('Trailing JSON data');
    }
    return value;
  }

  void _skip() {
    while (_index < _length) {
      final unit = _text.codeUnitAt(_index);
      if (unit == 0x20 || unit == 0x0a || unit == 0x0d || unit == 0x09) {
        _index++;
      } else {
        break;
      }
    }
  }

  Never _bad() => throw const FormatException('Invalid JSON');

  Object? _value(int depth) {
    _skip();
    if (depth > issuancePartialMaxDepth) _bad();
    _nodes++;
    if (_nodes > issuancePartialMaxNodes) _bad();
    if (_index >= _length) _bad();
    final unit = _text.codeUnitAt(_index);
    if (unit == 0x7b) return _object(depth + 1);
    if (unit == 0x5b) return _array(depth + 1);
    if (unit == 0x22) return _string();
    if (unit == 0x74) return _literal('true', true);
    if (unit == 0x66) return _literal('false', false);
    if (unit == 0x6e) _bad(); // null is not allowed in the closed schema
    if (unit == 0x2d || (unit >= 0x30 && unit <= 0x39)) return _integer();
    _bad();
  }

  Object? _literal(String text, Object value) {
    if (!_text.startsWith(text, _index)) _bad();
    _index += text.length;
    return value;
  }

  int _integer() {
    final start = _index;
    if (_text.codeUnitAt(_index) == 0x2d) _index++;
    if (_index >= _length) _bad();
    if (_text.codeUnitAt(_index) == 0x30) {
      _index++;
    } else {
      if (_text.codeUnitAt(_index) < 0x31 || _text.codeUnitAt(_index) > 0x39) {
        _bad();
      }
      while (_index < _length &&
          _text.codeUnitAt(_index) >= 0x30 &&
          _text.codeUnitAt(_index) <= 0x39) {
        _index++;
      }
    }
    final value = int.tryParse(_text.substring(start, _index));
    if (value == null) _bad();
    return value;
  }

  String _string() {
    final start = _index;
    _index++; // opening quote
    while (_index < _length) {
      final unit = _text.codeUnitAt(_index);
      if (unit == 0x22) {
        _index++;
        final token = _text.substring(start, _index);
        final decoded = jsonDecode(token);
        if (decoded is! String) _bad();
        return decoded;
      }
      if (unit == 0x5c) {
        _index++;
        if (_index >= _length) _bad();
        final escape = _text.codeUnitAt(_index);
        if (escape == 0x75) {
          if (_index + 4 >= _length) _bad();
          for (var i = 1; i <= 4; i++) {
            final h = _text.codeUnitAt(_index + i);
            if (!((h >= 0x30 && h <= 0x39) ||
                (h >= 0x61 && h <= 0x66) ||
                (h >= 0x41 && h <= 0x46))) {
              _bad();
            }
          }
          _index += 4;
        } else if (!'"/\\bfnrt'.contains(String.fromCharCode(escape))) {
          _bad();
        }
        _index++;
        continue;
      }
      if (unit < 0x20) _bad();
      _index++;
    }
    _bad();
  }

  List<Object?> _array(int depth) {
    final list = <Object?>[];
    _index++; // [
    _skip();
    if (_index < _length && _text.codeUnitAt(_index) == 0x5d) {
      _index++;
      return list;
    }
    while (true) {
      list.add(_value(depth));
      _skip();
      if (_index >= _length) _bad();
      final unit = _text.codeUnitAt(_index);
      if (unit == 0x5d) {
        _index++;
        return list;
      }
      if (unit != 0x2c) _bad();
      _index++;
    }
  }

  Map<String, Object?> _object(int depth) {
    final map = <String, Object?>{};
    _index++; // {
    _skip();
    if (_index < _length && _text.codeUnitAt(_index) == 0x7d) {
      _index++;
      return map;
    }
    while (true) {
      _skip();
      if (_index >= _length || _text.codeUnitAt(_index) != 0x22) _bad();
      final key = _string();
      if (map.containsKey(key)) _bad();
      _skip();
      if (_index >= _length || _text.codeUnitAt(_index) != 0x3a) _bad();
      _index++;
      map[key] = _value(depth);
      _skip();
      if (_index >= _length) _bad();
      final unit = _text.codeUnitAt(_index);
      if (unit == 0x7d) {
        _index++;
        return map;
      }
      if (unit != 0x2c) _bad();
      _index++;
    }
  }
}
