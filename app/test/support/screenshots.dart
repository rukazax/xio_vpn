import 'dart:convert';
import 'dart:io';
import 'dart:ui' as ui;

import 'package:flutter/widgets.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';

/// Opt-in screenshot capture for documentation and verification evidence.
///
/// Several layout tests rendered a widget tree and also wrote PNG/JSON evidence
/// into `../verification` (git-ignored, absent in a fresh clone) and
/// `../docs/images` (tracked). That turned an environment detail into a test
/// failure and let a test run modify versioned files.
///
/// Writes are opt-in now: layouts are always rendered and asserted, but files
/// are only produced when `XIO_CAPTURE_IMAGES=1` is exported, e.g.
///
/// ```sh
/// XIO_CAPTURE_IMAGES=1 flutter test test/layout_test.dart
/// ```
///
/// The directory is created on demand, so a clean checkout works as well.
bool get screenshotsEnabled =>
    Platform.environment['XIO_CAPTURE_IMAGES'] == '1';

/// Writes a PNG/JSON/text evidence artifact when capture is enabled.
void writeArtifact(String path, List<int> bytes) {
  if (!screenshotsEnabled) return;
  final file = File(path);
  file.parent.createSync(recursive: true);
  file.writeAsBytesSync(bytes);
}

/// Writes a text evidence artifact when capture is enabled.
void writeTextArtifact(String path, String text) =>
    writeArtifact(path, utf8.encode(text));

/// Renders [key]'s repaint boundary to `path` when capture is enabled.
Future<void> captureScreenshot(
  WidgetTester tester,
  GlobalKey key,
  String path, {
  double pixelRatio = 1,
}) async {
  if (!screenshotsEnabled) return;
  final context = key.currentContext;
  if (context == null) throw StateError('Nothing to capture for $path');
  final boundary = context.findRenderObject() as RenderRepaintBoundary;
  await tester.runAsync(() async {
    final image = await boundary.toImage(pixelRatio: pixelRatio);
    try {
      final data = await image.toByteData(format: ui.ImageByteFormat.png);
      writeArtifact(path, data!.buffer.asUint8List());
    } finally {
      image.dispose();
    }
  });
}
