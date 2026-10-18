import 'dart:io';

import 'package:flutter/services.dart';

import 'desktop_engine.dart';

class EngineChannel extends MethodChannel {
  const EngineChannel() : super('app.x1o/engine');
  @override
  Future<T?> invokeMethod<T>(String method, [dynamic arguments]) async {
    if (DesktopEngine.enabled && (Platform.isLinux || Platform.isWindows)) {
      return await DesktopEngine.invoke(method, arguments) as T?;
    }
    return super.invokeMethod<T>(method, arguments);
  }
}
