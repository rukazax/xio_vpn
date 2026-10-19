import Flutter
import UIKit
import NetworkExtension
import UniformTypeIdentifiers

final class XIOEngine: NSObject, UIDocumentPickerDelegate {
  private var manager: NETunnelProviderManager?
  private var busy = false
  private var pickerResult: FlutterResult?
  private var timer: Timer?
  private let revision = "2026-10-18"
  private func error(_ message: String, code: String = "ENGINE") -> FlutterError { FlutterError(code: code, message: message, details: nil) }
  private var shared: UserDefaults? { UserDefaults(suiteName: XIOKeychain.sharedSuite) }
  private func manager(_ callback: @escaping (NETunnelProviderManager?, Error?) -> Void) {
    NETunnelProviderManager.loadAllFromPreferences { managers, error in
      let existing = managers?.first { ($0.protocolConfiguration as? NETunnelProviderProtocol)?.providerBundleIdentifier == "app.xio.client.PacketTunnel" }
      self.manager = existing; callback(existing, error)
    }
  }
  func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    let args = call.arguments as? [String: Any] ?? [:]
    do {
      switch call.method {
      case "dataDirectory":
        let dir = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        result(dir.path)
      case "supportedProtocols": result(["rivet-h3", "rivet-s1"])
      case "setConsent": shared?.set(args["revision"] as? String ?? "", forKey: "consentRevision"); result(nil)
      case "setLanguage", "secureScreen": result(nil)
      case "connectionBusy": result(busy)
      case "saveConfig", "credentialWrite":
        guard let id = args["id"] as? String,
              let value = args[call.method == "saveConfig" ? "config" : "value"] as? String, value.utf8.count <= 200000 else { result(error("Invalid client data.")); return }
        try XIOKeychain.write(id, value: value, profile: call.method == "saveConfig"); result(nil)
      case "readConfig", "credentialRead":
        guard let id = args["id"] as? String else { result(error("Invalid identifier.")); return }
        result(try XIOKeychain.read(id, profile: call.method == "readConfig"))
      case "deleteConfig", "credentialDelete":
        guard let id = args["id"] as? String else { result(error("Invalid identifier.")); return }
        try XIOKeychain.delete(id, profile: call.method == "deleteConfig"); result(nil)
      case "activeId": manager { m, _ in
        if let m = m, [.connected, .reasserting].contains(m.connection.status) {
          result((m.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["profileID"])
        } else { result(nil) }
      }
      case "status": status(result)
      case "connect":
        guard shared?.string(forKey: "consentRevision") == revision else { result(error("Complete both disclosure screens.", code: "DENIED")); return }
        guard !busy, let id = args["id"] as? String,
              let raw = try XIOKeychain.read(id, profile: true),
              let j = try JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
              let proto = j["protocol"] as? String, ["rivet-h3", "rivet-s1"].contains(proto) else { result(error("This iOS build supports RIVET/H3 and RIVET/S1.")); return }
        let timeout = (args["timeoutMillis"] as? NSNumber)?.int64Value ?? 15000
        guard timeout >= 5000 && timeout <= 60000 else { result(error("Invalid connection timeout.")); return }
        connect(id: id, timeout: timeout, result: result)
      case "disconnect": timer?.invalidate(); timer = nil; manager { m, _ in m?.connection.stopVPNTunnel(); result(nil) }
      case "consumeConnectRequest": result(false)
      case "routingSummary": result(["enabled": false, "supported": false])
      case "pickBundle":
        guard pickerResult == nil else { result(error("File picker is busy.")); return }
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.data, .plainText], asCopy: true)
        picker.delegate = self; picker.allowsMultipleSelection = false; pickerResult = result
        guard let controller = topController() else { pickerResult = nil; result(error("No active window.")); return }; controller.present(picker, animated: true)
      case "shareBundle", "shareApplication":
        guard let raw = (args["bundle"] ?? args["text"]) as? String, let controller = topController() else { result(error("Nothing to share.")); return }
        let sheet = UIActivityViewController(activityItems: [raw], applicationActivities: nil)
        if let pop = sheet.popoverPresentationController { pop.sourceView = controller.view; pop.sourceRect = CGRect(x: controller.view.bounds.midX, y: controller.view.bounds.midY, width: 1, height: 1) }
        controller.present(sheet, animated: true); result(nil)
      case "openExternalLink":
        guard let raw = args["url"] as? String, let url = URL(string: raw), url.scheme == "https", url.user == nil else { result(error("Invalid URL.")); return }
        UIApplication.shared.open(url, options: [:]); result(nil)
      case "openSupportLink":
        UIApplication.shared.open(URL(string: "https://x1o.org/pay")!, options: [:]); result(nil)
      default: result(FlutterMethodNotImplemented)
      }
    } catch { result(self.error("Secure storage or client configuration is unavailable.")) }
  }
  private func connect(id: String, timeout: Int64, result: @escaping FlutterResult) {
    busy = true
    manager { existing, loadError in
      if loadError != nil { self.busy = false; result(self.error("Could not load VPN preferences.")); return }
      let m = existing ?? NETunnelProviderManager(); let p = NETunnelProviderProtocol()
      p.providerBundleIdentifier = "app.xio.client.PacketTunnel"; p.serverAddress = "XIO"
      p.providerConfiguration = ["profileID": id, "timeoutMillis": NSNumber(value: timeout)]
      p.includeAllNetworks = true; p.excludeLocalNetworks = false
      m.protocolConfiguration = p; m.localizedDescription = "XIO"; m.isEnabled = true
      m.saveToPreferences { saveError in
        guard saveError == nil else { self.busy = false; result(self.error("System VPN permission was not granted.", code: "DENIED")); return }
        // The connection budget starts after the interactive system permission.
        m.loadFromPreferences { reloadError in
          guard reloadError == nil else { self.busy = false; result(self.error("Could not reload VPN preferences.")); return }
          self.manager = m; let started = Date()
          do { try m.connection.startVPNTunnel() } catch { self.busy = false; result(self.error("iOS could not start the VPN extension.")); return }
          DispatchQueue.main.async {
            self.timer = Timer.scheduledTimer(withTimeInterval: 0.15, repeats: true) { timer in
              if m.connection.status == .connected {
                timer.invalidate(); self.timer = nil; self.busy = false
                result(["connectMillis": Int(Date().timeIntervalSince(started) * 1000)]); return
              }
              if Date().timeIntervalSince(started) * 1000 >= Double(timeout) || (Date().timeIntervalSince(started) > 1 && [.invalid, .disconnected].contains(m.connection.status)) {
                timer.invalidate(); self.timer = nil; self.busy = false; m.connection.stopVPNTunnel()
                result(self.error("The verified VPN connection did not start within its time budget."))
              }
            }
          }
        }
      }
    }
  }
  private func status(_ result: @escaping FlutterResult) {
    manager { m, _ in
      guard let m = m, [.connected, .reasserting].contains(m.connection.status), let session = m.connection as? NETunnelProviderSession else { result(["active": false]); return }
      var completed = false
      let fallback = DispatchWorkItem { if !completed { completed = true; result(["active": false, "phase": "unavailable"]) } }
      DispatchQueue.main.asyncAfter(deadline: .now() + 2, execute: fallback)
      do {
        try session.sendProviderMessage(Data("status".utf8)) { data in
          DispatchQueue.main.async {
            guard !completed else { return }; completed = true; fallback.cancel()
            if let data = data, let j = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] { result(j) }
            else { result(["active": false]) }
          }
        }
      } catch { if !completed { completed = true; fallback.cancel(); result(["active": false]) } }
    }
  }
  private func topController() -> UIViewController? {
    var vc = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.flatMap { $0.windows }.first(where: { $0.isKeyWindow })?.rootViewController
    while let presented = vc?.presentedViewController { vc = presented }; return vc
  }
  func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
    let callback = pickerResult; pickerResult = nil
    guard let url = urls.first else { callback?(nil); return }; let scoped = url.startAccessingSecurityScopedResource(); defer { if scoped { url.stopAccessingSecurityScopedResource() } }
    guard let info = try? url.resourceValues(forKeys: [.fileSizeKey]), (info.fileSize ?? 200001) <= 200000,
          let data = try? Data(contentsOf: url), let text = String(data: data, encoding: .utf8) else { callback?(error("Profile file is too large or invalid.")); return }; callback?(text)
  }
  func documentPickerWasCancelled(_ controller: UIDocumentPickerViewController) { let callback = pickerResult; pickerResult = nil; callback?(nil) }
}
