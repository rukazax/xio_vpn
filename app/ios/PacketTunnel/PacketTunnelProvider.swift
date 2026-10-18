import Foundation
import Network
import NetworkExtension
import Darwin

final class PacketTunnelProvider: NEPacketTunnelProvider, XIOPacketSink, XIOPhysicalSockets {
  private let worker = DispatchQueue(label: "app.xio.rivet", qos: .userInitiated)
  private let lock = NSLock()
  private var running = false
  private var cancelled = false
  private var dnsCache: [String: String] = [:]
  private var interfaceIndex: UInt32 = 0
  private var monitor: NWPathMonitor?
  private var profileID = ""
  private func isRunning() -> Bool { lock.lock(); defer { lock.unlock() }; return running }
  private func checkCancellation() throws { lock.lock(); let value = cancelled; lock.unlock(); if value { throw failure("VPN start cancelled.") } }
  private func beginPackets() -> Bool { lock.lock(); defer { lock.unlock() }; if cancelled { return false }; running = true; return true }
  private func failure(_ message: String) -> NSError { NSError(domain: "XIO", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }

  override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
    guard UserDefaults(suiteName: XIOKeychain.sharedSuite)?.string(forKey: "consentRevision") == "2026-10-18",
          let configuration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
          let id = configuration["profileID"] as? String else {
      completionHandler(failure("Open XIO and complete both disclosure screens.")); return
    }
    lock.lock(); cancelled = false; dnsCache = [:]; lock.unlock()
    profileID = id
    worker.async {
      do {
        guard let raw = try XIOKeychain.read(id, profile: true),
              let object = try JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
              let ip = object["ip"] as? String,
              let proto = object["protocol"] as? String,
              ["rivet-h3", "rivet-s1"].contains(proto) else { throw self.failure("No supported RIVET profile.") }
        let ready = DispatchSemaphore(value: 0)
        let monitor = NWPathMonitor(); self.monitor = monitor
        monitor.pathUpdateHandler = { [weak self] path in
          guard let self = self else { return }
          if let physical = path.availableInterfaces.first(where: {
            path.usesInterfaceType($0.type) && ($0.type == .wifi || $0.type == .cellular || $0.type == .wiredEthernet)
          }) {
            self.lock.lock(); self.interfaceIndex = UInt32(physical.index); self.lock.unlock(); ready.signal()
          }
        }
        monitor.start(queue: DispatchQueue(label: "app.xio.physical-path"))
        guard ready.wait(timeout: .now() + 5) == .success else { throw self.failure("No physical network is available.") }
        try self.checkCancellation()
        let timeout = (configuration["timeoutMillis"] as? NSNumber)?.int64Value ?? 15000
        _ = try XIORivetBridge.start(raw, protector: self, sink: self, timeout: timeout)
        try self.checkCancellation()
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.79.0.1")
        let ipv4 = NEIPv4Settings(addresses: [ip], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route.default()]; settings.ipv4Settings = ipv4
        // The RIVET v1 payload is IPv4. Capture and discard IPv6 instead of
        // letting IPv6 applications escape outside the selected VPN.
        let ipv6 = NEIPv6Settings(addresses: ["fd79:7869:6f::2"], networkPrefixLengths: [128])
        ipv6.includedRoutes = [NEIPv6Route.default()]; settings.ipv6Settings = ipv6
        settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1"]); settings.mtu = 1280
        self.setTunnelNetworkSettings(settings) { error in
          if let error = error { XIORivetBridge.stop(); self.monitor?.cancel(); completionHandler(error); return }
          guard self.beginPackets() else { XIORivetBridge.stop(); completionHandler(self.failure("VPN start cancelled.")); return }
          self.readPackets(); completionHandler(nil)
        }
      } catch {
        XIORivetBridge.stop(); self.monitor?.cancel(); completionHandler(self.failure("RIVET could not establish a verified VPN connection."))
      }
    }
  }
  private func readPackets() {
    guard isRunning() else { return }
    packetFlow.readPackets { [weak self] packets, protocols in
      guard let self = self, self.isRunning() else { return }
      for (index, packet) in packets.enumerated() where protocols[index].int32Value == AF_INET { _ = XIORivetBridge.input(packet) }
      self.readPackets()
    }
  }
  func writePacket(_ packet: Data) -> Bool {
    // The peer may send packets before routing is ready; drop them until start
    // has completed rather than writing to a detached packetFlow.
    guard isRunning() else { return true }
    return packetFlow.writePackets([packet], withProtocols: [NSNumber(value: AF_INET)])
  }
  func protect(_ socket: Int64) -> Bool {
    guard socket >= 0 && socket <= Int64(Int32.max) else { return false }
    lock.lock(); var index = interfaceIndex; let stopped = cancelled; lock.unlock(); guard index != 0 && !stopped else { return false }
    var address = sockaddr_storage(); var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
    let rc = withUnsafeMutablePointer(to: &address) { ptr in ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(Int32(socket), $0, &length) } }
    guard rc == 0 else { return false }
    if address.ss_family == sa_family_t(AF_INET6) {
      return setsockopt(Int32(socket), IPPROTO_IPV6, IPV6_BOUND_IF, &index, socklen_t(MemoryLayout<UInt32>.size)) == 0
    }
    return setsockopt(Int32(socket), IPPROTO_IP, IP_BOUND_IF, &index, socklen_t(MemoryLayout<UInt32>.size)) == 0
  }
  func resolve(_ host: String) -> String {
    lock.lock(); let cached = dnsCache[host]; lock.unlock(); if let cached = cached { return cached }
    var hints = addrinfo(); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM
    var result: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, nil, &hints, &result) == 0, let first = result else { return "" }
    defer { freeaddrinfo(result) }
    var text = [CChar](repeating: 0, count: Int(NI_MAXHOST))
    guard getnameinfo(first.pointee.ai_addr, first.pointee.ai_addrlen, &text, socklen_t(text.count), nil, 0, NI_NUMERICHOST) == 0 else { return "" }
    let value = String(cString: text); lock.lock(); dnsCache[host] = value; lock.unlock(); return value
  }
  override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
    lock.lock(); cancelled = true; running = false; lock.unlock(); monitor?.cancel(); XIORivetBridge.stop(); completionHandler()
  }
  override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
    guard messageData == Data("status".utf8), let data = XIORivetBridge.status().data(using: .utf8),
          var value = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { completionHandler?(nil); return }
    value["id"] = profileID; completionHandler?(try? JSONSerialization.data(withJSONObject: value))
  }
}
