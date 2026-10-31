import Foundation
import Network
import NetworkExtension
import Darwin

// Pure policy shared by packetFlow input/output and isolated source fixtures.
// Keep the address binding identical to rivet.IPv6For, not a client-chosen ULA.
enum XIODualStackPolicy {
  private struct BackendCapabilities: Decodable { let ipv6Payload: Bool? }
  static func ipv6Address(for ipv4: String) -> String? {
    guard ipv4.hasPrefix("10.79.0."), let slot = UInt8(ipv4.dropFirst(8)),
          slot >= 2, slot <= 254, ipv4 == "10.79.0.\(slot)" else { return nil }
    return "fd79:1::" + String(slot, radix: 16)
  }
  static func backendSupportsIPv6(_ status: String?) -> Bool {
    guard let data = status?.data(using: .utf8),
          let value = try? JSONDecoder().decode(BackendCapabilities.self, from: data) else { return false }
    // Older Apple cores validate IPv4 only. A profile ip6 alone is not proof
    // that the linked backend supports IPv6 payloads. Missing means disabled.
    return value.ipv6Payload == true
  }
  static func endpointHost(_ endpoint: String) -> String? {
    let host: String; let port: String
    if endpoint.hasPrefix("["), let end = endpoint.firstIndex(of: "]") {
      let suffix = endpoint[endpoint.index(after: end)...]
      guard suffix.hasPrefix(":") else { return nil }
      host = String(endpoint[endpoint.index(after: endpoint.startIndex)..<end]); port = String(suffix.dropFirst())
    } else {
      let parts = endpoint.split(separator: ":", omittingEmptySubsequences: false)
      guard parts.count == 2 else { return nil }
      host = String(parts[0]); port = String(parts[1])
    }
    guard !host.isEmpty, let number = UInt16(port), number > 0 else { return nil }
    return host
  }
  static func orderedAddresses(_ addresses: [String]) -> [String] {
    var seen = Set<String>()
    let unique = addresses.filter { seen.insert($0).inserted }
    guard let first = unique.first else { return [] }
    let firstIPv6 = first.contains(":")
    let primary = unique.filter { $0.contains(":") == firstIPv6 }
    let secondary = unique.filter { $0.contains(":") != firstIPv6 }
    var ordered: [String] = []
    for index in 0..<max(primary.count, secondary.count) {
      if index < primary.count { ordered.append(primary[index]) }
      if index < secondary.count { ordered.append(secondary[index]) }
    }
    return Array(ordered.prefix(16))
  }
  static func attemptBudget(remainingMillis: Int64, candidatesLeft: Int) -> Int64 {
    guard remainingMillis >= 1000, candidatesLeft > 0 else { return 0 }
    return candidatesLeft == 1 ? remainingMillis : min(5000, max(1000, remainingMillis / 2))
  }
  static func packetVersion(_ packet: Data, ipv6Enabled: Bool) -> UInt8? {
    guard let first = packet.first, packet.count <= 1280 else { return nil }
    let start = packet.startIndex
    switch first >> 4 {
    case 4:
      guard packet.count >= 20, first == 0x45,
            Int(packet[start + 2]) * 256 + Int(packet[start + 3]) == packet.count else { return nil }
      return 4
    case 6:
      guard ipv6Enabled, packet.count >= 40,
            Int(packet[start + 4]) * 256 + Int(packet[start + 5]) + 40 == packet.count else { return nil }
      return 6
    default: return nil
    }
  }
}

final class PacketTunnelProvider: NEPacketTunnelProvider, XIOPacketSink, XIOPhysicalSockets {
  private let worker = DispatchQueue(label: "app.xio.rivet", qos: .userInitiated)
  private let resolver = DispatchQueue(label: "app.xio.physical-dns", qos: .userInitiated, attributes: .concurrent)
  private let lock = NSLock()
  private var running = false
  private var ipv6PayloadEnabled = false
  private var cancelled = false
  private var dnsCache: [String: [String]] = [:]
  private var dnsCursor: [String: Int] = [:]
  private var generation: UInt64 = 0
  private var interfaceIndex: UInt32 = 0
  private var monitor: NWPathMonitor?
  private var profileID = ""
  private func isRunning() -> Bool { lock.lock(); defer { lock.unlock() }; return running }
  private func isCurrent(_ request: UInt64) -> Bool { lock.lock(); defer { lock.unlock() }; return !cancelled && generation == request }
  private func checkCancellation(_ request: UInt64) throws { lock.lock(); let value = cancelled || generation != request; lock.unlock(); if value { throw failure("VPN start cancelled.") } }
  private func beginPackets(ipv6Enabled: Bool, generation request: UInt64) -> Bool { lock.lock(); defer { lock.unlock() }; if cancelled || generation != request { return false }; ipv6PayloadEnabled = ipv6Enabled; running = true; return true }
  private func packetFamily(_ packet: Data) -> Int32? {
    lock.lock(); let enabled = ipv6PayloadEnabled; lock.unlock()
    guard let version = XIODualStackPolicy.packetVersion(packet, ipv6Enabled: enabled) else { return nil }
    return version == 6 ? AF_INET6 : AF_INET
  }
  private func failure(_ message: String) -> NSError { NSError(domain: "XIO", code: 1, userInfo: [NSLocalizedDescriptionKey: message]) }

  override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
    guard UserDefaults(suiteName: XIOKeychain.sharedSuite)?.string(forKey: "consentRevision") == "2026-10-18",
          let configuration = (protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
          let id = configuration["profileID"] as? String else {
      completionHandler(failure("Open XIO and complete both disclosure screens.")); return
    }
    lock.lock(); generation &+= 1; let request = generation; cancelled = false; running = false; ipv6PayloadEnabled = false; dnsCache = [:]; dnsCursor = [:]; lock.unlock()
    profileID = id
    worker.async {
      var attemptedMonitor: NWPathMonitor?
      do {
        guard let raw = try XIOKeychain.read(id, profile: true),
              let object = try JSONSerialization.jsonObject(with: Data(raw.utf8)) as? [String: Any],
              let ip = object["ip"] as? String,
              let endpoint = object["endpoint"] as? String,
              let proto = object["protocol"] as? String,
              ["rivet-h3", "rivet-s1"].contains(proto),
              let ipv6Address = XIODualStackPolicy.ipv6Address(for: ip) else { throw self.failure("No supported RIVET profile.") }
        let configuredIPv6 = object["ip6"] as? String ?? ""
        guard (object["ip6"] == nil || object["ip6"] is NSNull || object["ip6"] is String),
              configuredIPv6.isEmpty || configuredIPv6 == ipv6Address else { throw self.failure("Invalid RIVET IPv6 address binding.") }
        let ready = DispatchSemaphore(value: 0)
        let monitor = NWPathMonitor(); attemptedMonitor = monitor; self.monitor = monitor
        monitor.pathUpdateHandler = { [weak self] path in
          guard let self = self else { return }
          if let physical = path.availableInterfaces.first(where: {
            path.usesInterfaceType($0.type) && ($0.type == .wifi || $0.type == .cellular || $0.type == .wiredEthernet)
          }) {
            self.lock.lock(); let current = self.generation == request && !self.cancelled; if current { self.interfaceIndex = UInt32(physical.index) }; self.lock.unlock(); if current { ready.signal() }
          }
        }
        monitor.start(queue: DispatchQueue(label: "app.xio.physical-path"))
        guard ready.wait(timeout: .now() + 5) == .success else { throw self.failure("No physical network is available.") }
        try self.checkCancellation(request)
        let timeout = (configuration["timeoutMillis"] as? NSNumber)?.int64Value ?? 15000
        let backendStatus = try self.startBridge(raw, endpoint: endpoint, timeout: timeout, generation: request)
        let ipv6Enabled = configuredIPv6 == ipv6Address && XIODualStackPolicy.backendSupportsIPv6(backendStatus)
        try self.checkCancellation(request)
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.79.0.1")
        let ipv4 = NEIPv4Settings(addresses: [ip], subnetMasks: ["255.255.255.255"])
        ipv4.includedRoutes = [NEIPv4Route.default()]; settings.ipv4Settings = ipv4
        // Always capture IPv6, even with an old/missing IPv6 backend or profile.
        // packetFamily drops it unless both profile and core explicitly enable it.
        let ipv6 = NEIPv6Settings(addresses: [ipv6Address], networkPrefixLengths: [128])
        ipv6.includedRoutes = [NEIPv6Route.default()]; settings.ipv6Settings = ipv6
        settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1"]); settings.mtu = 1280
        self.setTunnelNetworkSettings(settings) { error in
          // Serialize ownership check/global cleanup with native Start. An old
          // settings callback must never stop the replacement generation.
          self.worker.async {
            guard self.isCurrent(request) else { monitor.cancel(); completionHandler(self.failure("VPN start cancelled.")); return }
            if let error = error { XIORivetBridge.stop(); monitor.cancel(); completionHandler(error); return }
            guard self.beginPackets(ipv6Enabled: ipv6Enabled, generation: request) else { monitor.cancel(); completionHandler(self.failure("VPN start cancelled.")); return }
            self.readPackets(); completionHandler(nil)
          }
        }
      } catch {
        attemptedMonitor?.cancel()
        if self.isCurrent(request) { XIORivetBridge.stop() }
        completionHandler(self.failure("RIVET could not establish a verified VPN connection."))
      }
    }
  }
  private func startBridge(_ raw: String, endpoint: String, timeout: Int64, generation request: UInt64) throws -> String? {
    // Match the public Runner timeout contract and leave DNS/startup overhead
    // above the native bridge minimum of 1000 ms.
    guard timeout >= 5000, timeout <= 60000, let host = XIODualStackPolicy.endpointHost(endpoint) else { throw failure("Invalid RIVET endpoint or timeout.") }
    let deadline = ProcessInfo.processInfo.systemUptime + Double(timeout) / 1000
    let ready = DispatchSemaphore(value: 0)
    // Bound physical DNS by the same overall startup budget, before routing.
    resolver.async { _ = self.resolveAddresses(host, generation: request); ready.signal() }
    guard ready.wait(timeout: .now() + .milliseconds(Int(timeout))) == .success else { throw failure("Physical endpoint resolution timed out.") }
    try checkCancellation(request)
    lock.lock(); let count = dnsCache[host]?.count ?? 0; lock.unlock()
    guard count > 0 else { throw failure("Physical endpoint resolution failed.") }
    var lastError: Error = failure("No RIVET endpoint is reachable.")
    for attempt in 0..<count {
      try checkCancellation(request)
      let remaining = Int64((deadline - ProcessInfo.processInfo.systemUptime) * 1000)
      let budget = XIODualStackPolicy.attemptBudget(remainingMillis: remaining, candidatesLeft: count - attempt)
      guard budget >= 1000 else { break }
      do { return try XIORivetBridge.start(raw, protector: self, sink: self, timeout: budget) }
      catch { lastError = error }
    }
    throw lastError
  }
  private func readPackets() {
    guard isRunning() else { return }
    packetFlow.readPackets { [weak self] packets, protocols in
      guard let self = self, self.isRunning() else { return }
      for (packet, proto) in zip(packets, protocols) {
        guard let family = self.packetFamily(packet), proto.int32Value == family else { continue }
        _ = XIORivetBridge.input(packet)
      }
      self.readPackets()
    }
  }
  func writePacket(_ packet: Data) -> Bool {
    // The peer may send packets before routing is ready; drop them until start
    // has completed rather than writing to a detached packetFlow.
    guard isRunning() else { return true }
    guard let family = packetFamily(packet) else { return false }
    return packetFlow.writePackets([packet], withProtocols: [NSNumber(value: family)])
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
    guard address.ss_family == sa_family_t(AF_INET) else { return false }
    return setsockopt(Int32(socket), IPPROTO_IP, IP_BOUND_IF, &index, socklen_t(MemoryLayout<UInt32>.size)) == 0
  }
  private func resolveAddresses(_ host: String, generation request: UInt64) -> [String] {
    lock.lock()
    guard generation == request, !cancelled else { lock.unlock(); return [] }
    let cached = dnsCache[host]; let mayResolve = !running; lock.unlock()
    if let cached = cached { return cached }
    // Active reconnects use only the pre-route physical cache, never fresh DNS.
    guard mayResolve, !host.utf8.contains(0) else { return [] }
    var hints = addrinfo(); hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM
    var result: UnsafeMutablePointer<addrinfo>?
    guard getaddrinfo(host, nil, &hints, &result) == 0, result != nil else { return [] }
    defer { freeaddrinfo(result) }
    var cursor = result; var addresses: [String] = []; var scanned = 0
    while let entry = cursor, scanned < 64 {
      cursor = entry.pointee.ai_next; scanned += 1
      guard entry.pointee.ai_family == AF_INET || entry.pointee.ai_family == AF_INET6,
            let address = entry.pointee.ai_addr else { continue }
      var text = [CChar](repeating: 0, count: Int(NI_MAXHOST))
      guard getnameinfo(address, entry.pointee.ai_addrlen, &text, socklen_t(text.count), nil, 0, NI_NUMERICHOST) == 0 else { continue }
      let value = String(cString: text)
      guard !value.contains("%") else { continue }
      addresses.append(value)
    }
    let ordered = XIODualStackPolicy.orderedAddresses(addresses)
    lock.lock(); defer { lock.unlock() }
    guard generation == request, !cancelled, !running else { return [] }
    if let cached = dnsCache[host] { return cached }
    dnsCache[host] = ordered; dnsCursor[host] = 0; return ordered
  }
  func resolve(_ host: String) -> String {
    lock.lock(); let request = generation; lock.unlock()
    let addresses = resolveAddresses(host, generation: request)
    lock.lock(); defer { lock.unlock() }
    guard generation == request, !cancelled, !addresses.isEmpty else { return "" }
    let index = (dnsCursor[host] ?? 0) % addresses.count
    dnsCursor[host] = (index + 1) % addresses.count
    // ONE numeric per callback preserves the Apple net.ParseIP ABI. Each
    // failed startup/reconnect advances to the next cached, interleaved family.
    return addresses[index]
  }
  override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
    lock.lock(); generation &+= 1; cancelled = true; running = false; ipv6PayloadEnabled = false; lock.unlock(); monitor?.cancel(); XIORivetBridge.stop(); completionHandler()
  }
  override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
    guard messageData == Data("status".utf8), let data = XIORivetBridge.status().data(using: .utf8),
          var value = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { completionHandler?(nil); return }
    lock.lock(); value["ipv6Payload"] = running && ipv6PayloadEnabled; lock.unlock()
    value["id"] = profileID; completionHandler?(try? JSONSerialization.data(withJSONObject: value))
  }
}
