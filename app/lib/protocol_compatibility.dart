/// Wire format and native-engine availability are separate contracts. Never
/// shrink the Android set or silently advertise a native engine that is absent.
const universalProtocolIds = {'xray', 'rivet-s1', 'cloak', 'awg', 'rivet-h3'};

enum ClientPlatform { android, windows, ubuntu, ios }

const nativeProtocolTargets = <ClientPlatform, Set<String>>{
  ClientPlatform.android: universalProtocolIds,
  ClientPlatform.windows: {'xray', 'rivet-s1', 'awg', 'rivet-h3'},
  ClientPlatform.ubuntu: {'xray', 'rivet-s1', 'awg', 'rivet-h3'},
  ClientPlatform.ios: {'rivet-s1', 'rivet-h3'},
};
Set<String> missingProtocolsFor(ClientPlatform target) =>
    universalProtocolIds.difference(nativeProtocolTargets[target]!);
bool get completeProtocolParity =>
    ClientPlatform.values.every((p) => missingProtocolsFor(p).isEmpty);
