package mobile

import (
	"runtime"
	"runtime/debug"
)

// Teardown reclaim.
//
// A tunnel that carried traffic leaves the helper's heap at whatever the
// two-generational goal allowed while it was up. On Android that is tens of
// megabytes: the AmneziaWG device queues up to 1024 packets per direction and
// every queued packet owns a [MaxMessageSize]byte (64 KiB) buffer, so the
// garbage left behind by one session is large, while the next collection only
// happens once the heap doubles again. Nothing in that garbage is reachable —
// the device, its bind and its queues are closed by the teardown — but the
// pages stay resident between connect/disconnect cycles and the process PSS
// climbs in steps until the collection catches up.
//
// Returning the pages at teardown is what keeps repeated Start/Stop flat: the
// heap is collected (so the next goal is computed from the real live set) and
// the free spans are handed back to the OS instead of waiting for a scavenger
// tick that may be minutes away on a battery-constrained device.
func reclaimAfterTeardown() {
	// One collection plus a scavenge. This is deliberately synchronous: it runs
	// once per disconnect, never on the packet path, and the caller is already
	// off the UI thread.
	runtime.GC()
	debug.FreeOSMemory()
}
