package desktop

// ResourceEvidence is deliberately not inferred from Runtime.current, an empty
// Runtime struct or a successful cooperating-helper claim. It only classifies
// read-only observations of the existing platform resource namespace. No
// observer is authorized to delete resources.
type ResourceEvidence string

const (
	ResourcesClean   ResourceEvidence = "clean"
	ResourcesOwned   ResourceEvidence = "owned"
	ResourcesUnknown ResourceEvidence = "unknown"
)

// resourceObservation keeps failed/unsafe enumeration distinct from an empty
// result. Owned means a reserved resource or ownership receipt remains, not
// permission to delete it. Even a malformed legacy receipt cannot turn Unknown
// into Clean.
type resourceObservation struct {
	complete bool
	owned    bool
}

// classifyResources is conservative: any incomplete observation makes the whole
// class Unknown, and any owned observation makes it Owned. No observations at all
// is Unknown, never Clean.
func classifyResources(observations ...resourceObservation) ResourceEvidence {
	if len(observations) == 0 {
		return ResourcesUnknown
	}
	for _, observation := range observations {
		if !observation.complete {
			return ResourcesUnknown
		}
	}
	for _, observation := range observations {
		if observation.owned {
			return ResourcesOwned
		}
	}
	return ResourcesClean
}
