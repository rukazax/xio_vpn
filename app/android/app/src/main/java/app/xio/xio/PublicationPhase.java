package app.xio.xio;

/** Persisted envelope phases. {@code pendingUnknown} is a real phase, not an error string. */
public enum PublicationPhase {
    /** The pending proposal was acknowledged as durably written. */
    PENDING("pending"),
    /**
     * A physical writer is (or may be) outstanding and the durable result is not
     * proven: a parent timeout, a {@code commit()==false}, or a settle after the
     * logical owner was revoked. Never treated as pending-before-rename.
     */
    PENDING_UNKNOWN("pendingUnknown"),
    /** The committed plan and its generation were durably written. */
    READY("ready"),
    /** Admission is refused until explicit reconciliation. */
    BLOCKED("blocked");

    public final String wire;

    PublicationPhase(String wire) { this.wire = wire; }

    public static PublicationPhase parse(String wire) {
        for (PublicationPhase phase : values()) if (phase.wire.equals(wire)) return phase;
        throw new StrictJson.Invalid("phase: unsupported " + wire);
    }
}
