package desktop

import (
	"encoding/json"
	"errors"
	"testing"
)

func legalRecordBytes(t *testing.T, mutate func(map[string]any)) json.RawMessage {
	t.Helper()
	fields := map[string]any{
		"revision":   acceptedConsentRevision,
		"timestamp":  "2026-10-18T00:00:00.000Z",
		"textSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"language":   "ru",
	}
	if mutate != nil {
		mutate(fields)
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestLegalRecordStrictShape(t *testing.T) {
	if _, err := parseLegalRecord(legalRecordBytes(t, nil)); err != nil {
		t.Fatalf("valid record: %v", err)
	}
	for name, raw := range map[string]json.RawMessage{
		"missing field": legalRecordBytes(t, func(fields map[string]any) { delete(fields, "language") }),
		"unknown field": legalRecordBytes(t, func(fields map[string]any) { fields["extra"] = "x" }),
		"non-string":    legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = 1 }),
		"null field":    legalRecordBytes(t, func(fields map[string]any) { fields["revision"] = nil }),
		"not an object": json.RawMessage(`[]`),
	} {
		if _, err := parseLegalRecord(raw); !errors.Is(err, ErrPolicyInvalid) {
			t.Fatalf("%s: %v, want POLICY_INVALID", name, err)
		}
	}
}

func TestLegalRecordCurrentMatchesAcceptedPredicate(t *testing.T) {
	// Cross-runtime corpus: every case was executed against Dart 3.13.5
	// (DateTime.tryParse) and the Go predicate must agree. Dart normalises
	// out-of-range components and numeric offsets; it accepts any fraction length
	// (truncating to microseconds), 4-6 digit signed years, an optional single
	// space before the zone and hour/minute-only times. It rejects one-digit
	// fields, lowercase 't', a missing/empty fraction, doubled whitespace and
	// trailing characters.
	valid := map[string]json.RawMessage{
		"millisecond Z":        legalRecordBytes(t, nil),
		"lowercase z":          legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00z" }),
		"zero offset":          legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00+00:00" }),
		"non-zero offset":      legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T03:00:00+03:00" }),
		"offset without colon": legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T03:00:00+0300" }),
		"offset hours only":    legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T03:00:00+03" }),
		"normalised offset":    legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00+99:99" }),
		"space separator":      legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18 00:00:00Z" }),
		"space before zone":    legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00 Z" }),
		"hour only":            legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00Z" }),
		"no seconds":           legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00Z" }),
		"comma fraction":       legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00,5Z" }),
		"seven-digit frac":     legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00.1234567Z" }),
		"nine-digit frac":      legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00.123456789Z" }),
		"twelve-digit frac":    legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00.999999999999Z" }),
		"month 13":             legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-13-06T09:00:00Z" }),
		"day 32":               legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-11-32T09:00:00Z" }),
		"hour 24":              legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-11-06T24:00:00Z" }),
		"minute 60":            legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-11-06T09:60:00Z" }),
		"second 60":            legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-11-06T09:00:60Z" }),
		"signed year":          legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "-2026-11-06T09:00:00Z" }),
		"plus year":            legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "+2026-11-06T09:00:00Z" }),
		"five-digit year":      legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "12026-11-06T09:00:00Z" }),
		"six-digit year":       legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "123456-11-06T09:00:00Z" }),
		"empty language":       legalRecordBytes(t, func(fields map[string]any) { fields["language"] = "" }),
		// Compact forms accepted by the installed Dart 3.13.5 _parseFormat:
		// optional date separators and optional time colons.
		"compact date and time": legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "20261106T090000Z" }),
		"compact time":          legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-11-06T090000Z" }),
		"compact date":          legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "20261106T09:00:00Z" }),
		"compact hour minute":   legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "20261106T0900Z" }),
		"mixed separators":      legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-1106T09:00:00Z" }),
		// Reviewer Dart oracle positive controls.
		"nine-digit fraction": legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-11-06T09:00:00.123456789Z" }),
		"oracle six-year":     legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "999999-11-06T09:00:00Z" }),
		"oracle signed year":  legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "+999999-11-06T09:00:00Z" }),
	}
	for name, raw := range valid {
		record, err := parseLegalRecord(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !record.current() {
			t.Fatalf("%s: accepted record is not current", name)
		}
	}
	stale := map[string]json.RawMessage{
		"wrong revision":        legalRecordBytes(t, func(fields map[string]any) { fields["revision"] = "2026-01-01" }),
		"date only":             legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18" }),
		"no zone":               legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00" }),
		"one-digit offset":      legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00+3" }),
		"three-digit offset":    legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00+003" }),
		"one-digit offset min":  legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00+03:5" }),
		"one-digit hour":        legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T9:00:00Z" }),
		"one-digit month":       legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-1-18T09:00:00Z" }),
		"empty fraction":        legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00.Z" }),
		"fraction without secs": legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00.5Z" }),
		"double space":          legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00  Z" }),
		"tab before zone":       legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00\tZ" }),
		"leading space":         legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = " 2026-10-18T00:00:00Z" }),
		"trailing space":        legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00Z " }),
		"lowercase t":           legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18t00:00:00z" }),
		"seven-digit year":      legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "1234567-11-06T09:00:00Z" }),
		"offset seconds":        legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00+03:30:00" }),
		"trailing char":         legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "2026-10-18T00:00:00Zx" }),
		"garbage timestamp":     legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "not-a-time-Z" }),
		// Actual Dart 3.13.5 _finishParse range boundary: the same regex matches,
		// but the normalised microseconds exceed _maxMillisecondsSinceEpoch*1000,
		// so DateTime.tryParse returns null and isUtc is false.
		"dart finishParse range boundary": legalRecordBytes(t, func(fields map[string]any) { fields["timestamp"] = "275761-01-01T00:00:00Z" }),
		"uppercase digest": legalRecordBytes(t, func(fields map[string]any) {
			fields["textSha256"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
		}),
		"short digest": legalRecordBytes(t, func(fields map[string]any) {
			fields["textSha256"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}),
		"empty digest": legalRecordBytes(t, func(fields map[string]any) { fields["textSha256"] = "" }),
	}
	for name, raw := range stale {
		record, err := parseLegalRecord(raw)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if record.current() {
			t.Fatalf("%s: stale record treated as current", name)
		}
	}
}

func TestUserRevokedSemantics(t *testing.T) {
	for name, tc := range map[string]struct {
		raw  json.RawMessage
		want bool
	}{
		"absent defaults false": {nil, false},
		"null defaults false":   {json.RawMessage("null"), false},
		"false":                 {json.RawMessage("false"), false},
		"true":                  {json.RawMessage("true"), true},
	} {
		got, err := userRevoked(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("%s: %v %v", name, got, err)
		}
	}
	for name, raw := range map[string]json.RawMessage{
		"string": json.RawMessage(`"false"`),
		"number": json.RawMessage("0"),
		"object": json.RawMessage("{}"),
		"array":  json.RawMessage("[]"),
	} {
		if _, err := userRevoked(raw); !errors.Is(err, ErrPolicyInvalid) {
			t.Fatalf("%s: %v, want POLICY_INVALID", name, err)
		}
	}
}
