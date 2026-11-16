package desktop

import (
	"encoding/json"
	"regexp"
)

// Confirmed accepted-source facts (repo-merge app/lib/legal_record.dart):
// LegalRecord.toJson = {revision, timestamp, textSha256, language}; all four are
// required strings and LegalRecord.parse rejects a missing one. A record is
// "current" only when the revision is exactly the accepted value, the timestamp
// satisfies Dart DateTime.tryParse(...).isUtc == true, and textSha256 is 64
// lowercase hex.
//
// The plan's consentRevision string is NEVER consent evidence by itself: a plan
// may quote a revision while the durable document carries a different or stale
// legal record, so the caller must validate the actual record from the supplied
// document snapshot before treating consent as current.
const acceptedConsentRevision = "2026-10-18"

var consentDigestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// dartTimestampFormat is the EXACT DateTime.parse format of the installed Dart
// 3.13.5 SDK (lib/core/date_time.dart, var _parseFormat; BSD-style SDK header):
//
//	^([+-]?\d{4,6})-?(\d\d)-?(\d\d)
//	 (?:[ T](\d\d)(?::?(\d\d)(?::?(\d\d)(?:[.,](\d+))?)?)?
//	 ( ?[zZ]| ?([-+])(\d\d)(?::?(\d\d))?)?)?$
//
// Groups: 1 year, 2 month, 3 day, 4 hour, 5 minute, 6 second, 7 fraction,
// 8 timezone, 9 sign, 10 offset hour, 11 offset minute. parse() sets isUtc iff
// group 8 participated; date separators and time colons are optional (compact
// forms are valid), the fraction may have any length (Dart uses the first six
// digits) and only follows seconds, and exactly one optional ASCII space may
// precede the zone. Month/day/hour/minute/second overflow is normalised by
// DateTime rather than rejected. We intentionally add no RFC or Go-DateTime
// range restrictions: the predicate mirrors the installed runtime's match plus
// isUtc rule, which the reviewer's Dart-generated oracle probes.
var dartTimestampFormat = regexp.MustCompile(
	`^([+-]?\d{4,6})-?(\d\d)-?(\d\d)(?:[ T](\d\d)(?::?(\d\d)(?::?(\d\d)(?:[.,](\d+))?)?)?( ?[zZ]| ?([-+])(\d\d)(?::?(\d\d))?)?)?$`)

// legalTimestampIsUTC mirrors DateTime.tryParse(value)?.isUtc == true: the value
// must match the SDK format, carry the timezone group, and survive
// _finishParse's representable-range check. It only decides match plus UTC
// validity; it never normalises or rewrites the stored bytes, so the document
// hash stays over the exact read-back bytes.
func legalTimestampIsUTC(value string) bool {
	parts := dartTimestampFormat.FindStringSubmatch(value)
	if parts == nil || parts[8] == "" {
		return false
	}
	year := dartParseInt(parts[1])
	month := dartParseInt(parts[2])
	day := dartParseInt(parts[3])
	hour := dartParseInt(parts[4])
	minute := dartParseInt(parts[5])
	second := dartParseInt(parts[6])
	millisecond, microsecond := dartFractionMicros(parts[7])
	if parts[9] != "" {
		offset := 60*dartParseInt(parts[10]) + dartParseInt(parts[11])
		if parts[9] == "-" {
			offset = -offset
		}
		minute -= offset
	}
	_, ok := dartBrokenDownMicroseconds(year, month, day, hour, minute, second, millisecond, microsecond)
	return ok
}

// Dart VM Duration constants and the core _maxMillisecondsSinceEpoch bound.
const (
	dartMicrosecondsPerDay    = int64(86_400_000_000)
	dartMicrosecondsPerHour   = int64(3_600_000_000)
	dartMicrosecondsPerMinute = int64(60_000_000)
	dartMicrosecondsPerSecond = int64(1_000_000)
	dartMicrosecondsPerMilli  = int64(1_000)
	dartMaxMicroseconds       = int64(8_640_000_000_000_000_000)
)

// _DAYS_UNTIL_MONTH from the installed VM date_patch.dart, non-leap then leap.
var dartDaysUntilMonth = [2][12]int64{
	{0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334},
	{0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335},
}

func dartParseInt(value string) int64 {
	if value == "" {
		return 0
	}
	var number int64
	negative := false
	if value[0] == '+' {
		value = value[1:]
	} else if value[0] == '-' {
		negative = true
		value = value[1:]
	}
	for i := 0; i < len(value); i++ {
		number = number*10 + int64(value[i]-'0')
	}
	if negative {
		number = -number
	}
	return number
}

// dartFractionMicros mirrors parseMilliAndMicroseconds: the first six fraction
// digits, zero-padded on the right, give milliseconds and microseconds.
func dartFractionMicros(digits string) (int64, int64) {
	var value int64
	for i := 0; i < 6; i++ {
		value *= 10
		if i < len(digits) {
			value += int64(digits[i] - '0')
		}
	}
	return value / 1000, value % 1000
}

// dartFlooredDivision mirrors date_patch.dart _flooredDivision, including the
// truncating ~/ step.
func dartFlooredDivision(a, b int64) int64 {
	if a < 0 {
		a -= b - 1
	}
	return a / b
}

func dartDayFromYear(year int64) int64 {
	return 365*(year-1970) +
		dartFlooredDivision(year-1969, 4) -
		dartFlooredDivision(year-1901, 100) +
		dartFlooredDivision(year-1601, 400)
}

func dartIsLeapYear(year int64) bool {
	return year%4 == 0 && (year%16 == 0 || year%100 != 0)
}

func dartEuclideanMod(a, b int64) int64 {
	remainder := a % b
	if remainder < 0 {
		remainder += b
	}
	return remainder
}

func dartAbs(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}

// dartBrokenDownMicroseconds mirrors _brokenDownDateToValue for isUtc=true,
// including month normalisation, leap days and Dart VM signed-64 wrapping. The
// range rejection is _finishParse's
// `value.abs() > _maxMillisecondsSinceEpoch * microsecondsPerMillisecond` test;
// because Dart VM int arithmetic wraps, extreme years such as 999999 can wrap
// back into range (and the Dart oracle shows isUtc=true) while 275761 exceeds
// the bound and is rejected.
func dartBrokenDownMicroseconds(year, month, day, hour, minute, second, millisecond, microsecond int64) (int64, bool) {
	month--
	if month >= 12 {
		year += month / 12
		month %= 12
	} else if month < 0 {
		realMonth := dartEuclideanMod(month, 12)
		year += (month - realMonth) / 12
		month = realMonth
	}
	leap := 0
	if dartIsLeapYear(year) {
		leap = 1
	}
	days := day - 1 + dartDaysUntilMonth[leap][month] + dartDayFromYear(year)
	value := days*dartMicrosecondsPerDay +
		hour*dartMicrosecondsPerHour +
		minute*dartMicrosecondsPerMinute +
		second*dartMicrosecondsPerSecond +
		millisecond*dartMicrosecondsPerMilli + microsecond
	if dartAbs(value) > dartMaxMicroseconds {
		return 0, false
	}
	return value, true
}

type legalRecord struct {
	Revision   string
	Timestamp  string
	TextSHA256 string
	Language   string
}

func parseLegalRecord(raw json.RawMessage) (legalRecord, error) {
	fields, err := decodeStrictObject(raw,
		[]string{"revision", "timestamp", "textSha256", "language"}, nil, "legal record")
	if err != nil {
		return legalRecord{}, err
	}
	record := legalRecord{}
	for _, field := range []struct {
		key    string
		target *string
		what   string
	}{
		{"revision", &record.Revision, "legal revision"},
		{"timestamp", &record.Timestamp, "legal timestamp"},
		{"textSha256", &record.TextSHA256, "legal text digest"},
		{"language", &record.Language, "legal language"},
	} {
		if *field.target, err = policyStringValue(fields[field.key], field.what); err != nil {
			return legalRecord{}, err
		}
	}
	return record, nil
}

// current mirrors the accepted Dart predicate; it never trims the stored value.
func (r legalRecord) current() bool {
	return r.Revision == acceptedConsentRevision &&
		consentDigestPattern.MatchString(r.TextSHA256) &&
		legalTimestampIsUTC(r.Timestamp)
}

// userRevoked mirrors the accepted users[].revoked semantics
// (repo-merge app/lib/managed_models.dart): an absent or null value currently
// defaults to false, a real bool is used as-is, and any other type is rejected
// rather than silently coerced.
func userRevoked(raw json.RawMessage) (bool, error) {
	if len(raw) == 0 || isJSONNull(raw) {
		return false, nil
	}
	var revoked bool
	if err := json.Unmarshal(raw, &revoked); err != nil {
		return false, policyInvalid("invalid user revoked flag")
	}
	return revoked, nil
}
