// Command xio-issuance-seal is the bounded stdin/stdout sealer for the
// XIO-CAPSULE-1 delivery capsule (G5 C0 primitive).
//
// It reads exactly one JSON object from stdin:
//
//	{"context": {"schema":1, "purpose":"owner-issuance/delivery", "version":1,
//	             "operation":"...", "uid":"...", "server":"...",
//	             "deployment":"...", "actor":"...",
//	             "requestDigest":"<64 hex>", "profileSetDigest":"<64 hex>"},
//	 "artifacts": {"<closed kind>": "<string>"},
//	 "recipientPublicKey": "<canonical base64, 32 bytes>"}
//
// and writes exactly one envelope JSON object to stdout. The input must be a
// single JSON value with no trailing bytes, no duplicate keys at any depth, and
// real JSON integers for schema/version. Secrets arrive only on stdin; they are
// never read from argv/environment, never written to a temp file, never echoed
// to stderr and never logged. Stderr carries only finite stable codes (no error
// text, no payload fragments). Any command-line argument is rejected so a
// secret can never be passed in argv by accident.
package main

import (
	"errors"
	"io"
	"os"

	"xio.local/rivet/internal/issuancecapsule"
)

const (
	exitOK       = 0
	exitReject   = 2
	exitInternal = 1

	maxInputBytes = 262144
)

const (
	codeUsage         = "E_USAGE"
	codeInputTooLarge = "E_INPUT_TOO_LARGE"
	codeInputShape    = "E_INPUT_SHAPE"
	codeContext       = "E_CONTEXT"
	codeArtifacts     = "E_ARTIFACTS"
	codeRecipient     = "E_RECIPIENT"
	codeSeal          = "E_SEAL"
)

func main() {
	os.Exit(seal(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// seal is testable without touching process globals.
func seal(arguments []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(arguments) != 0 {
		writeCode(stderr, codeUsage)
		return exitReject
	}
	input, err := io.ReadAll(io.LimitReader(stdin, maxInputBytes+1))
	if err != nil {
		writeCode(stderr, codeInputShape)
		return exitReject
	}
	if len(input) > maxInputBytes {
		writeCode(stderr, codeInputTooLarge)
		return exitReject
	}
	request, err := issuancecapsule.ParseSealRequest(input)
	if err != nil {
		writeCode(stderr, requestCode(err))
		return exitReject
	}
	envelope, err := issuancecapsule.Seal(request.Context, request.Artifacts, request.RecipientPublicKey)
	if err != nil {
		writeCode(stderr, sealCode(err))
		return exitReject
	}
	envelopeJSON := envelope.JSON()
	if _, err := stdout.Write(append(envelopeJSON, '\n')); err != nil {
		return exitInternal
	}
	return exitOK
}

func requestCode(err error) string {
	switch {
	case errors.Is(err, issuancecapsule.ErrSealRequestContext):
		return codeContext
	case errors.Is(err, issuancecapsule.ErrSealRequestArtifacts):
		return codeArtifacts
	case errors.Is(err, issuancecapsule.ErrSealRequestRecipient):
		return codeRecipient
	default:
		return codeInputShape
	}
}

func sealCode(err error) string {
	var rejection *issuancecapsule.Rejection
	if errors.As(err, &rejection) {
		switch rejection.Reason {
		case issuancecapsule.ReasonContext:
			return codeContext
		case issuancecapsule.ReasonArtifactKind, issuancecapsule.ReasonArtifactSize:
			return codeArtifacts
		case issuancecapsule.ReasonRecipientKey:
			return codeRecipient
		case issuancecapsule.ReasonPlaintextSize, issuancecapsule.ReasonTooLarge:
			return codeInputTooLarge
		}
	}
	return codeSeal
}

func writeCode(stderr io.Writer, code string) {
	_, _ = io.WriteString(stderr, code+"\n")
}
