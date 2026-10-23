package rivet

import "os"

func readSeal(path string) ([]byte, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	if len(b) != 32 {
		return nil, ErrProtocol
	}
	return b, nil
}
