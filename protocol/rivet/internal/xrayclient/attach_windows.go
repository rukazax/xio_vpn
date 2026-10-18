package xrayclient

import "errors"

func (s *Session) Attach(fd int) error { return errors.New("Use named Wintun device on Windows") }
