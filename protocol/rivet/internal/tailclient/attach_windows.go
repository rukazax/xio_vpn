package tailclient

import "errors"

func (d *Device) Attach(fd int) error { return errors.New("Wintun requires AttachIO") }
