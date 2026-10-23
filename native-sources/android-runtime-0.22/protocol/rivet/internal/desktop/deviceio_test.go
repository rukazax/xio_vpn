package desktop

import (
	"errors"
	"testing"
)

type batchTun struct {
	reads   int
	written []byte
}

func (*batchTun) BatchSize() int { return 3 }
func (t *batchTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	t.reads++
	if len(bufs) != 3 {
		return 0, errors.New("batch capacity")
	}
	for i := 0; i < 3; i++ {
		bufs[i][offset] = byte(i + 1)
		sizes[i] = 1
	}
	return 3, nil
}
func (t *batchTun) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 16 {
		return 0, errors.New("virtio headroom")
	}
	t.written = append([]byte(nil), bufs[0][offset:]...)
	return 1, nil
}
func (*batchTun) Close() error          { return nil }
func (*batchTun) Name() (string, error) { return deviceName, nil }
func TestPacketAdapterKeepsBatchesAndVirtioHeadroom(t *testing.T) {
	native := &batchTun{}
	d := newDeviceIO(native)
	b := make([]byte, 20)
	for i := 1; i <= 3; i++ {
		n, e := d.Read(b)
		if e != nil || n != 1 || b[0] != byte(i) {
			t.Fatal("packet in returned batch was lost")
		}
	}
	if native.reads != 1 {
		t.Fatal("batch was reread")
	}
	if n, e := d.Write([]byte{1, 2, 3}); n != 3 || e != nil || len(native.written) != 3 {
		t.Fatal("TUN write lost headroom or payload")
	}
}
