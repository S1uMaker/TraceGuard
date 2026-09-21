package collector

import (
	"strings"
	"testing"

	"github.com/zjc20/traceguard/internal/model"
)

func TestDecodeEventWireContract(t *testing.T) {
	// Fixed little-endian bytes from the 304-byte C wire contract. Do not use
	// eventSize or binary.Write here: accidental ABI changes must fail this test.
	record := make([]byte, 304)
	copy(record, []byte{
		0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01,
		0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
		0x24, 0x23, 0x22, 0x21,
		0x34, 0x33, 0x32, 0x31,
		0x44, 0x43, 0x42, 0x41,
		0x54, 0x53, 0x52, 0x51,
	})
	copy(record[32:48], "container-init\x00x")
	copy(record[48:304], "/usr/bin/curl\x00discarded-tail")

	got, err := decodeEvent(record)
	if err != nil {
		t.Fatalf("decodeEvent: %v", err)
	}
	want := model.RawEvent{
		TimestampNS: 0x0102030405060708,
		CgroupID:    0x1112131415161718,
		PID:         0x21222324,
		TID:         0x31323334,
		UID:         0x41424344,
		GID:         0x51525354,
		Comm:        "container-init",
		Filename:    "/usr/bin/curl",
	}
	if got != want {
		t.Fatalf("decoded record = %#v; want %#v", got, want)
	}
}

func TestDecodeEventFullWidthStrings(t *testing.T) {
	record := make([]byte, 304)
	wantComm := "0123456789abcdef"
	wantFilename := strings.Repeat("f", 256)
	copy(record[32:48], wantComm)
	copy(record[48:304], wantFilename)
	got, err := decodeEvent(record)
	if err != nil {
		t.Fatalf("decodeEvent: %v", err)
	}
	if got.Comm != wantComm || got.Filename != wantFilename {
		t.Fatalf("full-width strings were truncated or crossed fields: comm=%q filename length=%d", got.Comm, len(got.Filename))
	}
}

func TestDecodeEventRejectsInvalidSizes(t *testing.T) {
	for _, size := range []int{0, 1, 303, 305, 608} {
		got, err := decodeEvent(make([]byte, size))
		if err == nil {
			t.Errorf("size %d: expected an error", size)
		}
		if got != (model.RawEvent{}) {
			t.Errorf("size %d: invalid input returned a partial event: %#v", size, got)
		}
	}
}

func TestCStringNULTermination(t *testing.T) {
	for _, test := range []struct {
		name  string
		input []byte
		want  string
	}{
		{name: "nil"},
		{name: "empty", input: []byte{}},
		{name: "starts with NUL", input: []byte("\x00hidden")},
		{name: "first NUL wins", input: []byte("curl\x00ignored\x00tail"), want: "curl"},
		{name: "no terminator", input: []byte("complete"), want: "complete"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := cString(test.input); got != test.want {
				t.Fatalf("cString(%q) = %q; want %q", test.input, got, test.want)
			}
		})
	}
}
