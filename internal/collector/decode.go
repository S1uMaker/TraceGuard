// Package collector reads successful executable image replacements from eBPF.
package collector

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/zjc20/traceguard/internal/model"
)

// ErrClosed identifies reads or statistics requests after the collector closes.
var ErrClosed = os.ErrClosed

const eventSize = 304

// decodeEvent does not depend on Go struct padding or the host byte order.
func decodeEvent(data []byte) (model.RawEvent, error) {
	if len(data) != eventSize {
		return model.RawEvent{}, fmt.Errorf("invalid exec event size: got %d, want %d", len(data), eventSize)
	}
	return model.RawEvent{
		TimestampNS: binary.LittleEndian.Uint64(data[0:8]),
		CgroupID:    binary.LittleEndian.Uint64(data[8:16]),
		PID:         binary.LittleEndian.Uint32(data[16:20]),
		TID:         binary.LittleEndian.Uint32(data[20:24]),
		UID:         binary.LittleEndian.Uint32(data[24:28]),
		GID:         binary.LittleEndian.Uint32(data[28:32]),
		Comm:        cString(data[32:48]),
		Filename:    cString(data[48:304]),
	}, nil
}

func cString(data []byte) string {
	if i := bytes.IndexByte(data, 0); i >= 0 {
		data = data[:i]
	}
	return string(data)
}
