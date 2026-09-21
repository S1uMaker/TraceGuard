package main

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/zjc20/traceguard/internal/model"
)

type alertEncoder interface {
	Encode(any) error
}

// Console formatting never changes the full records written to the JSONL files.
func newAlertEncoder(w io.Writer, format string) (alertEncoder, error) {
	switch format {
	case "", "json":
		return json.NewEncoder(w), nil
	case "text":
		return &textAlertEncoder{writer: w}, nil
	default:
		return nil, fmt.Errorf("alert format must be json or text, got %q", format)
	}
}

type textAlertEncoder struct {
	writer io.Writer
}

func (encoder *textAlertEncoder) Encode(value any) error {
	alert, ok := value.(model.Alert)
	if !ok {
		return fmt.Errorf("text alert output expects model.Alert, got %T", value)
	}
	// Quote every event/config string so control characters cannot create fake
	// lines or terminal escape sequences. Event ID links back to the full evidence.
	line := fmt.Sprintf("%s level=%q rule=%q source=%q container=%q pid=%d uid=%d filename=%q event=%q replay=%t\n",
		alert.ObservedAt.UTC().Format(time.RFC3339Nano), alert.Severity, alert.RuleID,
		alert.Event.Source.Kind, alert.Event.Source.ContainerName, alert.Event.PID,
		alert.Event.UID, alert.Event.Filename, alert.EventID, alert.Event.Replay)
	n, err := io.WriteString(encoder.writer, line)
	if err == nil && n != len(line) {
		return io.ErrShortWrite
	}
	return err
}
