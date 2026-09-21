package output

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/zjc20/traceguard/internal/model"
)

func TestWriterAppendsAndRejectsWritesAfterClose(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "records")
	first, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.WriteEvent(model.Event{ID: "first", Type: "process_exec"}); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close must be idempotent: %v", err)
	}
	if err := first.WriteEvent(model.Event{ID: "must-not-appear"}); err == nil {
		t.Fatal("write after close was accepted")
	}
	second, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := second.WriteEvent(model.Event{ID: "second", Type: "process_exec"}); err != nil {
		t.Fatal(err)
	}
	if err := second.WriteAlert(model.Alert{ID: "alert-second", EventID: "second"}); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(dir, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var ids []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		var event model.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, event.ID)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "first" || ids[1] != "second" {
		t.Fatalf("appended event order = %v", ids)
	}
	data, err := os.ReadFile(filepath.Join(dir, "alerts.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var alert model.Alert
	if err := json.Unmarshal(data, &alert); err != nil {
		t.Fatal(err)
	}
	if alert.EventID != "second" {
		t.Fatalf("alert lost its event reference: %#v", alert)
	}
}
