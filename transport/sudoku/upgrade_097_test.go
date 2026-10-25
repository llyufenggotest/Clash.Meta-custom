package sudoku

import (
	"bytes"
	"testing"
)

type upgradeCountingWriter struct {
	bytes.Buffer
	writes int
}

func (w *upgradeCountingWriter) Write(p []byte) (int, error) {
	w.writes++
	return w.Buffer.Write(p)
}

// The 0.9.7 transport must batch header and payload into one underlying
// write without changing KIP framing.
func TestUpgrade097KIPSingleWriteAndWire(t *testing.T) {
	var w upgradeCountingWriter
	payload := []byte{1, 2, 3}
	if err := WriteKIPMessage(&w, KIPTypeOpenTCP, payload); err != nil {
		t.Fatal(err)
	}
	if w.writes != 1 {
		t.Fatalf("KIP took %d writes, want 1", w.writes)
	}
	want := []byte{'k', 'i', 'p', KIPTypeOpenTCP, 0, 3, 1, 2, 3}
	if !bytes.Equal(w.Bytes(), want) {
		t.Fatalf("wire = %x, want %x", w.Bytes(), want)
	}
	msg, err := ReadKIPMessage(bytes.NewReader(w.Bytes()))
	if err != nil || msg.Type != KIPTypeOpenTCP || !bytes.Equal(msg.Payload, payload) {
		t.Fatalf("roundtrip: %+v %v", msg, err)
	}
}
