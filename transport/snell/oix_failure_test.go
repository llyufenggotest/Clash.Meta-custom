package snell

import (
	"bytes"
	"errors"
	"testing"
)

type failAfterWriter struct {
	limit int
	buf   bytes.Buffer
}

func (w *failAfterWriter) Write(p []byte) (int, error) {
	if w.limit <= 0 {
		return 0, errors.New("synthetic write failure")
	}
	if len(p) > w.limit {
		p = p[:w.limit]
	}
	n, _ := w.buf.Write(p)
	w.limit -= n
	return n, errors.New("synthetic write failure")
}

func TestV4WriterDoesNotCommitSaltAfterWriteFailure(t *testing.T) {
	writer := &failAfterWriter{limit: 8}
	v4, err := newV4WriterWithIdentity(writer, []byte("synthetic-secret"), bytes.Repeat([]byte{1}, IdentityHeaderLength))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v4.Write([]byte("payload")); err == nil {
		t.Fatal("Write() unexpectedly succeeded")
	}
	if v4.saltSent {
		t.Fatal("salt was committed after a failed frame write")
	}
}
