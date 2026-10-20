package snell

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// Fixed, synthetic key/salt. Independent pre-optimization frame assembly keeps
// exact ciphertext/nonce equivalence independent from the optimized writer.
func streamWriter(t testing.TB, dst io.Writer) *v4Writer {
	t.Helper()
	a, err := v4AEAD([]byte("synthetic-stream-key"), make([]byte, v4SaltSize))
	if err != nil {
		t.Fatal(err)
	}
	return &v4Writer{Writer: dst, aead: a, saltSent: true, payloadLimit: maxLength, lastWrite: time.Now()}
}
func referenceStreamFrame(w *v4Writer, p []byte, n *[v4NonceSize]byte) []byte {
	h := make([]byte, v4HeaderPlainSize)
	h[0] = 4
	binary.BigEndian.PutUint16(h[5:7], uint16(len(p)))
	out := w.aead.Seal(nil, n[:], h, nil)
	incrementV4Nonce(n[:])
	if len(p) > 0 {
		out = append(out, w.aead.Seal(nil, n[:], p, nil)...)
		incrementV4Nonce(n[:])
	}
	return out
}
func TestV4StreamWriteAllocationBudget(t *testing.T) {
	w := streamWriter(t, io.Discard)
	p := make([]byte, 32768)
	if _, err := w.Write(p); err != nil {
		t.Fatal(err)
	}
	alloc := testing.AllocsPerRun(100, func() {
		if _, err := w.Write(p); err != nil {
			panic(err)
		}
	})
	if alloc != 0 {
		t.Fatalf("steady 32KiB write allocations=%g want=0", alloc)
	}
}
func TestV4StreamExactCiphertext(t *testing.T) {
	var raw bytes.Buffer
	w := streamWriter(t, &raw)
	var nonce [v4NonceSize]byte
	nonce[0] = 254
	w.nonce = nonce
	for _, size := range []int{1, 1421, maxLength, 0, 7, maxLength} {
		p := bytes.Repeat([]byte{byte(size)}, size)
		expected := referenceStreamFrame(w, p, &nonce)
		raw.Reset()
		if err := w.writeFrame(p, 0); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(raw.Bytes(), expected) {
			t.Fatalf("size=%d ciphertext differs", size)
		}
		if w.nonce != nonce {
			t.Fatalf("size=%d nonce=%x want=%x", size, w.nonce, nonce)
		}
	}
	if err := w.writeFrame(make([]byte, maxLength+1), 0); err == nil {
		t.Fatal("oversize frame accepted")
	}
}

type streamShortWriter struct {
	bytes.Buffer
	max       int
	failAfter int
	failure   error
}

func (w *streamShortWriter) Write(p []byte) (int, error) {
	if w.failure != nil && w.Len() >= w.failAfter {
		return 0, w.failure
	}
	if len(p) > w.max {
		p = p[:w.max]
	}
	return w.Buffer.Write(p)
}
func TestV4StreamPartialWriteAndError(t *testing.T) {
	dst := &streamShortWriter{max: 3}
	w := streamWriter(t, dst)
	p := bytes.Repeat([]byte{42}, maxLength+3)
	if n, err := w.Write(p); err != nil || n != len(p) {
		t.Fatalf("n=%d err=%v", n, err)
	}
	r := &v4Reader{Reader: bytes.NewReader(dst.Bytes()), aead: w.aead}
	got := make([]byte, len(p))
	if _, err := io.ReadFull(r, got); err != nil || !bytes.Equal(got, p) {
		t.Fatalf("partial write roundtrip err=%v", err)
	}
	fail := errors.New("synthetic write failure")
	dst = &streamShortWriter{max: 1 << 20, failAfter: v4HeaderCipherSize + maxLength + 16, failure: fail}
	w = streamWriter(t, dst)
	if n, err := w.Write(p); n != maxLength || !errors.Is(err, fail) {
		t.Fatalf("completed payload=%d want=%d error=%v", n, maxLength, err)
	}
	if w.nonce[0] != 4 {
		t.Fatalf("error-path nonce=%x want=4", w.nonce)
	}
	w = streamWriter(t, &streamShortWriter{max: 0})
	if _, err := w.Write([]byte{1}); err != io.ErrShortWrite {
		t.Fatalf("zero write err=%v", err)
	}
}
func TestV4StreamConsumedPlaintextCleared(t *testing.T) {
	var wire bytes.Buffer
	w := streamWriter(t, &wire)
	p := bytes.Repeat([]byte{0x57}, maxLength)
	if _, err := w.Write(p); err != nil {
		t.Fatal(err)
	}
	r := &v4Reader{Reader: &wire, aead: w.aead}
	got := make([]byte, 17)
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, p[:17]) {
		t.Fatal("incorrect payload")
	}
	if !bytes.Equal(r.frame[:17], make([]byte, 17)) {
		t.Fatal("consumed plaintext retained in reusable reader buffer")
	}
	if _, err := io.Copy(io.Discard, r); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(r.frame[:len(p)], make([]byte, len(p))) {
		t.Fatal("fully consumed plaintext retained")
	}
}

func TestV4StreamReadAllocationBudget(t *testing.T) {
	var wire bytes.Buffer
	w := streamWriter(t, &wire)
	p := make([]byte, 32768)
	r := &v4Reader{Reader: &wire, aead: w.aead}
	// Warm both maximum frame capacities before checking steady-state allocations.
	if _, err := w.Write(p); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(r, p); err != nil {
		t.Fatal(err)
	}
	// Account for the writer independently; the already-optimized writer is zero alloc.
	alloc := testing.AllocsPerRun(100, func() {
		if _, err := w.Write(p); err != nil {
			panic(err)
		}
		if _, err := io.ReadFull(r, p); err != nil {
			panic(err)
		}
	})
	if alloc != 0 {
		t.Fatalf("steady 32KiB read allocations=%g want=0", alloc)
	}
}
func TestV4StreamReadTruncationAndAuthentication(t *testing.T) {
	var wire bytes.Buffer
	w := streamWriter(t, &wire)
	p := bytes.Repeat([]byte{19}, 123)
	if err := w.writeFrame(p, 0); err != nil {
		t.Fatal(err)
	}
	frame := append([]byte(nil), wire.Bytes()...)
	for _, cut := range []int{0, 1, v4HeaderCipherSize - 1, v4HeaderCipherSize, v4HeaderCipherSize + 1, len(frame) - 1} {
		t.Run(fmt.Sprintf("cut_%d", cut), func(t *testing.T) {
			r := &v4Reader{Reader: bytes.NewReader(frame[:cut]), aead: w.aead}
			n, err := r.Read(make([]byte, 200))
			if n != 0 || err == nil {
				t.Fatalf("n=%d err=%v", n, err)
			}
			want := byte(0)
			if cut >= v4HeaderCipherSize {
				want = 1
			}
			if r.nonce[0] != want {
				t.Fatalf("nonce=%x want=%d", r.nonce, want)
			}
		})
	}
	for _, index := range []int{0, len(frame) - 1} {
		damaged := append([]byte(nil), frame...)
		damaged[index] ^= 1
		r := &v4Reader{Reader: bytes.NewReader(damaged), aead: w.aead}
		n, err := r.Read(make([]byte, 200))
		if n != 0 || err == nil {
			t.Fatalf("authenticated corruption accepted index=%d", index)
		}
		want := byte(1)
		if index != 0 {
			want = 2
		}
		if r.nonce[0] != want {
			t.Fatalf("nonce=%x want=%d", r.nonce, want)
		}
	}
}
func TestV4StreamReadBufferedPayloadSurvivesReuse(t *testing.T) {
	var wire bytes.Buffer
	w := streamWriter(t, &wire)
	var expected []byte
	for i, size := range []int{maxLength, 1, 721, maxLength, 7} {
		p := bytes.Repeat([]byte{byte(i + 1)}, size)
		expected = append(expected, p...)
		padding := 0
		if i == 2 {
			padding = 19
		}
		if err := w.writeFrame(p, padding); err != nil {
			t.Fatal(err)
		}
	}
	r := &v4Reader{Reader: &wire, aead: w.aead}
	var got bytes.Buffer
	chunk := make([]byte, 37)
	for got.Len() < len(expected) {
		n, err := r.Read(chunk)
		if err != nil {
			t.Fatal(err)
		}
		got.Write(chunk[:n])
	}
	if !bytes.Equal(got.Bytes(), expected) {
		t.Fatal("buffer reuse overwrote unread plaintext")
	}
}

func TestV4StreamConcurrentWrites(t *testing.T) {
	var raw bytes.Buffer
	w := streamWriter(t, &raw)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := bytes.Repeat([]byte{byte(i)}, 2048)
			for j := 0; j < 10; j++ {
				if _, err := w.Write(p); err != nil {
					t.Error(err)
				}
			}
		}(i)
	}
	wg.Wait()
	r := &v4Reader{Reader: &raw, aead: w.aead}
	counts := make([]int, 8)
	p := make([]byte, 2048)
	for i := 0; i < 80; i++ {
		if _, err := io.ReadFull(r, p); err != nil {
			t.Fatal(err)
		}
		if int(p[0]) >= len(counts) || !bytes.Equal(p, bytes.Repeat(p[:1], len(p))) {
			t.Fatal("interleaved payload")
		}
		counts[p[0]]++
	}
	for i, n := range counts {
		if n != 10 {
			t.Fatalf("writer %d count=%d", i, n)
		}
	}
}
func TestV4StreamCloseInterruptsBlockedWrite(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	conn := newV4Conn(client, []byte("synthetic-stream-key"))
	// Enter the reusable steady-frame path, not the unchanged salt/handshake path.
	conn.w = streamWriter(t, client)
	done := make(chan error, 1)
	go func() { _, err := conn.Write(make([]byte, 32768)); done <- err }()
	// Observe the underlying write before racing Close, rather than sleeping.
	first := make([]byte, 1)
	if _, err := io.ReadFull(server, first); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("blocked writer succeeded after Close")
		}
	case <-time.After(time.Second):
		t.Fatal("Close failed to unblock Write")
	}
}
func TestV4LegacyStreamVersionsRemainUsable(t *testing.T) {
	for _, version := range []int{Version1, Version2, Version3} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			wire := &bytes.Buffer{}
			conn := StreamConn(writerConn{Buffer: wire}, []byte("synthetic-stream-key"), version)
			if n, err := conn.Write([]byte("legacy-payload")); n != 14 || err != nil {
				t.Fatalf("n=%d err=%v", n, err)
			}
			if wire.Len() == 0 {
				t.Fatal("legacy transport wrote no frame")
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func BenchmarkV4Stream(b *testing.B) {
	for _, size := range []int{32768} {
		b.Run(fmt.Sprintf("Write/%d", size), func(b *testing.B) {
			w := streamWriter(b, io.Discard)
			p := make([]byte, size)
			_, _ = w.Write(p)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := w.Write(p); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run(fmt.Sprintf("Read/%d", size), func(b *testing.B) {
			var wire bytes.Buffer
			w := streamWriter(b, &wire)
			p := make([]byte, size)
			r := &v4Reader{Reader: &wire, aead: w.aead}
			_, _ = w.Write(p)
			_, _ = io.ReadFull(r, p)
			b.SetBytes(int64(size))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				b.StopTimer()
				if _, err := w.Write(p); err != nil {
					b.Fatal(err)
				}
				b.StartTimer()
				if _, err := io.ReadFull(r, p); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
