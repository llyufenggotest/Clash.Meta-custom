package multiplex

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var pongFixtureID atomic.Uint64
var errPongWrite = errors.New("injected pong write failure")

// Observe the actual production writer, without starting a substitute worker.
type pongObservedConn struct {
	net.Conn
	entered chan struct{}
	once    sync.Once
	fail    <-chan struct{}
}

func (c *pongObservedConn) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered) })
	if c.fail != nil {
		<-c.fail
		return 0, errPongWrite
	}
	return c.Conn.Write(p)
}

// Count multiplicities, not profile blocks, and require the unique ownership
// label and the real production stack in the same block.
func pongOwnedWorkers(t *testing.T, label string) (all, pong int) {
	t.Helper()
	var profile bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&profile, 1); err != nil {
		t.Fatal(err)
	}
	for _, block := range strings.Split(profile.String(), "\n\n") {
		if !strings.Contains(block, `"sudoku-pong-owner":"`+label+`"`) {
			continue
		}
		for _, line := range strings.Split(block, "\n") {
			if !strings.Contains(line, " @ ") {
				continue
			}
			n, err := strconv.Atoi(strings.Fields(line)[0])
			if err != nil {
				t.Fatal(err)
			}
			all += n
			if strings.Contains(block, "requestPong.func1") {
				pong += n
			}
			break
		}
	}
	return
}

func pongAwait(t *testing.T, condition func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		runtime.Gosched()
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("did not observe %s within 1s", what)
}

func newPongFixture(t *testing.T, fail <-chan struct{}) (*Session, net.Conn, string, <-chan struct{}) {
	t.Helper()
	server, peer := net.Pipe()
	conn := &pongObservedConn{Conn: server, entered: make(chan struct{}), fail: fail}
	label := fmt.Sprintf("pong-%d", pongFixtureID.Add(1))
	var s *Session
	pprof.Do(context.Background(), pprof.Labels("sudoku-pong-owner", label), func(context.Context) {
		var err error
		s, err = NewServerSession(conn)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Cleanup(func() {
		_ = s.Close()
		_ = peer.Close()
		pongAwait(t, func() bool { all, _ := pongOwnedWorkers(t, label); return all == 0 }, "all owned session workers retired")
	})
	pongAwait(t, func() bool { all, pong := pongOwnedWorkers(t, label); return all == 2 && pong == 0 }, "real readLoop and keepalive startup")
	return s, peer, label, conn.entered
}

func pongWritePing(t *testing.T, peer net.Conn) {
	t.Helper()
	var ping [headerSize]byte
	ping[0] = framePing
	if _, err := peer.Write(ping[:]); err != nil {
		t.Fatalf("write PING: %v", err)
	}
}

func pongReadReply(t *testing.T, peer net.Conn) {
	t.Helper()
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var reply [headerSize]byte
	if _, err := io.ReadFull(peer, reply[:]); err != nil {
		t.Fatalf("read PONG: %v", err)
	}
	want := [headerSize]byte{framePong}
	if reply != want {
		t.Fatalf("reply %v, want empty stream-zero PONG %v", reply, want)
	}
}

func TestPongBlockedBurstRecovers(t *testing.T) {
	s, peer, label, entered := newPongFixture(t, nil)
	if err := peer.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	pongWritePing(t, peer)
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("PONG writer did not start")
	}
	pongAwait(t, func() bool { _, n := pongOwnedWorkers(t, label); return n == 1 }, "actual blocked PONG worker")
	for i := 1; i < 10000; i++ {
		pongWritePing(t, peer)
		if i%128 == 0 {
			runtime.Gosched()
			time.Sleep(time.Millisecond)
		}
	}
	// Let admitted reply goroutines reach the writer before profiling.
	time.Sleep(20 * time.Millisecond)
	all, pong := pongOwnedWorkers(t, label)
	t.Logf("accepted ping frames=10000 owned workers=%d actual pong workers=%d", all, pong)
	if pong != 1 || !s.pongPending.Load() {
		t.Fatalf("blocked burst: actual pong workers=%d pending=%v, want 1/true", pong, s.pongPending.Load())
	}
	pongReadReply(t, peer)
	pongAwait(t, func() bool { _, n := pongOwnedWorkers(t, label); return n == 0 && !s.pongPending.Load() }, "PONG completion and pending reset")
	// A new PING must not be lost behind a permanently set flag.
	pongWritePing(t, peer)
	pongReadReply(t, peer)
	pongAwait(t, func() bool { _, n := pongOwnedWorkers(t, label); return n == 0 && !s.pongPending.Load() }, "second PONG completion")
	if s.IsClosed() {
		t.Fatal("normal PONG completion closed the session")
	}
}

func TestPongWorkerRetiresOnErrorAndClose(t *testing.T) {
	for _, mode := range []string{"write-error", "close"} {
		t.Run(mode, func(t *testing.T) {
			var fail chan struct{}
			if mode == "write-error" {
				fail = make(chan struct{})
			}
			// Ensure an assertion failure cannot strand the injected Write.
			if fail != nil {
				defer close(fail)
			}
			s, peer, label, entered := newPongFixture(t, fail)
			_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
			pongWritePing(t, peer)
			select {
			case <-entered:
			case <-time.After(time.Second):
				t.Fatal("PONG writer did not start")
			}
			pongAwait(t, func() bool { _, n := pongOwnedWorkers(t, label); return n == 1 }, "actual blocked PONG worker")
			if !s.pongPending.Load() {
				t.Error("pending cleared before blocked send returned")
			}
			if fail != nil {
				// Release with a real send error; Close is still production code.
				fail <- struct{}{}
			} else if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			pongAwait(t, func() bool {
				all, _ := pongOwnedWorkers(t, label)
				return all == 0 && !s.pongPending.Load() && s.IsClosed()
			}, "all owned workers retired and pending reset")
			if mode == "write-error" && !errors.Is(s.closedErr(), errPongWrite) {
				t.Fatalf("close error: %v", s.closedErr())
			}
			// Even an already-closed send must reset the flag on return.
			pprof.Do(context.Background(), pprof.Labels("sudoku-pong-owner", label), func(context.Context) { s.requestPong() })
			pongAwait(t, func() bool { all, _ := pongOwnedWorkers(t, label); return all == 0 && !s.pongPending.Load() }, "closed-session send retirement")
		})
	}
}
