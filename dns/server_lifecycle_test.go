package dns

import (
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	D "github.com/miekg/dns"
)

type lifecycleService struct{}

func (lifecycleService) ServeMsg(_ context.Context, q *D.Msg) (*D.Msg, error) {
	r := new(D.Msg)
	r.SetReply(q)
	r.Answer = []D.RR{&D.A{Hdr: D.RR_Header{Name: q.Question[0].Name, Rrtype: D.TypeA, Class: D.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 7)}}
	return r, nil
}

type lifecycleListenConfig struct {
	net.ListenConfig
	attempts chan struct{}
}

func (l *lifecycleListenConfig) Listen(ctx context.Context, network, addr string) (net.Listener, error) {
	p, e := l.ListenConfig.Listen(ctx, network, addr)
	if l.attempts != nil {
		l.attempts <- struct{}{}
	}
	return p, e
}
func (l *lifecycleListenConfig) ListenPacket(ctx context.Context, network, addr string) (net.PacketConn, error) {
	p, e := l.ListenConfig.ListenPacket(ctx, network, addr)
	if l.attempts != nil {
		l.attempts <- struct{}{}
	}
	return p, e
}
func lifecycleAddress(t *testing.T) string {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	a := l.Addr().String()
	l.Close()
	return a
}
func lifecycleSocketQuery(addr, network string) error {
	q := new(D.Msg)
	q.SetQuestion("private.test.", D.TypeA)
	r, _, e := (&D.Client{Net: network, Timeout: 200 * time.Millisecond}).Exchange(q, addr)
	if e == nil && (r.Rcode != D.RcodeSuccess || len(r.Answer) != 1) {
		return &net.AddrError{Err: "unexpected DNS response", Addr: addr}
	}
	return e
}
func TestDNSLifecycleBusyPortRetry(t *testing.T) {
	addr := lifecycleAddress(t)
	tcp, e := net.Listen("tcp", addr)
	if e != nil {
		t.Fatal(e)
	}
	udp, e := net.ListenPacket("udp", addr)
	if e != nil {
		tcp.Close()
		t.Fatal(e)
	}
	lc := &lifecycleListenConfig{attempts: make(chan struct{}, 4)}
	if err := ReCreateServerWithError(addr, lc, lifecycleService{}); err == nil {
		t.Fatal("busy bind reported success")
	}
	tcp.Close()
	udp.Close()
	defer ReCreateServer("", nil, nil)
	ReCreateServer(addr, &lifecycleListenConfig{}, lifecycleService{})
	for _, network := range []string{"udp", "tcp"} {
		if e := lifecycleSocketQuery(addr, network); e != nil {
			t.Errorf("same-address retry did not restore %s DNS: %v", network, e)
		}
	}
}

func lifecycleAssertFree(t *testing.T, addr string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestDNSLifecycleIndependentBind$")
	cmd.Env = append(os.Environ(), "DNS_LIFECYCLE_BIND="+addr)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("independent bind: %v\n%s", err, out)
	}
}
func TestDNSLifecycleIndependentBind(t *testing.T) {
	addr := os.Getenv("DNS_LIFECYCLE_BIND")
	if addr == "" {
		return
	}
	tcp, e := net.Listen("tcp", addr)
	if e != nil {
		t.Fatal(e)
	}
	defer tcp.Close()
	udp, e := net.ListenPacket("udp", addr)
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
}
func lifecycleAssertQueries(t *testing.T, addr string) {
	t.Helper()
	for _, n := range []string{"udp", "tcp"} {
		if e := lifecycleSocketQuery(addr, n); e != nil {
			t.Fatalf("%s query: %v", n, e)
		}
	}
}
func TestDNSLifecycleSuspendResume(t *testing.T) {
	StopServer()
	_ = ResumeServer()
	t.Cleanup(func() { StopServer(); _ = ResumeServer() })
	addr := lifecycleAddress(t)
	if e := ReCreateServerWithError(addr, &net.ListenConfig{}, lifecycleService{}); e != nil {
		t.Fatal(e)
	}
	lifecycleAssertQueries(t, addr)
	if e := SuspendServer(); e != nil {
		t.Fatal(e)
	}
	lifecycleAssertFree(t, addr)
	if e := ReCreateServerWithError(addr, &net.ListenConfig{}, lifecycleService{}); e != nil {
		t.Fatal(e)
	}
	lifecycleAssertFree(t, addr)
	if e := ResumeServer(); e != nil {
		t.Fatal(e)
	}
	lifecycleAssertQueries(t, addr)
	StopServer()
	lifecycleAssertFree(t, addr)
	// Clearing config must not undo a previously established owner gate.
	_ = SuspendServer()
	StopServer()
	ReCreateServer(addr, &net.ListenConfig{}, lifecycleService{})
	lifecycleAssertFree(t, addr)
	if e := ResumeServer(); e != nil {
		t.Fatal(e)
	}
	lifecycleAssertQueries(t, addr)
}
func TestDNSLifecyclePartialBindCleanup(t *testing.T) {
	StopServer()
	defer StopServer()
	for _, network := range []string{"tcp", "udp"} {
		addr := lifecycleAddress(t)
		var blocker io.Closer
		var err error
		if network == "tcp" {
			blocker, err = net.Listen("tcp", addr)
		} else {
			blocker, err = net.ListenPacket("udp", addr)
		}
		if err != nil {
			t.Fatal(err)
		}
		if e := ReCreateServerWithError(addr, &net.ListenConfig{}, lifecycleService{}); e == nil {
			t.Fatal("partial bind succeeded")
		}
		listenerMu.Lock()
		published := address
		listenerMu.Unlock()
		if published != "" {
			t.Fatalf("fake published address %s", published)
		}
		blocker.Close()
		lifecycleAssertFree(t, addr)
		if e := ReCreateServerWithError(addr, &net.ListenConfig{}, lifecycleService{}); e != nil {
			t.Fatal(e)
		}
		lifecycleAssertQueries(t, addr)
		StopServer()
		lifecycleAssertFree(t, addr)
	}
}

type lifecycleHeldBind struct {
	net.ListenConfig
	entered, release chan struct{}
}

func (lc *lifecycleHeldBind) ListenPacket(ctx context.Context, n, a string) (net.PacketConn, error) {
	close(lc.entered)
	<-lc.release
	return lc.ListenConfig.ListenPacket(ctx, n, a)
}
func TestDNSLifecycleHeldBindStop(t *testing.T) {
	StopServer()
	defer StopServer()
	addr := lifecycleAddress(t)
	lc := &lifecycleHeldBind{entered: make(chan struct{}), release: make(chan struct{})}
	created := make(chan error, 1)
	go func() { created <- ReCreateServerWithError(addr, lc, lifecycleService{}) }()
	<-lc.entered
	stopped := make(chan struct{})
	go func() { StopServer(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("stop passed a pending bind")
	case <-time.After(20 * time.Millisecond):
	}
	close(lc.release)
	if e := <-created; e != nil {
		t.Fatal(e)
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("stop stuck")
	}
	lifecycleAssertFree(t, addr)
	time.Sleep(20 * time.Millisecond)
	lifecycleAssertFree(t, addr)
}

type lifecycleBlockingService struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *lifecycleBlockingService) ServeMsg(ctx context.Context, q *D.Msg) (*D.Msg, error) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	return lifecycleService{}.ServeMsg(ctx, q)
}
func TestDNSLifecycleBoundedStopActiveRequest(t *testing.T) {
	StopServer()
	defer StopServer()
	addr := lifecycleAddress(t)
	svc := &lifecycleBlockingService{entered: make(chan struct{}), release: make(chan struct{})}
	if e := ReCreateServerWithError(addr, &net.ListenConfig{}, svc); e != nil {
		t.Fatal(e)
	}
	queried := make(chan struct{})
	go func() { _ = lifecycleSocketQuery(addr, "udp"); close(queried) }()
	<-svc.entered
	start := time.Now()
	StopServer()
	if time.Since(start) > time.Second {
		t.Fatal("stop waited for resolver request")
	}
	lifecycleAssertFree(t, addr)
	close(svc.release)
	<-queried
}
func TestDNSLifecycleConcurrentQueryReload(t *testing.T) {
	StopServer()
	defer StopServer()
	addr := lifecycleAddress(t)
	if e := ReCreateServerWithError(addr, &net.ListenConfig{}, lifecycleService{}); e != nil {
		t.Fatal(e)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				_ = lifecycleSocketQuery(addr, []string{"tcp", "udp"}[j%2])
			}
		}()
	}
	for i := 0; i < 30; i++ {
		if e := ReCreateServerWithError(addr, &net.ListenConfig{}, lifecycleService{}); e != nil {
			t.Fatal(e)
		}
	}
	// Also retire/rebind generations while requests are in flight; errors during
	// the intentional stopped windows are allowed, races and late binds are not.
	for i := 0; i < 8; i++ {
		StopServer()
		if e := ReCreateServerWithError(addr, &net.ListenConfig{}, lifecycleService{}); e != nil {
			t.Fatal(e)
		}
	}
	wg.Wait()
	lifecycleAssertQueries(t, addr)
}
