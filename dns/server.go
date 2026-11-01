package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/sockopt"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
	D "github.com/miekg/dns"
)

var (
	listenerMu          sync.Mutex
	address             string // Published only after both transports are ready.
	server              = &Server{}
	desiredAddress      string
	desiredListenConfig C.InboundListenConfig
	desiredService      resolver.Service
	listenerSuspended   bool   // Process-local ownership; clearing config does not reset it.
	dnsDefaultTTL       uint32 = 600
)

type Server struct {
	serviceMu sync.RWMutex
	service   resolver.Service
	tcpServer *D.Server
	udpServer *D.Server
	tcpRun    *dnsServerRun
	udpRun    *dnsServerRun
}

type dnsServerRun struct {
	done chan struct{}
	err  error // Read only after done is closed.
}

type serverHandler struct {
	*Server
	isUDP bool
}

func (s serverHandler) ServeDNS(w D.ResponseWriter, r *D.Msg) {
	s.serviceMu.RLock()
	service := s.service
	s.serviceMu.RUnlock()
	var msg *D.Msg
	var err error
	if service != nil {
		msg, err = service.ServeMsg(context.Background(), r)
	}
	if service == nil || err != nil || msg == nil {
		m := new(D.Msg)
		m.SetRcode(r, D.RcodeServerFailure)
		_ = w.WriteMsg(m)
		return
	}
	if s.isUDP {
		msg.Truncate(resolver.RequestUDPSize(r))
	}
	msg.Compress = true
	_ = w.WriteMsg(msg)
}
func (s *Server) UDPHandler() D.Handler { return serverHandler{Server: s, isUDP: true} }
func (s *Server) TCPHandler() D.Handler { return serverHandler{Server: s} }
func (s *Server) SetService(service resolver.Service) {
	s.serviceMu.Lock()
	s.service = service
	s.serviceMu.Unlock()
}

// ReCreateServer retains the existing caller contract; ownership-sensitive
// callers can use ReCreateServerWithError to observe bind/readiness failures.
func ReCreateServer(addr string, lc C.InboundListenConfig, service resolver.Service) {
	if err := ReCreateServerWithError(addr, lc, service); err != nil {
		log.Errorln("Start DNS server error: %s", err)
	}
}

func ReCreateServerWithError(addr string, lc C.InboundListenConfig, service resolver.Service) error {
	listenerMu.Lock()
	defer listenerMu.Unlock()
	desiredAddress, desiredListenConfig, desiredService = addr, lc, service
	if addr == "" || lc == nil || service == nil {
		desiredAddress, desiredListenConfig, desiredService = "", nil, nil
		stopServerLocked()
		return nil
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		stopServerLocked()
		return err
	}
	// Keep the established disabled-listener convention for zero/empty ports.
	if port == "0" || port == "" {
		desiredAddress, desiredListenConfig, desiredService = "", nil, nil
		stopServerLocked()
		return nil
	}
	if listenerSuspended {
		stopServerLocked()
		return nil
	}
	return startServerLocked()
}

// ReplaceServerWithError admits a configuration only after listener readiness.
// Unlike a retryable recreate/resume, failure preserves the active generation
// and all prior desired intent. Suspended admission remains socket-free.
func ReplaceServerWithError(addr string, lc C.InboundListenConfig, service resolver.Service) error {
	listenerMu.Lock()
	defer listenerMu.Unlock()
	if addr != "" && lc != nil && service != nil {
		_, port, err := net.SplitHostPort(addr)
		if err != nil {
			return err
		}
		if port == "0" || port == "" {
			addr, lc, service = "", nil, nil
		}
	} else {
		addr, lc, service = "", nil, nil
	}
	if listenerSuspended || addr == "" {
		desiredAddress, desiredListenConfig, desiredService = addr, lc, service
		stopServerLocked()
		return nil
	}
	if address == addr && runAlive(server.tcpRun) && runAlive(server.udpRun) {
		desiredAddress, desiredListenConfig, desiredService = addr, lc, service
		server.SetService(service)
		return nil
	}
	// Do not retire the old listener or publish candidate intent on a failed
	// UDP/TCP bind or readiness check. A prepared generation is independent.
	next, err := newServer(addr, lc, service)
	if err != nil {
		return err
	}
	old := server
	desiredAddress, desiredListenConfig, desiredService = addr, lc, service
	server, address = next, addr
	stopGeneration(old)
	return nil
}

// SuspendServer relinquishes sockets while retaining resolver/listener intent.
// All subsequent recreates remain socket-free until ResumeServer is called.
func SuspendServer() error {
	listenerMu.Lock()
	defer listenerMu.Unlock()
	listenerSuspended = true
	stopServerLocked()
	return nil
}

// ResumeServer reports success only after the current desired listener is ready.
// A failed resume remains retryable, including at the identical address.
func ResumeServer() error {
	listenerMu.Lock()
	defer listenerMu.Unlock()
	listenerSuspended = false
	return startServerLocked()
}

// EnsureServer verifies readiness without changing the ownership gate. Setup
// callers use it to avoid acknowledging a configuration whose bind failed.
func EnsureServer() error {
	listenerMu.Lock()
	defer listenerMu.Unlock()
	if listenerSuspended {
		return nil
	}
	return startServerLocked()
}

// StopServer clears listener intent, not the process-local ownership gate.
// It deliberately leaves resolver.DefaultService and its policy untouched.
func StopServer() {
	listenerMu.Lock()
	defer listenerMu.Unlock()
	desiredAddress, desiredListenConfig, desiredService = "", nil, nil
	stopServerLocked()
}

func runAlive(run *dnsServerRun) bool {
	if run == nil {
		return false
	}
	select {
	case <-run.done:
		return false
	default:
		return true
	}
}

func startDNSRun(srv *D.Server) (*dnsServerRun, error) {
	run := &dnsServerRun{done: make(chan struct{})}
	ready := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(ready) }
	go func() { run.err = srv.ActivateAndServe(); close(run.done) }()
	select {
	case <-ready:
		return run, nil
	case <-run.done:
		if run.err == nil {
			return run, errors.New("DNS server stopped before readiness")
		}
		return run, run.err
	}
}

func startServerLocked() error {
	if desiredAddress == "" || desiredListenConfig == nil || desiredService == nil {
		stopServerLocked()
		return nil
	}
	if address == desiredAddress && runAlive(server.tcpRun) && runAlive(server.udpRun) {
		server.SetService(desiredService)
		return nil
	}
	stopServerLocked()
	s, err := newServer(desiredAddress, desiredListenConfig, desiredService)
	if err != nil {
		return err
	}
	server, address = s, desiredAddress
	return nil
}

// newServer prepares a ready, independent generation without publishing it.
func newServer(addr string, lc C.InboundListenConfig, service resolver.Service) (*Server, error) {
	p, err := lc.ListenPacket(context.Background(), "udp", addr)
	if err != nil {
		return nil, fmt.Errorf("DNS UDP bind: %w", err)
	}
	l, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		_ = p.Close()
		return nil, fmt.Errorf("DNS TCP bind: %w", err)
	}
	if err := sockopt.UDPReuseaddr(p); err != nil {
		log.Warnln("Failed to Reuse UDP Address: %s", err)
	}
	s := &Server{service: service}
	s.udpServer = &D.Server{Addr: addr, PacketConn: p, Handler: s.UDPHandler()}
	s.tcpServer = &D.Server{Addr: addr, Listener: l, Handler: s.TCPHandler()}
	s.udpRun, err = startDNSRun(s.udpServer)
	if err == nil {
		s.tcpRun, err = startDNSRun(s.tcpServer)
	}
	if err != nil {
		stopGeneration(s)
		_ = p.Close()
		_ = l.Close()
		return nil, err
	}
	log.Infoln("DNS server(TCP/UDP) listening at: %s", addr)
	return s, nil
}

func stopServerLocked() {
	s := server
	server, address = &Server{}, ""
	stopGeneration(s)
}

func stopGeneration(s *Server) {
	// ShutdownContext marks the serve loop stopped before waiting for handlers.
	// Bound only the drain, never change active resolver request budgets. Explicit
	// socket closure also covers a generation whose ActivateAndServe failed early.
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	var wg sync.WaitGroup
	for _, srv := range []*D.Server{s.tcpServer, s.udpServer} {
		if srv == nil {
			continue
		}
		wg.Add(1)
		go func(srv *D.Server) { defer wg.Done(); _ = srv.ShutdownContext(ctx) }(srv)
	}
	wg.Wait()
	if s.tcpServer != nil && s.tcpServer.Listener != nil {
		_ = s.tcpServer.Listener.Close()
	}
	if s.udpServer != nil && s.udpServer.PacketConn != nil {
		_ = s.udpServer.PacketConn.Close()
	}
	s.SetService(nil)
}
