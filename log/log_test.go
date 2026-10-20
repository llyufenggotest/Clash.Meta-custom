package log

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/common/observable"
	logrus "github.com/sirupsen/logrus"
)

type countedString struct{ calls atomic.Int64 }

func (s *countedString) String() string { s.calls.Add(1); return "payload" }

func logState(t *testing.T) *bytes.Buffer {
	t.Helper()
	oldLevel, oldOutput := Level(), logrus.StandardLogger().Out
	var output bytes.Buffer
	logrus.SetOutput(&output)
	t.Cleanup(func() { SetLevel(oldLevel); logrus.SetOutput(oldOutput) })
	return &output
}

func receive(t *testing.T, sub observable.Subscription[Event]) Event {
	t.Helper()
	select {
	case event, ok := <-sub:
		if !ok {
			t.Fatal("subscription closed early")
		}
		return event
	case <-time.After(3 * time.Second):
		t.Fatal("event delivery timed out")
		return Event{}
	}
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("logger did not complete")
	}
}

// Synchronize with the production observable, whose unbuffered input send
// completes before fanout does. Do not let pending no-observer events leak
// into the next test's subscription.
func settle(t *testing.T) {
	t.Helper()
	sub := Subscribe()
	defer UnSubscribe(sub)
	Debugln("test barrier")
	for receive(t, sub).Payload != "test barrier" {
	}
}

func TestSuppressedNoObserverDoesNotFormat(t *testing.T) {
	logState(t)
	SetLevel(WARNING)
	value := new(countedString)
	Debugln("suppressed %s", value)
	settle(t)
	if got := value.calls.Load(); got != 0 {
		t.Fatalf("suppressed no-observer log formatted %d times, want 0", got)
	}
}

func TestConsoleLevelsWithoutSubscribers(t *testing.T) {
	output := logState(t)
	methods := []struct {
		level LogLevel
		call  func(string, ...any)
	}{{DEBUG, Debugln}, {INFO, Infoln}, {WARNING, Warnln}, {ERROR, Errorln}}
	for _, threshold := range []LogLevel{DEBUG, INFO, WARNING, ERROR, SILENT} {
		for _, method := range methods {
			t.Run(threshold.String()+"/"+method.level.String(), func(t *testing.T) {
				SetLevel(threshold)
				output.Reset()
				method.call("console %s", "payload")
				got := strings.Contains(output.String(), "console payload")
				if want := method.level >= threshold; got != want {
					t.Fatalf("console present=%v want=%v: %q", got, want, output.String())
				}
				settle(t)
			})
		}
	}
}

func TestSubscriberReceivesAllLevelsRegardlessOfConsole(t *testing.T) {
	logState(t)
	for _, threshold := range []LogLevel{DEBUG, INFO, WARNING, ERROR, SILENT} {
		t.Run(threshold.String(), func(t *testing.T) {
			SetLevel(threshold)
			first, second := Subscribe(), Subscribe()
			defer UnSubscribe(first)
			defer UnSubscribe(second)
			for _, method := range []struct {
				level LogLevel
				call  func(string, ...any)
			}{{DEBUG, Debugln}, {INFO, Infoln}, {WARNING, Warnln}, {ERROR, Errorln}} {
				method.call("event %d", method.level)
				for _, sub := range []observable.Subscription[Event]{first, second} {
					got := receive(t, sub)
					if got.LogLevel != method.level || got.Payload != fmt.Sprintf("event %d", method.level) {
						t.Fatalf("unexpected event: %+v", got)
					}
				}
			}
		})
	}
}

func TestSubscriberLocalFiltersAndOrder(t *testing.T) {
	logState(t)
	SetLevel(SILENT)
	debug, info := Subscribe(), Subscribe()
	defer UnSubscribe(debug)
	defer UnSubscribe(info)
	Debugln("debug 1")
	Infoln("info 2")
	Warnln("warn 3")
	Errorln("error 4")
	var all, filtered []string
	for i := 0; i < 4; i++ {
		all = append(all, receive(t, debug).Payload)
		event := receive(t, info)
		if event.LogLevel >= INFO {
			filtered = append(filtered, event.Payload)
		}
	}
	if strings.Join(all, ",") != "debug 1,info 2,warn 3,error 4" || strings.Join(filtered, ",") != "info 2,warn 3,error 4" {
		t.Fatalf("all=%v filtered=%v", all, filtered)
	}
}

func TestSuppressedSubscriberPreservesBackpressure(t *testing.T) {
	logState(t)
	SetLevel(WARNING)
	sub := Subscribe()
	defer UnSubscribe(sub)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 203; i++ {
			Debugln("event %d", i)
		}
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("undrained subscriber must retain lossless backpressure")
	case <-time.After(30 * time.Millisecond):
	}
	for i := 0; i < 203; i++ {
		if got := receive(t, sub).Payload; got != fmt.Sprintf("event %d", i) {
			t.Fatalf("event %d: %q", i, got)
		}
	}
	waitDone(t, done)
}

func TestUnsubscribeAndRepeatedCancel(t *testing.T) {
	logState(t)
	SetLevel(SILENT)
	sub := Subscribe()
	UnSubscribe(sub)
	UnSubscribe(sub)
	UnSubscribe(nil)
	if _, ok := <-sub; ok {
		t.Fatal("subscription remains open")
	}
	value := new(countedString)
	Debugln("%s", value)
	settle(t)
	if value.calls.Load() != 0 {
		t.Fatal("cancelled subscription still forces formatting")
	}
}

func TestConcurrentLevelsAndSubscriptionLifecycle(t *testing.T) {
	logState(t)
	logrus.SetOutput(io.Discard)
	stable := Subscribe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range stable {
		}
	}()
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			SetLevel(LogLevel(i % 5))
			_ = Level()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			Debugln("debug %d", i)
			Infoln("info %d", i)
			Warnln("warn %d", i)
			Errorln("error %d", i)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			sub := Subscribe()
			drained := make(chan struct{})
			go func() {
				defer close(drained)
				for range sub {
				}
			}()
			UnSubscribe(sub)
			UnSubscribe(sub)
			<-drained
		}
	}()
	complete := make(chan struct{})
	go func() { wg.Wait(); close(complete) }()
	waitDone(t, complete)
	UnSubscribe(stable)
	waitDone(t, done)
	SetLevel(SILENT)
	value := new(countedString)
	Debugln("%s", value)
	settle(t)
	if value.calls.Load() != 0 {
		t.Fatal("subscriber count leaked after concurrent cancellation")
	}
}

func TestLevelChangesApplyToNextCall(t *testing.T) {
	output := logState(t)
	for _, threshold := range []LogLevel{SILENT, DEBUG, INFO, WARNING, ERROR, DEBUG} {
		SetLevel(threshold)
		if Level() != threshold {
			t.Fatal("level did not update")
		}
		output.Reset()
		Debugln("changed level")
		if strings.Contains(output.String(), "changed level") != (threshold == DEBUG) {
			t.Fatal("stale console level")
		}
		settle(t)
	}
}

func TestFatalStillBypassesConsoleThresholdAndDoesNotPublish(t *testing.T) {
	output := logState(t)
	SetLevel(SILENT)
	logger := logrus.StandardLogger()
	oldExit := logger.ExitFunc
	defer func() { logger.ExitFunc = oldExit }()
	code := 0
	logger.ExitFunc = func(got int) { code = got }
	sub := Subscribe()
	defer UnSubscribe(sub)
	Fatalln("fatal %s", "payload")
	if code != 1 || !strings.Contains(output.String(), "fatal payload") {
		t.Fatalf("exit=%d output=%q", code, output.String())
	}
	Debugln("fatal barrier")
	if got := receive(t, sub); got.Payload != "fatal barrier" {
		t.Fatalf("fatal unexpectedly published: %+v", got)
	}
}

func TestConcurrentCancelWaitsForRemoval(t *testing.T) {
	logState(t)
	SetLevel(SILENT)
	sub := Subscribe()
	done := make(chan struct{})
	go func() {
		for i := 0; i < 203; i++ {
			Debugln("event %d", i)
		}
		close(done)
	}()
	// A full buffer plus a blocked producer means fanout owns its mutex.
	deadline := time.After(3 * time.Second)
	for len(sub) != cap(sub) {
		select {
		case <-deadline:
			t.Fatal("subscriber never filled")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	first, second := make(chan struct{}), make(chan struct{})
	go func() { UnSubscribe(sub); close(first) }()
	time.Sleep(10 * time.Millisecond)
	go func() { UnSubscribe(sub); close(second) }()
	premature := false
	select {
	case <-second:
		premature = true
	case <-time.After(20 * time.Millisecond):
	}
	// Keep draining until removal closes the subscription, including when the
	// assertion fails: preserving backpressure is intentional, not a leak.
	drained := make(chan struct{})
	go func() {
		for range sub {
		}
		close(drained)
	}()
	waitDone(t, first)
	waitDone(t, second)
	waitDone(t, done)
	waitDone(t, drained)
	if premature {
		t.Fatal("concurrent UnSubscribe returned before removal completed")
	}
}

func BenchmarkSuppressedDebug(b *testing.B) {
	old := Level()
	SetLevel(WARNING)
	defer SetLevel(old)
	b.Run("NoObserver", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			Debugln("suppressed audit %d", i)
		}
	})
	b.Run("DrainedObserver", func(b *testing.B) {
		sub := Subscribe()
		done := make(chan struct{})
		go func() {
			defer close(done)
			for range sub {
			}
		}()
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			Debugln("suppressed audit %d", i)
		}
		b.StopTimer()
		UnSubscribe(sub)
		<-done
	})
}
