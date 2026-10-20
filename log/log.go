package log

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	"github.com/metacubex/mihomo/common/observable"

	log "github.com/sirupsen/logrus"
)

var (
	logCh         = make(chan Event)
	source        = observable.NewObservable[Event](logCh)
	level         atomic.Int64
	subscribers   atomic.Int64
	subscriptions sync.Map // observable.Subscription[Event] -> struct{}
)

func init() {
	SetLevel(INFO)
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:             true,
		TimestampFormat:           "2006-01-02T15:04:05.000000000Z07:00",
		EnvironmentOverrideColors: true,
	})
}

type Event struct {
	LogLevel LogLevel
	Payload  string
}

func (e *Event) Type() string {
	return e.LogLevel.String()
}

func Infoln(format string, v ...any) {
	logln(INFO, format, v...)
}

func Warnln(format string, v ...any) {
	logln(WARNING, format, v...)
}

func Errorln(format string, v ...any) {
	logln(ERROR, format, v...)
}

func Debugln(format string, v ...any) {
	logln(DEBUG, format, v...)
}

func logln(logLevel LogLevel, format string, v ...any) {
	// Level filters console output only: subscribers filter independently.
	// Skip work only when neither can observe this call. Concurrent changes
	// may take effect after this check, just as after an ordinary log call.
	if logLevel < Level() && subscribers.Load() == 0 {
		return
	}
	event := newLog(logLevel, format, v...)
	logCh <- event
	print(event)
}

func Fatalln(format string, v ...any) {
	log.Fatalf(format, v...)
}

func Subscribe() observable.Subscription[Event] {
	// Count before registration, uncount only after removal: transitions may
	// cause extra publication, never an active listener undercount.
	subscribers.Add(1)
	sub, err := source.Subscribe()
	if err != nil {
		subscribers.Add(-1)
		return nil
	}
	subscriptions.Store(sub, struct{}{})
	return sub
}

func UnSubscribe(sub observable.Subscription[Event]) {
	// Preserve the observable's synchronous removal even for concurrent or
	// repeated cancellation; decrement at most once, after removal completes.
	source.UnSubscribe(sub)
	if _, loaded := subscriptions.LoadAndDelete(sub); loaded {
		subscribers.Add(-1)
	}
}

func Level() LogLevel {
	return LogLevel(level.Load())
}

func SetLevel(newLevel LogLevel) {
	level.Store(int64(newLevel))
}

func print(data Event) {
	if data.LogLevel < Level() {
		return
	}

	switch data.LogLevel {
	case INFO:
		log.Infoln(data.Payload)
	case WARNING:
		log.Warnln(data.Payload)
	case ERROR:
		log.Errorln(data.Payload)
	case DEBUG:
		log.Debugln(data.Payload)
	}
}

func newLog(logLevel LogLevel, format string, v ...any) Event {
	return Event{
		LogLevel: logLevel,
		Payload:  fmt.Sprintf(format, v...),
	}
}
