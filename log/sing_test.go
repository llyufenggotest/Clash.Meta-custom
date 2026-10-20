package log

import (
	"context"
	"fmt"

	"testing"

	logrus "github.com/sirupsen/logrus"
)

type singTypedValue int

func (v singTypedValue) String() string { return fmt.Sprintf("typed:%d%%", int(v)) }

func singMessages() [][]any {
	return [][]any{nil, {"100% %s %d %%"}, {"first\n", singTypedValue(7), " ", 42, true, "\nlast"}, {12, 34, singTypedValue(5)}}
}

func TestSingAdapterPreservesLiteralTextAndTypedArgs(t *testing.T) {
	output := logState(t)
	SetLevel(DEBUG)
	ctx := context.Background()
	l, remap := singLogger{}, singInfoToDebugLogger{}
	methods := []struct {
		name  string
		level LogLevel
		call  func(...any)
	}{
		{"Trace", DEBUG, l.Trace}, {"Debug", DEBUG, l.Debug}, {"Info", INFO, l.Info}, {"Warn", WARNING, l.Warn}, {"Error", ERROR, l.Error},
		{"TraceContext", DEBUG, func(a ...any) { l.TraceContext(ctx, a...) }},
		{"DebugContext", DEBUG, func(a ...any) { l.DebugContext(ctx, a...) }},
		{"InfoContext", INFO, func(a ...any) { l.InfoContext(ctx, a...) }},
		{"WarnContext", WARNING, func(a ...any) { l.WarnContext(ctx, a...) }},
		{"ErrorContext", ERROR, func(a ...any) { l.ErrorContext(ctx, a...) }},
		{"RemapInfo", DEBUG, remap.Info}, {"RemapInfoContext", DEBUG, func(a ...any) { remap.InfoContext(ctx, a...) }},
	}
	// Message-only formatter exposes exact console bytes, including newlines.
	logger := logrus.StandardLogger()
	oldFormatter := logger.Formatter
	logger.SetFormatter(singMessageFormatter{})
	defer logger.SetFormatter(oldFormatter)
	sub := Subscribe()
	defer UnSubscribe(sub)
	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			for _, args := range singMessages() {
				output.Reset()
				m.call(args...)
				want := fmt.Sprint(args...)
				got := receive(t, sub)
				if got.LogLevel != m.level || got.Payload != want || output.String() != want {
					t.Fatalf("args=%#v event=%+v console=%q want=%q", args, got, output.String(), want)
				}
			}
		})
	}
}

type singMessageFormatter struct{}

func (singMessageFormatter) Format(e *logrus.Entry) ([]byte, error) { return []byte(e.Message), nil }

func TestSingFatalAndPanicKeepFatalExitWithoutPublication(t *testing.T) {
	output := logState(t)
	SetLevel(SILENT)
	logger := logrus.StandardLogger()
	oldExit, oldFormatter := logger.ExitFunc, logger.Formatter
	defer func() { logger.ExitFunc = oldExit; logger.SetFormatter(oldFormatter) }()
	logger.SetFormatter(singMessageFormatter{})
	ctx := context.Background()
	l := singLogger{}
	methods := []struct {
		name string
		call func(...any)
	}{
		{"Fatal", l.Fatal}, {"Panic", l.Panic},
		{"FatalContext", func(a ...any) { l.FatalContext(ctx, a...) }},
		{"PanicContext", func(a ...any) { l.PanicContext(ctx, a...) }},
	}
	sub := Subscribe()
	defer UnSubscribe(sub)
	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			for _, args := range singMessages() {
				output.Reset()
				var exits []int
				logger.ExitFunc = func(code int) { exits = append(exits, code) }
				m.call(args...)
				if len(exits) != 1 || exits[0] != 1 || output.String() != fmt.Sprint(args...) {
					t.Fatalf("exits=%v output=%q want=%q", exits, output.String(), fmt.Sprint(args...))
				}
				Debugln("sing fatal barrier")
				if got := receive(t, sub); got.Payload != "sing fatal barrier" {
					t.Fatalf("fatal published event: %+v", got)
				}
			}
		})
	}
}
