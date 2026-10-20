package snell

import (
	"bytes"
	"encoding/json"
	"io"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func streamProcessCPU(t *testing.T) uint64 {
	t.Helper()
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &creation, &exit, &kernel, &user); err != nil {
		t.Fatal(err)
	}
	return (uint64(kernel.HighDateTime)<<32 | uint64(kernel.LowDateTime)) + (uint64(user.HighDateTime)<<32 | uint64(user.LowDateTime))
}
func TestV4StreamCPUFixedLoad(t *testing.T) {
	const iterations = 65536
	p := make([]byte, 32768)
	for _, mode := range []string{"write", "read"} {
		t.Run(mode, func(t *testing.T) {
			w := streamWriter(t, io.Discard)
			_, _ = w.Write(p)
			var wire bytes.Buffer
			sourceWriter := streamWriter(t, &wire)
			_, _ = sourceWriter.Write(p)
			frame := append([]byte(nil), wire.Bytes()...)
			src := bytes.NewReader(frame)
			r := &v4Reader{Reader: src, aead: sourceWriter.aead}
			_, _ = io.ReadFull(r, p)
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			cpu := streamProcessCPU(t)
			start := time.Now()
			for i := 0; i < iterations; i++ {
				if mode == "write" {
					if _, err := w.Write(p); err != nil {
						t.Fatal(err)
					}
				} else {
					src.Reset(frame)
					r.nonce = [v4NonceSize]byte{}
					if _, err := io.ReadFull(r, p); err != nil {
						t.Fatal(err)
					}
				}
			}
			elapsed := time.Since(start).Seconds()
			cpuSeconds := float64(streamProcessCPU(t)-cpu) / 1e7
			runtime.ReadMemStats(&after)
			result := map[string]any{"mode": mode, "iterations": iterations, "payload_bytes_per_op": len(p), "payload_bytes": uint64(iterations) * uint64(len(p)), "wall_seconds": elapsed, "process_cpu_seconds": cpuSeconds, "total_alloc_bytes": after.TotalAlloc - before.TotalAlloc, "mallocs": after.Mallocs - before.Mallocs, "gc_cycles": after.NumGC - before.NumGC}
			data, _ := json.Marshal(result)
			t.Logf("STREAM_CPU %s", data)
		})
	}
}
