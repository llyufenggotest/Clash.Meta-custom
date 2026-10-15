package resource

import (
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/fstest"
	"time"
)

func TestInitialFetchOwnerAndSingleUse(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "rules") }))
	defer s.Close()
	makeFetcher := func(name string) *Fetcher[string] {
		return NewFetcher(name, 0, NewHTTPVehicle(s.URL, filepath.Join(t.TempDir(), name), "", nil, time.Second, 0), nil, func(b []byte) (string, error) { return string(b), nil }, nil)
	}
	a, b := makeFetcher("a"), makeFetcher("b")
	defer a.Close()
	defer b.Close()
	token, err := a.FetchInitial()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.InitialFromFetch(token); err == nil {
		t.Fatal("foreign fetch token accepted")
	}
	if got, err := a.InitialFromFetch(token); err != nil || got != "rules" {
		t.Fatalf("owner consume=%q, %v", got, err)
	}
	if _, err = a.InitialFromFetch(token); err == nil {
		t.Fatal("fetch token replay accepted")
	}
}

func TestInitialPrefetchFallbackCompatibility(t *testing.T) {
	for _, mode := range []string{"cache", "bundle", "bad-cache-remote", "bad-bundle-remote"} {
		t.Run(mode, func(t *testing.T) {
			var hits atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); _, _ = io.WriteString(w, "remote") }))
			defer s.Close()
			path := filepath.Join(t.TempDir(), "rules")
			var bundle BundleFile
			want := "remote"
			switch mode {
			case "cache":
				_ = os.WriteFile(path, []byte("cached"), 0600)
				want = "cached"
			case "bad-cache-remote":
				_ = os.WriteFile(path, []byte("bad"), 0600)
			case "bundle":
				want = "bundled"
				fallthrough
			case "bad-bundle-remote":
				content := "bundled"
				if mode == "bad-bundle-remote" {
					content = "bad"
				}
				files := fstest.MapFS{"rules": &fstest.MapFile{Data: []byte(content)}}
				bundle = func() (fs.File, error) { return files.Open("rules") }
			}
			f := NewFetcher(mode, 0, NewHTTPVehicle(s.URL, path, "", nil, time.Second, 0), bundle, func(b []byte) (string, error) {
				if string(b) == "bad" {
					return "", fmt.Errorf("invalid")
				}
				return string(b), nil
			}, nil)
			defer f.Close()
			token, err := f.FetchInitial()
			if err != nil {
				t.Fatal(err)
			}
			if hits.Load() != 0 {
				t.Fatal("prefetch bypassed cache or bundle fallback")
			}
			got, err := f.InitialFromFetch(token)
			if err != nil || got != want {
				t.Fatalf("got %q, %v; want %q", got, err, want)
			}
			var expected int32
			if want == "remote" {
				expected = 1
			}
			if hits.Load() != expected {
				t.Fatalf("hits=%d want %d", hits.Load(), expected)
			}
		})
	}
}

func TestInitialFetchCloseRejectsPublication(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "rules") }))
	defer s.Close()
	parsed := false
	f := NewFetcher("closed", 0, NewHTTPVehicle(s.URL, filepath.Join(t.TempDir(), "rules"), "", nil, time.Second, 0), nil, func(b []byte) (string, error) { parsed = true; return string(b), nil }, nil)
	token, err := f.FetchInitial()
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	if _, err = f.InitialFromFetch(token); err == nil {
		t.Fatal("closed owner accepted token")
	}
	if parsed {
		t.Fatal("closed owner entered parser")
	}
}
