package outbound

import "testing"

func TestVlessSLMarkerIsNotSpecial(t *testing.T) {
	option := VlessOption{
		Name:       "ordinary sl suffix",
		Server:     "127.0.0.1",
		Port:       443,
		UUID:       "00000000-0000-0000-0000-000000000000#sl",
		TLS:        true,
		ServerName: "original.example",
	}
	proxy, err := NewVless(option)
	if err != nil {
		t.Fatalf("ordinary #sl text must not activate a special protocol path: %v", err)
	}
	defer proxy.Close()
	if proxy.option.UUID != option.UUID {
		t.Fatalf("#sl was unexpectedly stripped: got %q", proxy.option.UUID)
	}
	if proxy.option.ServerName != option.ServerName {
		t.Fatalf("#sl unexpectedly changed SNI: got %q", proxy.option.ServerName)
	}
}

func TestVlessX365MarkerRemainsSupported(t *testing.T) {
	option := VlessOption{
		Name:   "x365 fixture",
		Server: "127.0.0.1",
		Port:   443,
		UUID:   "00000000-0000-0000-0000-000000000000#x365",
	}
	proxy, err := NewVless(option)
	if err != nil {
		t.Fatalf("#x365 marker must remain supported: %v", err)
	}
	defer proxy.Close()
}
