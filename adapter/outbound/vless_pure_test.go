package outbound

import "testing"

func pureOption() VlessOption {
	return VlessOption{
		UUID:    "00112233-4455-6677-8899-aabbccddeeff#PuRe",
		TLS:     true,
		Network: "ws",
	}
}

func TestConfigurePureVlessCanonicalizesTransport(t *testing.T) {
	o := pureOption()
	enabled, err := configurePureVless(&o)
	if err != nil || !enabled {
		t.Fatalf("enabled=%v err=%v", enabled, err)
	}
	if len(o.ALPN) != 1 || o.ALPN[0] != "http/1.1" || o.WSOpts.Path != "/websocket" {
		t.Fatalf("not canonicalized: %#v", o)
	}
}

func TestNewPureVlessKeepsXUDPDisabled(t *testing.T) {
	o := pureOption()
	o.Name = "pure"
	o.Server = "example.com"
	o.Port = 443
	v, err := NewVless(o)
	if err != nil {
		t.Fatal(err)
	}
	if v.option.XUDP || v.option.PacketAddr || v.SupportUDP() {
		t.Fatalf("Pure packet modes enabled: option=%#v", v.option)
	}
}

func TestConfigurePureVlessRejectsUnsupportedCombinations(t *testing.T) {
	cases := map[string]func(*VlessOption){
		"udp":        func(o *VlessOption) { o.UDP = true },
		"xudp":       func(o *VlessOption) { o.XUDP = true },
		"flow":       func(o *VlessOption) { o.Flow = "xtls-rprx-vision" },
		"encryption": func(o *VlessOption) { o.Encryption = "mlkem" },
		"no tls":     func(o *VlessOption) { o.TLS = false },
		"not ws":     func(o *VlessOption) { o.Network = "tcp" },
		"utls":       func(o *VlessOption) { o.ClientFingerprint = "chrome" },
		"ech":        func(o *VlessOption) { o.ECHOpts.Enable = true },
		"reality":    func(o *VlessOption) { o.RealityOpts.PublicKey = "x" },
		"early data": func(o *VlessOption) { o.WSOpts.MaxEarlyData = 1 },
		"headers":    func(o *VlessOption) { o.WSOpts.Headers = map[string]string{"Host": "x"} },
		"path":       func(o *VlessOption) { o.WSOpts.Path = "/custom" },
		"alpn":       func(o *VlessOption) { o.ALPN = []string{"h2"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			o := pureOption()
			mutate(&o)
			if _, err := configurePureVless(&o); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}
