//go:build with_low_memory

package config

// The low-memory core is the one embedded in the iOS Network Extension, i.e. the
// core that receives traffic captured from the TUN device. That is exactly where
// a proxy-server-addressed packet must be forced DIRECT, because re-dialling it
// through a proxy is a routing loop.
const proxyServerBypassEnabled = true
