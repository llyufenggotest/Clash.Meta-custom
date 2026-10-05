//go:build !with_low_memory

package config

// Desktop and regular mobile builds keep upstream behaviour untouched: the user's
// rules decide everything, and platform routing (fwmark / routing-mark / the
// per-socket bind mihomo does natively) already keeps proxy dials out of the
// tunnel.
const proxyServerBypassEnabled = false
