//go:build !with_low_memory

package mmdb

// Everywhere else the ASN database is a normal optional feature and mapping it
// is exactly what the caller asked for.
const asnMappingAllowed = true
