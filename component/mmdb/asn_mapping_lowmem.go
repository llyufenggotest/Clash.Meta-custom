//go:build with_low_memory

package mmdb

// Low-memory builds never enable ASN rules (see geodata.InitASN, which stores
// asnEnable=false and returns nil). Mapping the database would therefore buy
// nothing while costing the whole file: maxminddb opens it with mmap, and on
// iOS file-backed pages count against the extension's phys_footprint budget.
const asnMappingAllowed = false
