//go:build with_low_memory

package provider

// The iOS Network Extension has a hard ~50 MB phys_footprint budget (jetsam kills
// above it). Building a rule set's matcher is not proportional to its steady-state
// size: domainStrategy fills a DomainTrie with every entry, then NewDomainSet()
// materialises one reversed string per entry and sorts that slice before
// collapsing it into the succinct set. Measured on the real subscription cache
// (2026-08-30, GOMEMLIMIT as shipped):
//
//	provider         rules    transient peak   settled
//	BanAD          187,945       ~195 MB        4.5 MB
//	ChinaClassical 111,321        ~72 MB        1.2 MB
//	ProxyClassical  27,070        ~26 MB        0.5 MB
//	ChinaCIDR        9,651        ~12 MB        0.4 MB
//
// The peak is limit-independent: GOMEMLIMIT is a soft target, so Go overshoots it
// rather than failing the allocation. At 24/32/48 MB budgets BanAD still peaked
// at 199/190/199 MB. That single spike is what jetsam kills the extension on,
// one second after "Initial configuration complete".
//
// So the extension refuses to build oversized matchers at all. The app-process
// core keeps full fidelity (see the !with_low_memory variant): only the code
// inside the packet tunnel is constrained.
//
// 10,000 is chosen from the table above: it keeps ChinaCIDR (9,651, ~12 MB peak,
// needed for China direct routing) and rejects the three lists that account for
// 7.8 MB of the 10.7 MB steady-state total and every spike above 26 MB. The
// device's own baseline with a live tunnel is ~13 MB against a ~48 MB death line,
// so a ~12 MB worst-case transient is the most that fits.
const maxLowMemoryRuleCount = 10000
