package provider

import (
	"bytes"
	"os"

	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
)

// Two-sided fix for the iOS Network Extension's ~50 MB footprint budget.
//
// The cost of a rule set is not in holding it, it is in BUILDING the matcher:
// domainStrategy.FinishInsert -> NewDomainSet materialises every domain reversed
// into a []string and sorts it. Measured on the real subscription lists, BanAD
// (187,945 domains, 5.2 MB of text) peaks at ~190 MB doing this, and the peak is
// independent of GOMEMLIMIT because that limit is a soft target: Go overshoots it
// rather than failing an allocation.
//
// The MRS format stores the FINISHED succinct bitmap instead, so loading it is
// three slice reads with no trie and no sort. Measured on the same lists:
//
//	                 rules      raw     mrs   trie build   mrs load
//	BanAD          187,945   5.2 MB  1.8 MB     ~190 MB     18.3 MB
//	ChinaClassical 111,321   2.2 MB  0.5 MB      ~72 MB     13.2 MB
//	ProxyClassical  27,070   0.6 MB  0.2 MB      ~26 MB     10.9 MB
//
// So the split is: whichever side has memory to spare pays the trie cost once and
// writes an MRS sidecar next to the cache file; the extension loads the sidecar.
// No rules are dropped, which is what the rule-count budget alone would have
// cost (ad blocking and domain routing both live in those big lists).
//
// The sidecar is content-addressed by the cache file it was built from: the
// extension only trusts a sidecar that is at least as new as its source, so a
// refreshed rule set is never matched against a stale bitmap.

// sidecarMinRules is the size above which a sidecar is worth writing. Below it
// the trie build is cheap enough that the extra file is not worth the bytes.
const sidecarMinRules = 5000

func sidecarPath(vehiclePath string) string {
	return vehiclePath + ".mrs"
}

// sidecarUsable reports whether a sidecar exists and is not older than the raw
// rule file it was derived from.
func sidecarUsable(vehiclePath string) (string, bool) {
	path := sidecarPath(vehiclePath)
	sc, err := os.Stat(path)
	if err != nil {
		return "", false
	}
	src, err := os.Stat(vehiclePath)
	if err == nil && sc.ModTime().Before(src.ModTime()) {
		// Raw list was refreshed after the sidecar was built: the bitmap no
		// longer describes it. Matching against stale rules is worse than
		// paying the build cost, so refuse it.
		return "", false
	}
	return path, true
}

// loadFromSidecar builds a strategy from the pre-computed MRS bitmap.
func loadFromSidecar(path string, behavior P.RuleBehavior) (ruleStrategy, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return rulesMrsParse(buf, newStrategy(behavior, nil))
}

// writeSidecar persists an already-built strategy as MRS so a memory-constrained
// build can skip the trie construction next time. Best effort: a failure here
// only means the constrained side has to fall back, so it is logged and ignored.
//
// Only called on builds that are not memory constrained (maxLowMemoryRuleCount
// == 0), which is where the strategy has just been built anyway.
func writeSidecar(vehiclePath string, behavior P.RuleBehavior, strategy ruleStrategy) {
	mrsStrategy, ok := strategy.(mrsRuleStrategy)
	if !ok {
		// classical behavior has no MRS representation; those lists are small
		// (largest observed 2,265 rules / ~3 MB peak) so they need no sidecar.
		return
	}
	if strategy.Count() < sidecarMinRules {
		return
	}

	var buf bytes.Buffer
	if err := WriteMrsFromStrategy(&buf, behavior, mrsStrategy); err != nil {
		log.Warnln("[Provider] build mrs sidecar for %s: %v", vehiclePath, err)
		return
	}

	path := sidecarPath(vehiclePath)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, buf.Bytes(), 0o644); err != nil {
		log.Warnln("[Provider] write mrs sidecar %s: %v", path, err)
		return
	}
	// Rename so a reader never sees a half-written bitmap.
	if err := os.Rename(tmp, path); err != nil {
		log.Warnln("[Provider] rename mrs sidecar %s: %v", path, err)
		_ = os.Remove(tmp)
		return
	}
	log.Infoln("[Provider] wrote MRS sidecar for %s (%d rules, %d bytes)",
		vehiclePath, strategy.Count(), buf.Len())
}
