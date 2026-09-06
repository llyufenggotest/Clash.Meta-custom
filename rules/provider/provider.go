package provider

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/pool"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/resource"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/rules/common"
)

var tunnel P.Tunnel

func SetTunnel(t P.Tunnel) {
	tunnel = t
}

type RulePayload struct {
	/**
	key: Domain or IP Cidr
	value: Rule type or is empty
	*/
	Payload []string `yaml:"payload"`
	Rules   []string `yaml:"rules"`
}

type providerForApi struct {
	Behavior    string    `json:"behavior"`
	Format      string    `json:"format"`
	Name        string    `json:"name"`
	RuleCount   int       `json:"ruleCount"`
	Type        string    `json:"type"`
	VehicleType string    `json:"vehicleType"`
	UpdatedAt   time.Time `json:"updatedAt"`
	Payload     []string  `json:"payload,omitempty"`
}

type ruleStrategy interface {
	Behavior() P.RuleBehavior
	Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool
	Count() int
	Reset()
	Insert(rule string)
	FinishInsert()
}

type mrsRuleStrategy interface {
	ruleStrategy
	FromMrs(r io.Reader, count int) error
	WriteMrs(w io.Writer) error
	DumpMrs(f func(key string) bool)
}

type baseProvider struct {
	behavior P.RuleBehavior
	strategy ruleStrategy
}

func (bp *baseProvider) Type() P.ProviderType {
	return P.Rule
}

func (bp *baseProvider) Behavior() P.RuleBehavior {
	return bp.behavior
}

func (bp *baseProvider) Count() int {
	return bp.strategy.Count()
}

func (bp *baseProvider) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	return bp.strategy != nil && bp.strategy.Match(metadata, helper)
}

func (bp *baseProvider) Strategy() any {
	return bp.strategy
}

type loadedRuleStrategy struct {
	strategy ruleStrategy
	digest   string
}

type ruleSetProvider struct {
	baseProvider
	*resource.Fetcher[loadedRuleStrategy]
	format P.RuleFormat
}

type RuleSetProvider struct {
	*ruleSetProvider
	readyMu     sync.RWMutex
	readyDigest string
}

func (rp *RuleSetProvider) Format() P.RuleFormat {
	return rp.format
}

// Match and Count share the snapshot lock with ExtensionReadyDigest, so callers
// cannot observe a matcher and readiness digest from different updates.
func (rp *RuleSetProvider) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	rp.readyMu.RLock()
	defer rp.readyMu.RUnlock()
	return rp.baseProvider.Match(metadata, helper)
}

func (rp *RuleSetProvider) Count() int {
	rp.readyMu.RLock()
	defer rp.readyMu.RUnlock()
	return rp.baseProvider.Count()
}

func (rp *RuleSetProvider) Strategy() any {
	rp.readyMu.RLock()
	defer rp.readyMu.RUnlock()
	return rp.baseProvider.Strategy()
}

func (rp *RuleSetProvider) ExtensionReadyDigest() (string, error) {
	rp.readyMu.RLock()
	defer rp.readyMu.RUnlock()
	if rp.readyDigest == "" {
		return "", fmt.Errorf("provider has no loaded ready snapshot")
	}
	return rp.readyDigest, nil
}

func extensionReadyDigest(behavior P.RuleBehavior, format P.RuleFormat, count int, raw, sidecar []byte) string {
	h := sha256.New()
	fmt.Fprintf(h, "rule-ready-v1\x00%s\x00%s\x00%d\x00", behavior.String(), format.String(), count)
	h.Write(raw)
	h.Write(sidecar)
	return hex.EncodeToString(h.Sum(nil))
}

func (rp *ruleSetProvider) Initial() error {
	_, err := rp.Fetcher.Initial()
	return err
}

func (rp *ruleSetProvider) InitialLocal() error {
	_, err := rp.Fetcher.InitialLocal()
	return err
}

const extensionRawRuleBudget = 10000

// ValidateForExtension runs in Runner after Initial has rebuilt missing/legacy
// sidecars. A warning-only write failure must not be reported as readiness.
func (rp *RuleSetProvider) ValidateForExtension() error {
	count := rp.Count()
	if rp.format == P.MrsRule || count <= extensionRawRuleBudget {
		return nil
	}
	if rp.behavior == P.Classical {
		return fmt.Errorf("%w: classical provider has %d rules, exceeds %d-rule extension budget; classical has no safe MRS representation", ErrRuleSetTooLarge, count, extensionRawRuleBudget)
	}
	if _, err := rp.ExtensionReadyDigest(); err != nil {
		return fmt.Errorf("extension artifact not ready: %w", err)
	}
	return nil
}

func (rp *ruleSetProvider) Update() error {
	_, _, err := rp.Fetcher.Update()
	return err
}

func (rp *RuleSetProvider) MarshalJSON() ([]byte, error) {
	rp.readyMu.RLock()
	defer rp.readyMu.RUnlock()
	return json.Marshal(
		providerForApi{
			Behavior:    rp.behavior.String(),
			Format:      rp.format.String(),
			Name:        rp.Fetcher.Name(),
			RuleCount:   rp.strategy.Count(),
			Type:        rp.Type().String(),
			UpdatedAt:   rp.UpdatedAt(),
			VehicleType: rp.VehicleType().String(),
		})
}

func (rp *RuleSetProvider) Close() error {
	runtime.SetFinalizer(rp, nil)
	return rp.ruleSetProvider.Close()
}

func NewRuleSetProvider(name string, behavior P.RuleBehavior, format P.RuleFormat, interval time.Duration, vehicle P.Vehicle, payload []string, bundleFile resource.BundleFile, parse common.ParseRuleFunc) P.RuleProvider {
	rp := &ruleSetProvider{
		baseProvider: baseProvider{
			behavior: behavior,
		},
		format: format,
	}

	var wrapper *RuleSetProvider
	onUpdate := func(loaded loadedRuleStrategy) {
		wrapper.readyMu.Lock()
		rp.strategy = loaded.strategy
		wrapper.readyDigest = loaded.digest
		wrapper.readyMu.Unlock()
		tunnel.RuleUpdateCallback().Emit(P.RuleUpdate{Name: rp.Name(), Strategy: loaded.strategy})
	}

	rp.strategy = newStrategy(behavior, parse)
	if len(payload) > 0 { // using as fallback rules
		rp.strategy = rulesParseInline(payload, rp.strategy)
	}
	rp.Fetcher = resource.NewFetcher(name, interval, vehicle, bundleFile, func(bytes []byte) (loadedRuleStrategy, error) {
		// Memory-constrained builds (the iOS Network Extension) try the
		// pre-computed MRS sidecar first: building the matcher from raw text is
		// what spikes the footprint, and the sidecar skips that entirely while
		// keeping every rule in a successfully loaded artifact. Startup admission
		// and total process memory safety must be enforced by the caller.
		var sidecarErr error
		var sidecarSnapshot []byte
		if maxLowMemoryRuleCount > 0 && format != P.MrsRule {
			sidecarSnapshot, sidecarErr = os.ReadFile(sidecarPath(vehicle.Path()))
			if sidecarErr == nil {
				strategy, err := loadFromSidecarBytes(sidecarSnapshot, bytes, behavior)
				if err == nil {
					log.Infoln("[Provider] %s loaded %d rules from MRS sidecar (skipped trie build)", name, strategy.Count())
					return loadedRuleStrategy{
						strategy: strategy,
						digest:   extensionReadyDigest(behavior, format, strategy.Count(), bytes, sidecarSnapshot),
					}, nil
				}
				sidecarErr = err
			}
			// Only fall back when the full raw matcher fits the build budget.
			// A parse error must retain the previous active strategy, not publish
			// a partial matcher. Initial failures require caller admission control.
			log.Debugln("[Provider] %s sidecar unavailable: %v", name, sidecarErr)
		}

		strategy, err := rulesParse(bytes, newStrategy(behavior, parse), format)
		if err != nil {
			if sidecarErr != nil {
				return loadedRuleStrategy{}, fmt.Errorf("%s rules: %w; prepared sidecar: %v; prepare in app (large classical has no safe MRS representation)", behavior, err, sidecarErr)
			}
			return loadedRuleStrategy{}, err
		}
		// On unconstrained builds, persist the finished bitmap so the extension
		// can load it next time without paying the build cost.
		if maxLowMemoryRuleCount == 0 && format != P.MrsRule {
			writeSidecar(vehicle.Path(), bytes, behavior, strategy)
			if strategy.Count() > extensionRawRuleBudget && behavior != P.Classical {
				sidecarSnapshot, err = os.ReadFile(sidecarPath(vehicle.Path()))
				if err != nil {
					return loadedRuleStrategy{}, fmt.Errorf("extension artifact not ready: %w", err)
				}
				if _, err = loadFromSidecarBytes(sidecarSnapshot, bytes, behavior); err != nil {
					return loadedRuleStrategy{}, fmt.Errorf("extension artifact not ready: %w", err)
				}
			}
		}
		return loadedRuleStrategy{
			strategy: strategy,
			digest:   extensionReadyDigest(behavior, format, strategy.Count(), bytes, sidecarSnapshot),
		}, nil
	}, onUpdate)

	wrapper = &RuleSetProvider{
		ruleSetProvider: rp,
	}

	runtime.SetFinalizer(wrapper, (*RuleSetProvider).Close)
	return wrapper
}

func newStrategy(behavior P.RuleBehavior, parse common.ParseRuleFunc) ruleStrategy {
	switch behavior {
	case P.Domain:
		strategy := NewDomainStrategy()
		return strategy
	case P.IPCIDR:
		strategy := NewIPCidrStrategy()
		return strategy
	case P.Classical:
		strategy := NewClassicalStrategy(parse)
		return strategy
	default:
		return nil
	}
}

var (
	ErrNoPayload     = errors.New("file must have a `payload` field")
	ErrInvalidFormat = errors.New("invalid format")

	// ErrRuleSetTooLarge is returned when a rule set exceeds the low-memory
	// build's budget. Startup callers must propagate it and refuse activation.
	ErrRuleSetTooLarge = errors.New("rule set too large for this build")
)

func rulesParse(buf []byte, strategy ruleStrategy, format P.RuleFormat) (ruleStrategy, error) {
	strategy.Reset()
	if format == P.MrsRule {
		return rulesMrsParse(buf, strategy)
	}

	schema := &RulePayload{}

	firstLineBuffer := pool.GetBuffer()
	defer pool.PutBuffer(firstLineBuffer)
	firstLineLength := 0

	s := 0 // search start index
	for s < len(buf) {
		// search buffer for a new line.
		line := buf[s:]
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			i += s
			line = buf[s : i+1]
			s = i + 1
		} else {
			s = len(buf)                                      // stop loop in next step
			if firstLineLength == 0 && format == P.YamlRule { // no head or only one line body
				return nil, ErrNoPayload
			}
		}
		var str string
		switch format {
		case P.TextRule:
			str = string(line)
			str = strings.TrimSpace(str)
			if len(str) == 0 {
				continue
			}
			if str[0] == '#' { // comment
				continue
			}
			if strings.HasPrefix(str, "//") { // comment in Premium core
				continue
			}
		case P.YamlRule:
			trimLine := bytes.TrimSpace(line)
			if len(trimLine) == 0 {
				continue
			}
			if trimLine[0] == '#' { // comment
				continue
			}
			firstLineBuffer.Write(line)
			if firstLineLength == 0 { // find payload head
				firstLineLength = firstLineBuffer.Len()
				firstLineBuffer.WriteString("  - ''") // a test line

				err := yaml.Unmarshal(firstLineBuffer.Bytes(), schema)
				firstLineBuffer.Truncate(firstLineLength)
				if err == nil && (len(schema.Rules) > 0 || len(schema.Payload) > 0) { // found
					continue
				}

				// not found or err!=nil
				firstLineBuffer.Truncate(0)
				firstLineLength = 0
				continue
			}

			// parse payload body
			err := yaml.Unmarshal(firstLineBuffer.Bytes(), schema)
			firstLineBuffer.Truncate(firstLineLength)
			if err != nil {
				continue
			}

			if len(schema.Rules) > 0 {
				str = schema.Rules[0]
			}
			if len(schema.Payload) > 0 {
				str = schema.Payload[0]
			}
		default:
			return nil, ErrInvalidFormat
		}

		if str == "" {
			continue
		}

		strategy.Insert(str)

		// Bail out before FinishInsert() rather than after: the matcher build is
		// where the footprint spike happens, and on a jetsam-capped extension the
		// process is killed mid-build. Counting during the scan lets us stop
		// while the cost is still just the parsed entries.
		if maxLowMemoryRuleCount > 0 && strategy.Count() > maxLowMemoryRuleCount {
			return nil, fmt.Errorf(
				"%w: %d rules exceeds the %d-rule budget for the low-memory build",
				ErrRuleSetTooLarge, strategy.Count(), maxLowMemoryRuleCount,
			)
		}
	}

	strategy.FinishInsert()

	return strategy, nil
}

func rulesParseInline(rs []string, strategy ruleStrategy) ruleStrategy {
	strategy.Reset()
	for _, r := range rs {
		if r != "" {
			strategy.Insert(r)
		}
	}
	strategy.FinishInsert()
	return strategy
}

type InlineProvider struct {
	*inlineProvider
}

type inlineProvider struct {
	baseProvider
	name       string
	updateAt   time.Time
	payload    []string
	initialErr error
}

func (i *inlineProvider) Name() string {
	return i.name
}

func (i *InlineProvider) ExtensionReadyDigest() (string, error) {
	h := sha256.New()
	fmt.Fprintf(h, "rule-ready-v1\x00%s\x00inline\x00%d\x00", i.behavior.String(), i.Count())
	for _, rule := range i.payload {
		h.Write([]byte(rule))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (i *inlineProvider) Initial() error {
	return i.initialErr
}

func (i *inlineProvider) Update() error {
	// make api update happy
	i.updateAt = time.Now()
	return nil
}

func (i *inlineProvider) VehicleType() P.VehicleType {
	return P.Inline
}

func (i *inlineProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		providerForApi{
			Behavior:    i.behavior.String(),
			Name:        i.Name(),
			RuleCount:   i.strategy.Count(),
			Type:        i.Type().String(),
			VehicleType: i.VehicleType().String(),
			UpdatedAt:   i.updateAt,
			Payload:     i.payload,
		})
}

func NewInlineProvider(name string, behavior P.RuleBehavior, payload []string, parse common.ParseRuleFunc) P.RuleProvider {
	ip := &inlineProvider{
		baseProvider: baseProvider{
			behavior: behavior,
			strategy: newStrategy(behavior, parse),
		},
		payload:  payload,
		name:     name,
		updateAt: time.Now(),
	}
	// Inline has no file-backed sidecar; guard before matcher construction.
	budget := maxLowMemoryRuleCount
	if features.IOS {
		budget = extensionRawRuleBudget
	}
	if budget > 0 && len(payload) > budget {
		ip.initialErr = fmt.Errorf("%w: inline provider has %d entries, exceeds %d-rule extension budget; no prepared artifact", ErrRuleSetTooLarge, len(payload), budget)
	} else {
		ip.strategy = rulesParseInline(payload, ip.strategy)
	}

	wrapper := &InlineProvider{
		ip,
	}

	//runtime.SetFinalizer(wrapper, (*InlineProvider).Close)
	return wrapper
}
