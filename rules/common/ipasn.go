package common

import (
	"fmt"

	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/mmdb"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type ASN struct {
	Base
	asn         string
	adapter     string
	noResolveIP bool
	isSourceIP  bool
}

func (a *ASN) Match(metadata *C.Metadata, helper C.RuleMatchHelper) (bool, string) {
	if !a.noResolveIP && !a.isSourceIP && helper.ResolveIP != nil {
		helper.ResolveIP()
	}

	ip := metadata.DstIP
	if a.isSourceIP {
		ip = metadata.SrcIP
	}
	if !ip.IsValid() {
		return false, ""
	}

	asn, aso := mmdb.ASNInstance().LookupASN(ip.AsSlice())
	if a.isSourceIP {
		metadata.SrcIPASN = asn + " " + aso
	} else {
		metadata.DstIPASN = asn + " " + aso
	}

	return a.asn == asn, a.adapter
}

func (a *ASN) RuleType() C.RuleType {
	if a.isSourceIP {
		return C.SrcIPASN
	}
	return C.IPASN
}

func (a *ASN) Adapter() string {
	return a.adapter
}

func (a *ASN) Payload() string {
	return a.asn
}

func (a *ASN) GetASN() string {
	return a.asn
}

func NewIPASN(asn string, adapter string, isSrc, noResolveIP bool) (*ASN, error) {
	if err := geodata.InitASN(); err != nil {
		log.Errorln("can't initial ASN: %s", err)
		return nil, err
	}

	// InitASN reports success while leaving the feature disabled on low-memory
	// builds. Building the rule anyway would be worse than dropping it: the rule
	// can never match, but its first Match call mmaps the whole ASN database.
	// On iOS that mapping is charged to phys_footprint against a ~50 MB budget,
	// so a rule that is guaranteed useless would cost the process its life.
	// Refuse here; callers treat the error as "skip this rule" and keep going.
	if !geodata.ASNEnable() {
		return nil, fmt.Errorf("ASN rule %s ignored: ASN database is disabled on this build", asn)
	}

	return &ASN{
		Base:        Base{},
		asn:         asn,
		adapter:     adapter,
		noResolveIP: noResolveIP,
		isSourceIP:  isSrc,
	}, nil
}

var _ C.Rule = (*ASN)(nil)
