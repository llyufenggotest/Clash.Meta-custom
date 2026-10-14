package dns

import (
	"github.com/metacubex/mihomo/component/trie"
	C "github.com/metacubex/mihomo/constant"
)

type dnsPolicy interface {
	Match(domain string) []dnsClient
	ForEachClient(func(dnsClient))
}

type domainTriePolicy struct {
	*trie.DomainTrie[[]dnsClient]
}

func (p domainTriePolicy) Match(domain string) []dnsClient {
	record := p.DomainTrie.Search(domain)
	if record != nil {
		return record.Data()
	}
	return nil
}

func (p domainTriePolicy) ForEachClient(fn func(dnsClient)) {
	if p.DomainTrie == nil {
		return
	}
	p.DomainTrie.Foreach(func(_ string, clients []dnsClient) bool {
		for _, client := range clients {
			fn(client)
		}
		return true
	})
}

type domainMatcherPolicy struct {
	matcher    C.DomainMatcher
	dnsClients []dnsClient
}

func (p domainMatcherPolicy) ForEachClient(fn func(dnsClient)) {
	for _, client := range p.dnsClients {
		fn(client)
	}
}

func (p domainMatcherPolicy) Match(domain string) []dnsClient {
	if p.matcher.MatchDomain(domain) {
		return p.dnsClients
	}
	return nil
}
