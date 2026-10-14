package dns

import "reflect"

// One reset traversal covers the resolver graph, including shared bootstrap
// resolvers and aggregate proxy/direct resolvers. Address is not an identity:
// equal endpoints may have different dialers or transport options.
type connectionResetter struct {
	resolvers map[*Resolver]struct{}
	clients   map[dnsClient]struct{}
}

func newConnectionResetter() *connectionResetter {
	return &connectionResetter{resolvers: make(map[*Resolver]struct{}), clients: make(map[dnsClient]struct{})}
}

func (s *connectionResetter) resetClient(c dnsClient) {
	for c != nil {
		u, ok := c.(interface{ Unwrap() dnsClient })
		if !ok {
			break
		}
		c = u.Unwrap()
	}
	if c == nil {
		return
	}
	// Value.Comparable checks dynamic interface fields as well as the static
	// type, unlike Type.Comparable. Unknown non-comparable value clients must
	// still be reset: there is no safe generic identity to deduplicate them by.
	if reflect.ValueOf(c).Comparable() {
		if _, ok := s.clients[c]; ok {
			return
		}
		s.clients[c] = struct{}{}
	}
	c.ResetConnection()
}

func (s *connectionResetter) resetResolver(r *Resolver) {
	if r == nil {
		return
	}
	if _, ok := s.resolvers[r]; ok {
		return
	}
	s.resolvers[r] = struct{}{}
	for _, c := range r.main {
		s.resetClient(c)
	}
	for _, c := range r.fallback {
		s.resetClient(c)
	}
	for _, p := range r.policy {
		p.ForEachClient(s.resetClient)
	}
	s.resetResolver(r.defaultResolver)
}
