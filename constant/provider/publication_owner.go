package provider

import "context"

// PublicationOwner guards only a prepared final transaction. Implementations
// must not run preparation, arbitrary callbacks or network under this guard.
type PublicationOwner interface {
	Context() context.Context
	CommitPrepared(func() error) error
}
type publicationOwnerKey struct{}

func WithPublicationOwner(ctx context.Context, owner PublicationOwner) context.Context {
	return context.WithValue(ctx, publicationOwnerKey{}, owner)
}
func PublicationOwnerFromContext(ctx context.Context) PublicationOwner {
	owner, _ := ctx.Value(publicationOwnerKey{}).(PublicationOwner)
	return owner
}
