package cachefile_test

import (
 "path/filepath"
 "testing"
 "github.com/metacubex/bbolt"
 "github.com/metacubex/mihomo/component/profile/cachefile"
 "github.com/metacubex/mihomo/component/resource"
 C "github.com/metacubex/mihomo/constant"
 P "github.com/metacubex/mihomo/constant/provider"
)

func independentCache(t *testing.T, path string) *cachefile.CacheFile {
 t.Helper(); db, err := bbolt.Open(path, 0600, nil); if err != nil { t.Fatal(err) }; t.Cleanup(func(){ _=db.Close() }); return &cachefile.CacheFile{DB: db}
}
func TestIndependentOwnedLegacyLastWriteWins(t *testing.T) {
 dir := t.TempDir(); old := C.Path.HomeDir(); C.SetHomeDir(dir); defer C.SetHomeDir(old)
 c := independentCache(t, C.Path.Cache())
 f := resource.NewOwnedFetcher("metadata",0,resource.NewFileVehicle(filepath.Join(dir,"raw")),nil,
 func(_ *resource.Owner,b []byte)(string,error){ return string(b),nil },
 func(o *resource.Owner,_ string){
 ctx:=P.WithPublicationOwner(o.Context(),o)
 if err:=c.SetSubscriptionInfoOwned(ctx,"p","owned-old"); err!=nil {t.Fatal(err)}
 if err:=c.SetETagWithHashOwned(ctx,"u",cachefile.EtagWithHash{ETag:"owned-old"}); err!=nil {t.Fatal(err)}
 c.SetSubscriptionInfo("p","legacy-new")
 c.SetETagWithHash("u",cachefile.EtagWithHash{ETag:"legacy-new"})
 if got:=c.GetSubscriptionInfo("p");got!="legacy-new" {t.Errorf("subscription=%q want legacy-new",got)}
 if got:=c.GetETagWithHash("u").ETag;got!="legacy-new" {t.Errorf("etag=%q want legacy-new",got)}
 }); defer f.Close(); if _,_,err:=f.SideUpdate([]byte("raw"));err!=nil {t.Fatal(err)}
}
func TestIndependentCacheReceiverIsolation(t *testing.T) {
 dir:=t.TempDir(); old:=C.Path.HomeDir(); C.SetHomeDir(dir); defer C.SetHomeDir(old)
 a:=independentCache(t,filepath.Join(dir,"A.db")); b:=independentCache(t,filepath.Join(dir,"B.db"))
 b.SetSubscriptionInfo("p","B-private")
 f:=resource.NewOwnedFetcher("metadata",0,resource.NewFileVehicle(filepath.Join(dir,"raw")),nil,
 func(_ *resource.Owner,d []byte)(string,error){return string(d),nil},func(o *resource.Owner,_ string){
 if err:=a.SetSubscriptionInfoOwned(P.WithPublicationOwner(o.Context(),o),"p","A-private");err!=nil {t.Fatal(err)}
 if got:=b.GetSubscriptionInfo("p");got!="B-private" {t.Errorf("B returned %q from A-owned write",got)}
 });defer f.Close(); if _,_,err:=f.SideUpdate([]byte("raw"));err!=nil {t.Fatal(err)}
}
