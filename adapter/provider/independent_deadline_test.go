package provider
import (
 "errors"
 "context"
 "net/http"
 "net/http/httptest"
 "path/filepath"
 "testing"
 "time"
 "github.com/metacubex/mihomo/component/resource"
 "github.com/metacubex/mihomo/component/profile/cachefile"
 C "github.com/metacubex/mihomo/constant"
)
func TestIndependentHTTPDeadlineRejectsLateSubscriptionPublication(t *testing.T) {
 dir:=t.TempDir();old:=C.Path.HomeDir();C.SetHomeDir(dir);defer C.SetHomeDir(old)
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){w.Header().Set("subscription-userinfo","upload=99; download=88");_,_=w.Write([]byte("proxies: []\n"))}));defer server.Close()
 hc:=NewHealthCheck(nil,"",0,0,false,nil)
 v:=resource.NewHTTPVehicle(server.URL,filepath.Join(dir,"cache"),"",nil,2*time.Second,0)
 p,err:=NewProxySetProvider("deadline-late",0,nil,func([]byte)([]C.Proxy,error){return nil,nil},v,hc);if err!=nil {t.Fatal(err)};defer p.Close()
 cache:=cachefile.Cache();if cache.DB!=nil && cache.DB.Path()==C.Path.Cache(){defer cache.Close()}
 p.mutex.Lock();locked:=true;defer func(){if locked {p.mutex.Unlock()}}()
 done:=make(chan error,1);go func(){done<-p.Update()}()
 deadline:=time.Now().Add(3*time.Second)
 for cachefile.Cache().GetSubscriptionInfo("deadline-late")=="" {if time.Now().After(deadline){t.Fatal("HTTP metadata callback not reached")};time.Sleep(time.Millisecond)}
 time.Sleep(2500*time.Millisecond)
 p.mutex.Unlock();locked=false
 if err:=<-done;!errors.Is(err,context.DeadlineExceeded){t.Fatalf("Update err=%v want deadline",err)}
 if info:=p.subscriptionSnapshot();info!=nil {t.Fatalf("request canceled before provider lock acquired, but published subscription=%+v",info)}
}
