package utils
import("sync/atomic";"testing";"time")
func TestIndependentPreparedEmitUnregisterBeforeAdmission(t *testing.T){
 c:=NewCallback[int]();var called atomic.Int32;done:=make(chan struct{},1)
 closer:=c.Register(func(int){called.Add(1);done<-struct{}{}})
 emit:=c.PrepareEmit(1)
 _=closer.Close() // unregister finishes before launch/admission, not an already-admitted listener
 emit()
 select{case <-done:t.Fatalf("unregistered listener invoked after PrepareEmit snapshot and before launch; calls=%d",called.Load());case <-time.After(100*time.Millisecond):}
}
