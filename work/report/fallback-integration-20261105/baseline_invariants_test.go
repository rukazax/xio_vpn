package desktop

import (
 "context"
 "net/netip"
 "sync/atomic"
 "testing"
 "time"
)

// Baseline-only desired invariants derived from I's immutable observational probes.
// These MUST fail against frozen BASE; they are not gap-observation successes.
func TestBaselineInvariantNoPostRevokePlanEffects(t *testing.T) {
 var revoked atomic.Bool
 calls,after:=0,0
 var applied []networkCommand
 err:=applyNetworkPlan(linuxNetworkPlan(Profile{MTU:1280,Addresses:[]netip.Prefix{netip.MustParsePrefix("10.9.0.2/32")},DNS:[]netip.Addr{netip.MustParseAddr("9.9.9.9")}}),func(string,...string)([]byte,error){calls++;if revoked.Load(){after++};revoked.Store(true);return nil,nil},&applied)
 if err==nil||calls!=1||after!=0 {t.Fatalf("desired invariant FAIL: err=%v calls=%d after-revoke=%d",err,calls,after)}
}
type baselineResolver struct {entered,release chan struct{}}
func(n *baselineResolver) Resolve(string)string {close(n.entered);<-n.release;return "192.0.2.1"}
func(n *baselineResolver) bypass(netip.Addr)error {panic("late bypass")}
func TestBaselineInvariantCanceledDNSReturns(t *testing.T) {
 n:=&baselineResolver{make(chan struct{}),make(chan struct{})}
 ctx,cancel:=context.WithCancel(context.Background());defer cancel()
 done:=make(chan error,1)
 go func(){p:=Profile{Endpoints:[]string{"fixture.invalid:443"}};done<-prepareEndpointsBudget(&p,n,ctx.Err)}()
 <-n.entered;cancel()
 select {case err:=<-done:if err!=context.Canceled{t.Fatalf("unexpected error %v",err)};case <-time.After(20*time.Millisecond):close(n.release);<-done;t.Fatal("desired invariant FAIL: original resolver ignores setup cancellation until independently released")}
}
