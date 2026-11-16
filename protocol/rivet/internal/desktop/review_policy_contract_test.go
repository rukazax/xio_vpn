//go:build reviewprobe

package desktop

import (
 "encoding/json"
 "strings"
 "sync"
 "sync/atomic"
 "testing"
 "time"
)

// Review-only probes: real Runtime/parser, inert evidence observer, no helper,
// socket, service, device, route, or firewall. No product functions are replaced.
func reviewDocument(t *testing.T, request PolicyRequest) (map[string]any, *policyPlan) {
 t.Helper()
 plan := parsePlanOrFail(t, request.Plan)
 document := validationDocumentFor(plan)
 document["schema"] = 2
 document["connectionPlanReceipt"] = map[string]any{
  "schema": 1, "transactionId": request.TransactionID,
  "planGeneration": request.PlanGeneration, "plan": json.RawMessage(request.Plan),
 }
 return document, plan
}

func reviewValidate(t *testing.T, r *Runtime, request PolicyRequest) {
 t.Helper()
 document, plan := reviewDocument(t, request)
 configs := map[string]string{}
 for _, profile := range plan.Profiles { configs[profile.ID] = testConfigFor(t, profile) }
 if _, err := r.PolicyValidate(request, validationObject(t, document, plan, configs)); err != nil { t.Fatal(err) }
}

func TestReviewPositiveMixedAndTamperControls(t *testing.T) {
 for _, mode := range []string{"selectedOnly", "automatic"} {
  t.Run(mode, func(t *testing.T) {
   for _, tamper := range []string{"none", "config bytes", "revoked", "receipt identity"} {
    t.Run(tamper, func(t *testing.T) {
     r, instance := newValidationRuntime(t, false)
     offered := testPlan()
     offered["selectedId"] = "a"
     offered["ids"] = []string{"a"}
     offered["policy"] = map[string]any{"mode":mode, "roundMillis":30000}
     offered["profiles"] = []map[string]any{{"id":"a", "protocol":"awg", "endpoint":"203.0.113.9:51820", "configDigest":policyConfigDigest(syntheticAWGConfig)}}
     configs := map[string]string{"a":syntheticAWGConfig}
     if mode == "automatic" {
      offered["ids"] = []string{"a", "b"}
      offered["profiles"] = append(offered["profiles"].([]map[string]any), map[string]any{"id":"b", "protocol":"xray", "endpoint":"203.0.113.9:443", "configDigest":policyConfigDigest(syntheticXrayConfig)})
      configs["b"] = syntheticXrayConfig
     }
     request := policyRequestFor(t, instance, testPlanBytes(t, offered), testGeneration, testTxID, nil)
     document, plan := reviewDocument(t, request)
     document["unrelatedSetting"] = map[string]any{"valid": []any{1, "two", true}}
     switch tamper {
     case "config bytes": configs["a"] += "\n"
     case "revoked": document["users"].([]map[string]any)[0]["revoked"] = true
     case "receipt identity": document["connectionPlanReceipt"].(map[string]any)["transactionId"] = testOtherTx
     }
     ack, err := r.PolicyValidate(request, validationObject(t, document, plan, configs))
     if tamper != "none" {
      if err == nil { t.Fatalf("same-identity %s tamper accepted: %v", tamper, ack) }
      if _, err := r.PolicyReconcile(request); err == nil { t.Fatal("failed validation installed authority") }
      return
     }
     if err != nil || len(ack) != 5 { t.Fatalf("valid mixed/manual snapshot rejected: %v %v", ack, err) }
     ready, err := r.PolicyReconcile(request)
     if err != nil || ready["state"] != "ready" { t.Fatalf("valid snapshot did not reach READY: %v %v", ready, err) }
    })
   }
  })
 }
}

func TestReviewValidationCapabilityIsAdvertised(t *testing.T) {
 r, _ := newValidationRuntime(t, false)
 capabilities, err := r.PolicyCapabilities()
 if err != nil { t.Fatal(err) }
 if capabilities["validation"] != 1 { t.Fatalf("WIRE-V2 section8 requires validation:1; actual capabilities=%v", capabilities) }
}

func TestReviewRejectsMalformedDocumentAuthority(t *testing.T) {
 mutations := map[string]func(map[string]any){
  "document schema missing": func(d map[string]any) { delete(d,"schema") },
  "document schema wrong": func(d map[string]any) { d["schema"] = 77 },
  "document schema wrong type": func(d map[string]any) { d["schema"] = "2" },
  "receipt missing": func(d map[string]any) { delete(d,"connectionPlanReceipt") },
  "receipt null": func(d map[string]any) { d["connectionPlanReceipt"] = nil },
  "receipt schema missing": func(d map[string]any) { delete(d["connectionPlanReceipt"].(map[string]any),"schema") },
  "receipt schema wrong": func(d map[string]any) { d["connectionPlanReceipt"].(map[string]any)["schema"] = 77 },
  "receipt schema wrong type": func(d map[string]any) { d["connectionPlanReceipt"].(map[string]any)["schema"] = "1" },
  "receipt unexpected key": func(d map[string]any) { d["connectionPlanReceipt"].(map[string]any)["extra"] = true },
  "connection policy unexpected key": func(d map[string]any) { d["connectionPolicy"].(map[string]any)["extra"] = true },
 }
 for name, mutate := range mutations {
  t.Run(name, func(t *testing.T) {
   r, instance := newValidationRuntime(t, false)
   request := policyRequestFor(t, instance, testPlanBytes(t, testPlan()), testGeneration, testTxID, nil)
   document, plan := reviewDocument(t, request)
   mutate(document)
   ack, err := r.PolicyValidate(request, validationObject(t, document, plan, map[string]string{"fixture":testAWGConfig}))
   if err == nil {
    ready, reconcileErr := r.PolicyReconcile(request)
    t.Fatalf("malformed authority was validated and can publish: validateACK=%v reconcile=%v error=%v", ack, ready, reconcileErr)
   }
   if _, err := r.PolicyReconcile(request); err == nil { t.Fatal("malformed document still installed consumable authority") }
  })
 }
}

type reviewResult struct { ack map[string]any; err error }

func TestReviewConcurrentCommitRetainsPhysicalLane(t *testing.T) {
 r, instance := newValidationRuntime(t, false)
 rawPlan := testPlanBytes(t, testPlan())
 initial := policyRequestFor(t, instance, rawPlan, testGeneration, testTxID, nil)
 reviewValidate(t, r, initial)
 if _, err := r.PolicyReconcile(initial); err != nil { t.Fatal(err) }
 next := policyRequestFor(t, instance, rawPlan, testOtherGen, testOtherTx, mustSpan(t,testGeneration))
 if _, err := r.PolicyBegin(next); err != nil { t.Fatal(err) }
 reviewValidate(t, r, next)
 var calls atomic.Int32
 entered := make(chan int32, 2)
 firstRelease, secondRelease := make(chan struct{}), make(chan struct{})
 var firstOnce, secondOnce sync.Once
 releaseFirst := func() { firstOnce.Do(func(){ close(firstRelease) }) }
 releaseSecond := func() { secondOnce.Do(func(){ close(secondRelease) }) }
 defer releaseFirst(); defer releaseSecond()
 r.mu.Lock()
 r.policy.observe = func() ResourceEvidence {
  call := calls.Add(1)
  entered <- call
  if call == 1 { <-firstRelease } else { <-secondRelease }
  return ResourcesClean
 }
 r.mu.Unlock()
 first, second := make(chan reviewResult,1), make(chan reviewResult,1)
 go func(){ ack, err := r.PolicyCommit(next); first <- reviewResult{ack,err} }()
 select { case <-entered: case <-time.After(2*time.Second): t.Fatal("first controlled observer did not enter") }
 go func(){ ack, err := r.PolicyCommit(next); second <- reviewResult{ack,err} }()
 duplicated := false
 select {
 case <-entered: duplicated = true; t.Errorf("same reservation started TWO simultaneous physical observations")
 case result := <-second:
  if result.err == nil { t.Errorf("second commit returned before physical predecessor settled: %v",result.ack) }
  releaseFirst(); <-first
  return
 case <-time.After(200*time.Millisecond): // A correct implementation may join the first owner.
 }
 releaseFirst()
 var firstResult reviewResult
 select { case firstResult = <-first: case <-time.After(2*time.Second): t.Fatal("first controlled observation did not settle") }
 if firstResult.err != nil || firstResult.ack["state"] != "ready" { t.Fatalf("first commit failed: %v",firstResult) }
 if duplicated {
  state, err := r.PolicyState()
  if err != nil { t.Fatal(err) }
  if state["state"] == "ready" { t.Errorf("READY exposed while duplicate physical owner remains outstanding: %v",state) }
  successor := policyRequestFor(t, instance, rawPlan, strings.Repeat("8",32), strings.Repeat("9",32), mustSpan(t,testOtherGen))
  if _, err := r.PolicyBegin(successor); err == nil {
   t.Errorf("successor admitted while duplicate physical owner remains outstanding")
   blocked, err := r.PolicyAbort(PolicyAbortRequest{Version:1, InstanceNonce:instance, TransactionID:successor.TransactionID})
   if err != nil || blocked["state"] != "blocked" { t.Fatalf("successor abort fixture: %v %v",blocked,err) }
  }
 }
 releaseSecond()
 select {
 case result := <-second:
  if result.err == nil && result.ack["state"] == "ready" {
   state, err := r.PolicyState()
   if err != nil { t.Fatal(err) }
   if state["state"] != "ready" { t.Errorf("late predecessor ACK claims READY after successor settled BLOCKED: ACK=%v STATE=%v",result.ack,state) }
  }
 case <-time.After(2*time.Second): t.Fatal("second controlled owner did not settle")
 }
}
