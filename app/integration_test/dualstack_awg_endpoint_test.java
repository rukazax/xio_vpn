package org.amnezia.awg.config;

import java.net.InetAddress;
import java.net.Inet4Address;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

public final class dualstack_awg_endpoint_test {
 static int checks;
 static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}
 static InetAddress ip(String s)throws Exception{return InetAddress.getByName(s);}
 public static void main(String[]args)throws Exception {
  InetAddress v4=ip("192.0.2.1"),v6=ip("2001:db8::1"),dns64=ip("64:ff9b::c000:201");
  check(EndpointResolver.order(new InetAddress[]{v4}).get(0).equals(v4),"A-only");
  check(EndpointResolver.order(new InetAddress[]{v6}).get(0).equals(v6),"AAAA-only");
  check(EndpointResolver.order(new InetAddress[]{dns64,v4}).get(0).equals(dns64),"DNS64 preference must not be overridden by A");
  check(EndpointResolver.order(new InetAddress[]{v4,v6}).get(0).equals(v4),"physical IPv4 preference retained");
  for(boolean first4:new boolean[]{false,true}) {
   List<InetAddress> input=new ArrayList<>();
   for(int i=1;i<=16;i++)input.add(ip(first4?"192.0.2."+i:"2001:db8::"+Integer.toHexString(i)));
   input.add(first4?v6:v4);
   List<InetAddress> selected=EndpointResolver.order(input.toArray(new InetAddress[0]));
   check(selected.size()==16,"bounded candidates");
   check((selected.get(1) instanceof Inet4Address)!=first4,"mixed16+1 retains alternate family");
  }
  check(EndpointResolver.order(new InetAddress[]{ip("::"),ip("0.0.0.0"),ip("ff02::1"),ip("224.0.0.1"),ip("fe80::1")}).isEmpty(),"unsafe addresses rejected");
  check(EndpointResolver.order(new InetAddress[]{v4,v4,v6}).size()==2,"dedup");
  InetEndpoint endpoint=InetEndpoint.parse("vpn.invalid:51820");
  check(endpoint.getResolved().isEmpty(),"unseeded serialization never falls back to DNS");
  check(endpoint.getResolved(h->new InetAddress[]{dns64,v4},500).orElseThrow().getHost().contains(":"),"production endpoint picks physical DNS64");
  check(endpoint.getResolved().orElseThrow().toString().startsWith("["),"IPv6 UAPI brackets");
  check(endpoint.getResolvedCandidates().size()==2,"all numeric candidates retained");
  check(endpoint.getResolvedCandidates().get(1).toString().equals("192.0.2.1:51820"),"candidate family order/port");
  endpoint.getResolvedCandidates().clear();
  check(endpoint.getResolvedCandidates().size()==2,"defensive candidates copy");
  check(endpoint.getResolved(h->{throw new UnknownHostException();},500).isEmpty(),"physical failure fails closed");
  check(endpoint.getResolved().isEmpty(),"no stale successful endpoint after physical failure");
  check(endpoint.getResolvedCandidates().isEmpty(),"failed DNS clears candidate list");
  check(InetEndpoint.parse("192.0.2.1:51820").getResolved(null,1).isPresent(),"literal v4 skips DNS");
  check(InetEndpoint.parse("[2001:db8::1]:51820").getResolved(null,1).isPresent(),"literal v6 skips DNS");
  CountDownLatch entered=new CountDownLatch(1),release=new CountDownLatch(1);
  long start=System.nanoTime(); boolean timedOut=false;
  try {EndpointResolver.resolve("vpn.invalid",h->{entered.countDown();while(release.getCount()>0){try{release.await();}catch(InterruptedException ignored){}}return new InetAddress[]{v6};},30);}
  catch(TimeoutException expected){timedOut=true;}
  check(timedOut && TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start)<1000,"bounded DNS timeout");
  check(entered.getCount()==0,"stalled callback entered");
  boolean bounded=false;
  try {EndpointResolver.resolve("vpn.invalid",h->{throw new AssertionError("must not enqueue another resolver");},30);}
  catch(IllegalStateException expected){bounded=true;}
  finally {release.countDown();}
  check(bounded,"stuck callbacks bounded to one worker");
  Thread.sleep(30);
  check(EndpointResolver.resolve("vpn.invalid",h->new InetAddress[]{v4},500).get(0).equals(v4),"resolver recovers after stuck work returns");
  String backend=java.nio.file.Files.readString(java.nio.file.Path.of("vendor/amneziawg/android/src/main/java/org/amnezia/awg/backend/GoBackend.java"));
  String bridge=java.nio.file.Files.readString(java.nio.file.Path.of("vendor/amneziawg/android/src/main/java/org/amnezia/awg/GoBackend.java"));
  check(backend.contains("NET_CAPABILITY_NOT_VPN")&&backend.contains("network.getAllByName(host)")&&!backend.contains("InetAddress.getAllByName"),"physical NOT_VPN DNS source contract");
  check(bridge.contains("service.protect((int)fd)")&&bridge.contains("::resolveEndpoint"),"protector kept and bridge resolver wired (source-only)");
  System.out.println("XIO_AWG_ENDPOINT_JVM_PASS checks="+checks+"; no Android/device/handshake failover certification");
 }
}
