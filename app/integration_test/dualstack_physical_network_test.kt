package app.xio.xio

import java.net.InetAddress

/** Pure helper fixture, run on a JVM with Android API stubs. No device or DNS. */
fun main() {
 var checks=0
 fun verify(value:Boolean,message:String) { checks++; check(value){message} }
 fun ip(literal:String)=InetAddress.getByName(literal)
 val v6=(1..16).map {ip("2001:db8::"+it.toString(16))}
 val v4=(1..16).map {ip("192.0.2.$it")}
 val v6First=PhysicalNetwork.numericAddresses(v6+v4.take(1))
 verify(v6First.size==16,"maximum bridge size")
 verify(v6First[0].contains(":"),"retain OS IPv6 preference")
 verify(v6First[1]=="192.0.2.1","IPv4 fallback must survive sixteen AAAA answers")
 val v4First=PhysicalNetwork.numericAddresses(v4+v6.take(1))
 verify(v4First[0]=="192.0.2.1","retain OS IPv4 preference")
 verify(v4First[1].contains(":"),"IPv6 fallback must survive sixteen A answers")
 verify(PhysicalNetwork.numericAddresses(listOf(ip("0.0.0.0"),ip("::"),ip("224.0.0.1"),ip("ff02::1"),ip("fe80::1"))).isEmpty(),"reject invalid/scopeless outer destinations")
 verify(PhysicalNetwork.numericAddresses(listOf(ip("192.0.2.1"),ip("192.0.2.1"),ip("2001:db8::1"))).size==2,"deduplicate addresses")
 verify(PhysicalNetwork.numericAddresses(v6.take(2)).size==2,"IPv6-only answers survive")
 verify(PhysicalNetwork.numericAddresses(v4.take(2)).size==2,"IPv4-only answers survive")
 verify(PhysicalNetwork.numericAddresses(emptyList()).isEmpty(),"empty DNS fails closed")
 println("XIO_DUALSTACK_PHYSICAL_DNS_PASS checks=$checks scope=numeric-bridge-helper-only;device-VPN-not-tested")
}
