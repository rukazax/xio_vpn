/* SPDX-License-Identifier: Apache-2.0
 * XIO adapter: all engines use the same gomobile runtime.
 * Upstream API names are retained for the existing Android backend.
 */
package org.amnezia.awg;

import app.xio.mobile.Mobile;

public class GoBackend {
 public static String awgGetConfig(int handle) {return Mobile.awgGetConfig(handle);}
 public static int awgGetSocketV4(int handle) {return (int)Mobile.awgGetSocketV4(handle);}
 public static int awgGetSocketV6(int handle) {return (int)Mobile.awgGetSocketV6(handle);}
 public static void awgTurnOff(int handle) {Mobile.awgTurnOff(handle);}
 public static int awgTurnOn(String ifName,int tunFd,String settings,final android.net.VpnService service) {
  return (int)Mobile.awgTurnOn(ifName,tunFd,settings,new app.xio.mobile.Protector(){
   public boolean protect(long fd){return fd>=0&&fd<=Integer.MAX_VALUE&&service.protect((int)fd);}
   public String resolve(String host){
    if(!(service instanceof org.amnezia.awg.backend.GoBackend.VpnService))return "";
    try {
     java.util.List<java.net.InetAddress> addresses=org.amnezia.awg.config.EndpointResolver.resolve(host,
      ((org.amnezia.awg.backend.GoBackend.VpnService)service)::resolveEndpoint,2000);
     StringBuilder result=new StringBuilder();
     for(java.net.InetAddress address:addresses){if(result.length()>0)result.append(',');result.append(address.getHostAddress());}
     return result.toString();
    }catch(Exception e){if(e instanceof InterruptedException)Thread.currentThread().interrupt();return "";}
   }
  });
 }
 public static void awgHandshakeCandidates(int handle,String publicKey,String candidates,long timeoutMillis) throws Exception {Mobile.awgHandshakeCandidates(handle,publicKey,candidates,timeoutMillis);}
 public static void awgCancelHandshake(int handle) {Mobile.awgCancelHandshake(handle);}
 public static String awgVersion() {return Mobile.awgVersion();}
}
