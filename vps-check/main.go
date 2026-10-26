// Validate a private device profile using isolated userspace networking.
// Does not create a host TUN, change routes, or require local root.
package main

import (
 "context"
 "encoding/base64"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "net/http"
 "net/netip"
 "os"
 "strings"
 "time"

 "github.com/amnezia-vpn/amneziawg-go/v3/conn"
 "github.com/amnezia-vpn/amneziawg-go/v3/device"
 "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)
func main() {
 if len(os.Args)!=3 {panic("Usage: vps-check PRIVATE_PROFILE EXPECTED_TUNNEL_IP")}
 raw,err:=os.ReadFile(os.Args[1]);must(err)
 fields:=map[string]string{}
 for _,line:=range strings.Split(string(raw),"\n") {parts:=strings.SplitN(line,"=",2);if len(parts)==2 {fields[strings.ToLower(strings.TrimSpace(parts[0]))]=strings.TrimSpace(parts[1])}}
 local:=strings.Split(strings.Split(fields["address"],",")[0],"/")[0]
 tun,stack,err:=netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr(local)},[]netip.Addr{netip.MustParseAddr("1.1.1.1")},1280);must(err)
 dev:=device.NewDevice(tun,conn.NewDefaultBind(),device.NewLogger(device.LogLevelError,"xio-check: "));defer dev.Close()
 priv,err:=base64.StdEncoding.DecodeString(fields["privatekey"]);must(err)
 pub,err:=base64.StdEncoding.DecodeString(fields["publickey"]);must(err)
 config:="private_key="+hex.EncodeToString(priv)+"\n"
 for _,name:=range []string{"jc","jmin","jmax","s1","s2","s3","s4","h1","h2","h3","h4"} {if v,ok:=fields[name];ok {config+=name+"="+v+"\n"}}
 config+="public_key="+hex.EncodeToString(pub)+"\nendpoint="+fields["endpoint"]+"\nallowed_ip=0.0.0.0/0\npersistent_keepalive_interval=5\n"
 must(dev.IpcSet(config));must(dev.Up())
 client:=&http.Client{Timeout:20*time.Second,Transport:&http.Transport{DialContext:stack.DialContext}}
 defer client.CloseIdleConnections()
 context,cancel:=context.WithTimeout(context.Background(),20*time.Second);defer cancel()
 req,err:=http.NewRequestWithContext(context,http.MethodGet,"http://"+os.Args[2]+":8080/whoami",nil);must(err)
 resp,err:=client.Do(req);must(err);defer resp.Body.Close()
 body,err:=io.ReadAll(resp.Body);must(err)
 var data map[string]string;must(json.Unmarshal(body,&data))
 if resp.StatusCode!=200||data["marker"]!="xio-real-debian-vps"||data["client"]!=local {panic("Tunnel validation failed")}
 result:=map[string]any{"endpoint":fields["endpoint"],"clientIp":local,"server":os.Args[2],"separateDeviceProfileValidated":true,"scope":"isolated userspace client, not physical Honor","at":time.Now().UTC().Format(time.RFC3339)}
 encoded,_:=json.Marshal(result);fmt.Println(string(encoded))
}
func must(err error) {if err!=nil {panic(err)}}
