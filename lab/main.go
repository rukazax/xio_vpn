// Local WireGuard laboratory. No host TUN, forwarding, routes or root access.
// The listener binds only loopback and is exposed to the Android emulator via 10.0.2.2.
package main

import (
    "crypto/ecdh"
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "log"
    "net"
    "net/http"
    "net/netip"
    "os"
    "os/signal"
    "path/filepath"
    "sync/atomic"
    "sync"
    "golang.zx2c4.com/wireguard/conn"
    "golang.zx2c4.com/wireguard/device"
    "golang.zx2c4.com/wireguard/tun/netstack"
)

// Minimal UDP4 bind for an isolated test fixture, not a production transport.
type loopbackBind struct { mu sync.Mutex; socket *net.UDPConn }
func (b *loopbackBind) Open(port uint16) ([]conn.ReceiveFunc,uint16,error) {
    b.mu.Lock(); defer b.mu.Unlock()
    if b.socket!=nil{return nil,0,conn.ErrBindAlreadyOpen}
    socket,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1),Port:int(port)})
    if err!=nil{return nil,0,err};b.socket=socket
    receive:=func(packets [][]byte,sizes []int,endpoints []conn.Endpoint)(int,error){
        n,addr,err:=socket.ReadFromUDPAddrPort(packets[0]);if err!=nil{return 0,err}
        sizes[0]=n;endpoints[0]=&conn.StdNetEndpoint{AddrPort:addr};return 1,nil
    }
    return []conn.ReceiveFunc{receive},uint16(socket.LocalAddr().(*net.UDPAddr).Port),nil
}
func(b *loopbackBind) Close()error{b.mu.Lock();socket:=b.socket;b.socket=nil;b.mu.Unlock();if socket!=nil{return socket.Close()};return nil}
func(b *loopbackBind) SetMark(mark uint32)error{return nil}
func(b *loopbackBind) BatchSize()int{return 1}
func(b *loopbackBind) ParseEndpoint(s string)(conn.Endpoint,error){addr,err:=netip.ParseAddrPort(s);if err!=nil{return nil,err};return &conn.StdNetEndpoint{AddrPort:addr},nil}
func(b *loopbackBind) Send(bufs [][]byte,ep conn.Endpoint)error{
    b.mu.Lock();socket:=b.socket;b.mu.Unlock();if socket==nil{return net.ErrClosed}
    endpoint,ok:=ep.(*conn.StdNetEndpoint);if !ok{return conn.ErrWrongEndpointType}
    for _,buf:=range bufs{if _,err:=socket.WriteToUDPAddrPort(buf,endpoint.AddrPort);err!=nil{return err}};return nil
}

func must(err error){if err!=nil{log.Fatal(err)}}
func main(){
    dir:="../.build-support/lab";must(os.MkdirAll(dir,0700))
    sshFixture:=startSSHFixture(dir);defer sshFixture.Close()
    server,err:=ecdh.X25519().GenerateKey(rand.Reader);must(err)
    client,err:=ecdh.X25519().GenerateKey(rand.Reader);must(err)
    tun,stack,err:=netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.77.0.1")},nil,1280);must(err)
    dev:=device.NewDevice(tun,&loopbackBind{},device.NewLogger(device.LogLevelError,"lab: "))
    defer dev.Close()
    // Internal random port, announced only to the local UDP gateway.
    must(dev.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=51829\npublic_key=%x\nallowed_ip=10.77.0.2/32\n",server.Bytes(),client.PublicKey().Bytes())))
    must(dev.Up())
    config:=fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = 10.77.0.2/32\nMTU = 1280\n\n[Peer]\nPublicKey = %s\nEndpoint = 10.0.2.2:51829\nAllowedIPs = 10.77.0.0/24\nPersistentKeepalive = 5\n",base64.StdEncoding.EncodeToString(client.Bytes()),base64.StdEncoding.EncodeToString(server.PublicKey().Bytes()))
    must(os.WriteFile(filepath.Join(dir,"client.conf"),[]byte(config),0600))
    listener,err:=stack.ListenTCP(&net.TCPAddr{Port:8080});must(err)
    var count atomic.Int64
    httpServer:=&http.Server{Handler:http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){count.Add(1);fmt.Fprint(w,"x1o-wireguard-lab-ok");log.Printf("encrypted HTTP exchange %d",count.Load())})}
    go httpServer.Serve(listener)
    log.Print("READY: loopback gateway :51829, encrypted HTTP 10.77.0.1:8080; ephemeral test keys saved privately")
    signalChannel:=make(chan os.Signal,1);signal.Notify(signalChannel,os.Interrupt)
    <-signalChannel
    httpServer.Close()
    os.Remove(filepath.Join(dir,"client.conf"))
}

func splitLines(s string) []string {
    var result []string
    start:=0
    for i,b:=range []byte(s){if b=='\n'{result=append(result,s[start:i]);start=i+1}}
    if start<len(s){result=append(result,s[start:])};return result
}
