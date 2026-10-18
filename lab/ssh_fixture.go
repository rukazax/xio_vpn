package main

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/json"
    "errors"
    "net"
    "os"
    "path/filepath"
    "sync/atomic"
    "strconv"
    "golang.org/x/crypto/ssh"
)

// This is a test-only SSH endpoint. It never executes operating system commands.
func startSSHFixture(dir string) net.Listener {
    _,private,err:=ed25519.GenerateKey(rand.Reader);must(err)
    signer,err:=ssh.NewSignerFromKey(private);must(err)
    var authAttempts atomic.Int64
    must(os.WriteFile(filepath.Join(dir,"ssh-auth-count"),[]byte("0"),0600))
    config:=&ssh.ServerConfig{PasswordCallback:func(meta ssh.ConnMetadata,password []byte)(*ssh.Permissions,error){
        count:=authAttempts.Add(1)
        must(os.WriteFile(filepath.Join(dir,"ssh-auth-count"),[]byte(strconv.FormatInt(count,10)),0600))
        if meta.User()=="lab" && string(password)=="x1o-lab-password" {return nil,nil};return nil,errors.New("denied")
    }}
    config.AddHostKey(signer)
    listener,err:=net.Listen("tcp4","127.0.0.1:22229");must(err)
    metadata,_:=json.Marshal(map[string]any{"host":"127.0.0.1","port":22229,"username":"lab","password":"x1o-lab-password","fingerprint":ssh.FingerprintSHA256(signer.PublicKey())})
    must(os.WriteFile(filepath.Join(dir,"ssh.json"),metadata,0600))
    go func(){for{socket,err:=listener.Accept();if err!=nil{return};go func(){
        defer socket.Close();connection,channels,requests,err:=ssh.NewServerConn(socket,config);if err!=nil{return};defer connection.Close()
        go ssh.DiscardRequests(requests)
        for channel:=range channels{channel.Reject(ssh.Prohibited,"fixture has no shell")}
    }()}}()
    return listener
}
