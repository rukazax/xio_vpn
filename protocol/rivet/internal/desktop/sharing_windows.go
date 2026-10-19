package desktop

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"golang.org/x/sys/windows"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
)

func powershellSharing(script string) ([]byte, error) {
	dir, e := windows.GetSystemDirectory()
	if e != nil {
		return nil, e
	}
	var b bytes.Buffer
	for _, v := range utf16.Encode([]rune(script)) {
		binary.Write(&b, binary.LittleEndian, v)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(dir, "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(b.Bytes()))
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, e := cmd.Output()
	if e != nil {
		return nil, errors.New("Не удалось настроить общий доступ Windows. Проверьте VPN, хот-спот и существующий общий доступ")
	}
	if len(out) > 65536 {
		return nil, errors.New("Invalid Windows sharing response")
	}
	return bytes.TrimPrefix(out, []byte{0xef, 0xbb, 0xbf}), nil
}

const sharingPrefix = `$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$manager=New-Object -ComObject HNetCfg.HNetShare
$all=@(foreach($connection in $manager.EnumEveryConnection){$p=$manager.NetConnectionProps($connection);[pscustomobject]@{Connection=$connection;Props=$p;Config=$manager.INetSharingConfigurationForINetConnection($connection)}})
$receipt=Join-Path $env:ProgramData 'XIO\sharing.json'
`

func sharingOptions() (map[string]any, error) {
	out, e := powershellSharing(sharingPrefix + `
$adapters=@(Get-NetAdapter -IncludeHidden | Where-Object {$_.InterfaceDescription -like '*Wi-Fi Direct*' -and $_.Status -eq 'Up'})
$candidates=@(foreach($a in $adapters){@{id=$a.InterfaceGuid.ToString().ToLower();name=$a.Name}})
@{supported=$true;enabled=$false;candidates=$candidates;message='Windows ICS: после включения проверьте внешний IP на подключённом устройстве'}|ConvertTo-Json -Compress -Depth 4
`)
	if e != nil {
		return nil, e
	}
	var value map[string]any
	e = json.Unmarshal(bytes.TrimSpace(out), &value)
	return value, e
}
func applySharing(enabled bool, iface string) error {
	if enabled && !regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`).MatchString(iface) {
		return errors.New("Включите мобильный хот-спот Windows и выберите интерфейс раздачи")
	}
	script := sharingPrefix
	if enabled {
		script += `$privateId='` + strings.ToLower(iface) + `'
$public=@($all|Where-Object {$_.Props.Name -eq 'xio019'});$private=@($all|Where-Object {$_.Props.Guid.ToString().Trim('{}').ToLower() -eq $privateId})
if($public.Count -ne 1 -or $private.Count -ne 1){throw 'Missing interface'}
$valid=@(Get-NetAdapter -IncludeHidden|Where-Object {$_.InterfaceDescription -like '*Wi-Fi Direct*' -and $_.Status -eq 'Up' -and $_.InterfaceGuid.ToString().ToLower() -eq $privateId})
if($valid.Count -ne 1){throw 'Hotspot is not ready'}
$publicId=$public[0].Props.Guid.ToString()
$old=$null;if(Test-Path -LiteralPath $receipt){$old=Get-Content -Raw -LiteralPath $receipt|ConvertFrom-Json}
foreach($item in $all){if($item.Config.SharingEnabled -and ($null -eq $old -or @($old.public,$old.private) -notcontains $item.Props.Guid.ToString())){throw 'Foreign ICS configuration'}}
if($null -ne $old -and ($old.public -ne $publicId -or $old.private -ne $private[0].Props.Guid.ToString())){throw 'Disable previous sharing first'}
$rule='XIO-Sharing-IPv6-'+$privateId
$created=$false
try{
 if(!(Get-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue)){New-NetFirewallRule -Name $rule -DisplayName $rule -Direction Inbound -InterfaceAlias $valid[0].Name -RemoteAddress '::/0' -Action Block|Out-Null;$created=$true}
 @{public=$publicId;private=$private[0].Props.Guid.ToString();rule=$rule;owner='xio-sharing-v1'}|ConvertTo-Json|Set-Content -LiteralPath $receipt -Encoding UTF8
 if(!$public[0].Config.SharingEnabled){$public[0].Config.EnableSharing(0)}
 if(!$private[0].Config.SharingEnabled){$private[0].Config.EnableSharing(1)}
 if(!$public[0].Config.SharingEnabled -or !$private[0].Config.SharingEnabled){throw 'ICS did not activate'}
}catch{
 foreach($item in @($private[0],$public[0])){try{if($item.Config.SharingEnabled){$item.Config.DisableSharing()}}catch{}}
 if($created){Remove-NetFirewallRule -Name $rule -ErrorAction SilentlyContinue}
 Remove-Item -LiteralPath $receipt -ErrorAction SilentlyContinue
 throw
}
'OK'
`
	} else {
		script += `if(Test-Path -LiteralPath $receipt){
 $old=Get-Content -Raw -LiteralPath $receipt|ConvertFrom-Json
 if($old.owner -ne 'xio-sharing-v1'){throw 'Unowned sharing receipt'}
 $foreign=@($all|Where-Object {$_.Config.SharingEnabled -and $_.Config.SharingConnectionType -eq 0 -and $_.Props.Guid.ToString() -ne $old.public})
 if($foreign.Count){throw 'ICS was changed by another application'}
 foreach($item in $all){if(@($old.public,$old.private) -contains $item.Props.Guid.ToString() -and $item.Config.SharingEnabled){$item.Config.DisableSharing()}}
 Remove-NetFirewallRule -Name $old.rule -ErrorAction SilentlyContinue
 Remove-Item -LiteralPath $receipt
}
'OK'
`
	}
	_, e := powershellSharing(script)
	return e
}
