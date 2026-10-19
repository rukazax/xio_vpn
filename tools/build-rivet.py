#!/usr/bin/env python3
"""Build pinned RIVET server and optionally Android binding; no signing keys."""
from pathlib import Path
import argparse,subprocess,os,hashlib,json,sys,runpy,shutil
from native_fingerprint import fingerprint
r=Path(__file__).resolve().parent.parent
p=argparse.ArgumentParser();p.add_argument('--go',default='go');p.add_argument('--gomobile');args=p.parse_args()
args.go=str(Path(shutil.which(args.go) or args.go).resolve())
if args.gomobile:args.gomobile=str(Path(shutil.which(args.gomobile) or args.gomobile).resolve())
version=subprocess.check_output([args.go,'version'],text=True).strip()
assert 'go1.27.2 ' in version,'Use the verified Go 1.27.2 toolchain; newer toolchains require validation'
assert sys.platform=='linux','Verified server build requires Linux x86_64'
assert subprocess.check_output([args.go,'env','GOARCH'],text=True).strip()=='amd64'
subprocess.run([sys.executable,str(r/'tools/prepare-xray.py'),'--go',args.go],check=True)
module=r/'protocol/rivet'
subprocess.run([args.go,'test','-race','./...'],cwd=module,check=True)
subprocess.run([args.go,'build','-trimpath',"-ldflags=-s -w",'-o',str(r/'vendor-server/xio-rivet-linux-amd64'),'./cmd/rivet'],cwd=module,check=True)
subprocess.run([args.go,'build','-trimpath',"-ldflags=-s -w",'-o',str(r/'vendor-server/xio-xray-linux-amd64'),'./cmd/xraygateway'],cwd=module,check=True)
subprocess.run([args.go,'build','-trimpath',"-ldflags=-s -w",'-o',str(r/'vendor-server/xio-cloak-linux-amd64'),'github.com/cbeuw/Cloak/cmd/ck-server'],cwd=module,check=True)
if args.gomobile:
 go_binary=Path(shutil.which(args.go) or args.go).resolve();patched=runpy.run_path(str(r/'tools/prepare-mobile-go.py'))['prepare'](go_binary.parent.parent,r/'.build-support/go-awg')
 mobile_env=dict(os.environ,GOROOT=str(patched),PATH=str(patched/'bin')+os.pathsep+str(Path(args.gomobile).resolve().parent)+os.pathsep+os.environ['PATH'],ANDROID_HOME=os.environ.get('ANDROID_HOME',str(Path.home()/'Android/Sdk')),ANDROID_NDK_HOME=os.environ.get('ANDROID_NDK_HOME',str(Path.home()/'Android/Sdk/ndk/30.0.16248370')))
 subprocess.run([args.gomobile,'bind','-target=android/arm64,android/arm,android/amd64','-androidapi','26','-trimpath',"-ldflags=-s -w",'-javapkg','app.xio','-o',str(r/'app/android/app/libs/rivet.aar'),'./mobile'],cwd=module,env=mobile_env,check=True)
metadata={'go':version,'sourceSha256':fingerprint(r),'xrayServerSha256':hashlib.sha256((r/'vendor-server/xio-xray-linux-amd64').read_bytes()).hexdigest(),'cloakServerSha256':hashlib.sha256((r/'vendor-server/xio-cloak-linux-amd64').read_bytes()).hexdigest(),'fingerprintIncludes':'protocol/rivet plus vendor/anet, cloak, patched xray and tun2socks (tailscale source archive only)','serverSha256':hashlib.sha256((r/'vendor-server/xio-rivet-linux-amd64').read_bytes()).hexdigest(),'androidRuntime':'single Go runtime; private CLOCK_BOOTTIME patch, crypto unchanged','awgModule':'v3.1.20260814','androidAarSha256':hashlib.sha256((r/'app/android/app/libs/rivet.aar').read_bytes()).hexdigest()}
(r/'vendor-metadata/rivet-build.json').write_text(json.dumps(metadata,indent=2)+'\n')
print('RIVET runtime artifacts and source fingerprints recorded')
