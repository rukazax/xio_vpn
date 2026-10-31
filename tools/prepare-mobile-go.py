#!/usr/bin/env python3
"""Private copy of Go with upstream Android CLOCK_BOOTTIME timer semantics."""
from pathlib import Path
import shutil,argparse

def prepare(go,patched):
 go=Path(go);patched=Path(patched)
 assert (go/'VERSION').read_text().splitlines()[0]=='go1.27.3','Go 1.27.3 required (GO-2026-6809 fixed)'
 if (patched/'.xio-patched').exists():
  assert (patched/'VERSION').read_text().splitlines()[0]=='go1.27.3','Private Go cache version differs; old toolchain preserved'
  assert (patched/'.xio-patched').read_text().strip()=='CLOCK_BOOTTIME on arm/arm64/amd64','Unknown private Go patch marker'
  for arch,needle in [('amd64','MOVL\t$7, DI // CLOCK_BOOTTIME'),('arm64','#define CLOCK_BOOTTIME 7'),('arm','#define CLOCK_BOOTTIME\t7')]:
   assert (patched/f'src/runtime/sys_linux_{arch}.s').read_text().count(needle)==1,'Private Go runtime patch differs'
  return patched
 assert not patched.exists(),'Inspect incomplete private toolchain before retry'
 shutil.copytree(go,patched)
 edits={'amd64':[('MOVL\t$1, DI // CLOCK_MONOTONIC','MOVL\t$7, DI // CLOCK_BOOTTIME')],'arm64':[('#define CLOCK_MONOTONIC 1','#define CLOCK_BOOTTIME 7'),('$CLOCK_MONOTONIC, R0','$CLOCK_BOOTTIME, R0')],'arm':[('#define CLOCK_MONOTONIC\t1','#define CLOCK_BOOTTIME\t7'),('$CLOCK_MONOTONIC, R0','$CLOCK_BOOTTIME, R0')]}
 for arch,replacements in edits.items():
  p=patched/f'src/runtime/sys_linux_{arch}.s';text=p.read_text()
  for before,after in replacements:
   assert text.count(before)==1,'Review changed Go runtime assembly'
   text=text.replace(before,after)
  p.write_text(text)
 (patched/'.xio-patched').write_text('CLOCK_BOOTTIME on arm/arm64/amd64\n');return patched
if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('go_root');p.add_argument('private_copy');a=p.parse_args();print(prepare(a.go_root,a.private_copy))
