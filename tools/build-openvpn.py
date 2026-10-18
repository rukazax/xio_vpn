#!/usr/bin/env python3
"""Rebuild the official OpenVPN 3 JNI bridge from included corresponding source."""
from pathlib import Path
import argparse, hashlib, json, os, shutil, subprocess

r = Path(__file__).resolve().parent.parent
p = argparse.ArgumentParser()
p.add_argument('--sdk', type=Path, default=Path(os.environ.get('ANDROID_HOME', str(Path.home()/'Android/Sdk'))))
p.add_argument('--ndk', default='30.0.16248370')
args = p.parse_args()
ndk = args.sdk/'ndk'/args.ndk
assert ndk.is_dir(), 'Install the pinned Android NDK first'
deps = r/'vendor/openvpn-deps'
manifest = json.loads((deps/'SOURCE-SHA256.json').read_text())
for name, expected in manifest.items():
    assert hashlib.sha256((deps/name).read_bytes()).hexdigest() == expected, 'Native source mismatch: '+name
java = r/'app/android/app/src/main/java/app/xio/openvpn'
java.mkdir(parents=True, exist_ok=True)
subprocess.run(['swig', '-c++', '-java', '-package', 'app.xio.openvpn', '-I'+str(deps/'openvpn3/client'), '-I'+str(deps/'openvpn3'), '-outdir', str(java), '-o', str(r/'native/openvpn/wrapper.cpp'), str(deps/'openvpn3/client/ovpncli.i')], check=True)
for abi, triple in [('arm64-v8a','aarch64-linux-android'), ('armeabi-v7a','arm-linux-androideabi'), ('x86_64','x86_64-linux-android')]:
    build = r/'.build-support'/('openvpn-'+abi)
    subprocess.run(['cmake', '-S', str(r/'native/openvpn'), '-B', str(build), '-G', 'Ninja', '-DCMAKE_TOOLCHAIN_FILE='+str(ndk/'build/cmake/android.toolchain.cmake'), '-DANDROID_ABI='+abi, '-DANDROID_PLATFORM=android-26', '-DCMAKE_BUILD_TYPE=Release'], check=True)
    subprocess.run(['cmake', '--build', str(build), '--parallel', '4'], check=True)
    dest = r/'app/android/app/src/main/jniLibs'/abi
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(build/'libxio_openvpn.so', dest/'libxio_openvpn.so')
    shutil.copyfile(ndk/'toolchains/llvm/prebuilt/linux-x86_64/sysroot/usr/lib'/triple/'libc++_shared.so', dest/'libc++_shared.so')
print('OpenVPN JNI: three ABIs built from verified included sources')
