from pathlib import Path
import hashlib,json,sys,os,shutil,signal
b=Path('/srv/archives/agent-review-rivet-aar-20261106'); s=b/'src'; mode=sys.argv[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
if mode!='finalize':
 app=s/'app'; p=app/'build/app/generated/source/buildConfig/debug/app/xio/xio/BuildConfig.java'
 text=p.read_text(); assert ('CLIENT_ONLY = '+('true' if mode=='client' else 'false')) in text
 assert ('APPLICATION_ID = "'+('app.xio.client' if mode=='client' else 'app.xio.xio')+'"') in text
 shutil.copy2(p,b/f'logs/{mode}-BuildConfig.java')
 classes={str(p.relative_to(app)):sha(p) for root in [app/'build/app/tmp/kotlin-classes/debug',app/'build/app/intermediates/javac/debug'] for p in root.rglob('*.class')}
 assert classes
 (b/f'logs/{mode}-compiled-classes.json').write_text(json.dumps(classes,indent=2))
 print(mode,'compiled class files',len(classes),'BuildConfigSHA256',sha(p))
 main=app/'build/app/tmp/kotlin-classes/debug/app/xio/xio/MainActivity.class'
 assert main.is_file(); shutil.copy2(main,b/f'logs/{mode}-MainActivity.class'); print('MainActivitySHA256',sha(main))
else:
 pre=json.loads((b/'source-pre.json').read_text()); post={k:sha(s/k) if (s/k).is_file() else None for k in pre}
 changes={k:{'before':v,'after':post[k]} for k,v in pre.items() if v!=post[k]}
 assert list(changes)==['app/android/app/libs/rivet.aar'],changes
 assert changes['app/android/app/libs/rivet.aar']['after']=='7e11803667f85980f2d35b35c7474b19987936101f3b9564472017cc5858370c'
 (b/'source-post.json').write_text(json.dumps(post,indent=2))
 proof={'archiveSha256':sha(b/'source-595.tar'),'archivedFileCount':len(pre),'archivedFileDeltas':changes,'kotlinSourceCount':len(list((s/'app/android/app/src/main').rglob('*.kt'))),'javaSourceCount':len(list((s/'app/android/app/src/main').rglob('*.java')))}
 (b/'logs/hash-verification.json').write_text(json.dumps(proof,indent=2)); print(json.dumps(proof,indent=2))
 for p in Path('/proc').iterdir():
  if not p.name.isdigit():continue
  try:cmd=(p/'cmdline').read_bytes().replace(b'\0',b' ').decode()
  except (OSError,UnicodeError):continue
  if 'org.jetbrains.kotlin.daemon.KotlinCompileDaemon' in cmd and str(b) in cmd: os.kill(int(p.name),signal.SIGTERM);print('Stopped own Kotlin daemon',p.name)
