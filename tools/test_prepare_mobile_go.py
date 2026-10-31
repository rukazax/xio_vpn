import importlib.util,tempfile,unittest
from pathlib import Path
spec=importlib.util.spec_from_file_location('prepare_mobile_go',Path(__file__).with_name('prepare-mobile-go.py'))
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)

def source(base,version='go1.27.3'):
 p=base/'source';(p/'src/runtime').mkdir(parents=True);(p/'VERSION').write_text(version+'\n')
 values={'amd64':'MOVL\t$1, DI // CLOCK_MONOTONIC\n','arm64':'#define CLOCK_MONOTONIC 1\n$CLOCK_MONOTONIC, R0\n','arm':'#define CLOCK_MONOTONIC\t1\n$CLOCK_MONOTONIC, R0\n'}
 for arch,value in values.items():(p/f'src/runtime/sys_linux_{arch}.s').write_text(value)
 return p

class PrepareMobileGoSecurityTests(unittest.TestCase):
 def test_fresh_copy_and_valid_reuse(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d);s=source(b);before={p.name:p.read_bytes() for p in (s/'src/runtime').iterdir()};p=m.prepare(s,b/'patched')
   self.assertEqual(m.prepare(s,p),p);self.assertEqual((p/'VERSION').read_text().strip(),'go1.27.3')
   self.assertTrue(all('CLOCK_BOOTTIME' in f.read_text() for f in (p/'src/runtime').iterdir()))
   self.assertEqual(before,{p.name:p.read_bytes() for p in (s/'src/runtime').iterdir()})
 def test_old_input_refused_before_copy(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d);s=source(b,'go1.27.2')
   with self.assertRaisesRegex(AssertionError,'1.27.3 required'):m.prepare(s,b/'patched')
   self.assertFalse((b/'patched').exists())
 def test_old_cache_does_not_survive_new_input(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d);s=source(b);p=b/'patched';p.mkdir();(p/'VERSION').write_text('go1.27.2\n');(p/'.xio-patched').write_text('CLOCK_BOOTTIME on arm/arm64/amd64\n')
   before=(p/'VERSION').read_bytes()
   with self.assertRaisesRegex(AssertionError,'cache version differs'):m.prepare(s,p)
   self.assertEqual((p/'VERSION').read_bytes(),before)
 def test_marker_does_not_hide_corruption(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d);s=source(b);p=m.prepare(s,b/'patched');(p/'src/runtime/sys_linux_arm64.s').write_text('corrupted runtime\n')
   with self.assertRaisesRegex(AssertionError,'runtime patch differs'):m.prepare(s,p)
 def test_partial_and_unknown_cache_refused(self):
  with tempfile.TemporaryDirectory() as d:
   b=Path(d);s=source(b);p=b/'patched';p.mkdir()
   with self.assertRaisesRegex(AssertionError,'incomplete'):m.prepare(s,p)
   (p/'VERSION').write_text('go1.27.3\n');(p/'.xio-patched').write_text('foreign marker\n')
   with self.assertRaisesRegex(AssertionError,'Unknown'):m.prepare(s,p)

if __name__=='__main__':unittest.main()
