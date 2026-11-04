"""Offline production build and final-binary receipt; only needed on build hosts."""
import argparse, hashlib, json, os, pathlib, struct, subprocess

p=argparse.ArgumentParser();p.add_argument('--output',type=pathlib.Path)
p.add_argument('--check-vendor',action='store_true',help='verify all vendored files without building')
a=p.parse_args()
root=pathlib.Path(__file__).resolve().parents[1]
failures=[]
manifests=sorted(root.joinpath('vendor').glob('*/.cargo-checksum.json'))
if not manifests:raise SystemExit('Vendored dependency checksum manifests are missing.')
for manifest in manifests:
 for relative,expected in json.loads(manifest.read_text())['files'].items():
  path=manifest.parent/relative
  if not path.is_file():failures.append(str(path.relative_to(root))+': missing')
  elif hashlib.sha256(path.read_bytes()).hexdigest()!=expected:
   failures.append(str(path.relative_to(root))+': checksum mismatch')
if failures:raise SystemExit('Vendored dependency integrity failed:\n'+'\n'.join(failures))
if a.check_vendor:
 print('All vendored file checksums match.')
 raise SystemExit(0)
name=root.joinpath('Cargo.toml').read_text().split('name = "',1)[1].split('"',1)[0]
target='x86_64-unknown-linux-musl'
for action in ['test','build']:
 subprocess.run(['cargo',action,'--release','--locked','--offline','--target',target],cwd=root,check=True)
target_dir=pathlib.Path(os.environ.get('CARGO_TARGET_DIR',str(root/'target')))
if not target_dir.is_absolute():target_dir=root/target_dir
source=target_dir/target/'release'/name
data=source.read_bytes();assert data[:6]==b'\x7fELF\x02\x01'
h=struct.unpack_from('<16sHHIQQQIHHHHHH',data)
for i in range(h[10]):
 kind,flags,off,va,pa,size,memsz,align=struct.unpack_from('<IIQQQQQQ',data,h[5]+i*h[9])
 assert kind!=3,'dynamic interpreter is not allowed in a standalone release'
 if kind==2:
  for j in range(off,off+size,16):
   tag,val=struct.unpack_from('<QQ',data,j)
   assert tag!=1,'external shared library is not allowed in a standalone release'
info=json.loads(subprocess.check_output([str(source),'--build-info'],text=True))
sha=hashlib.sha256(data).hexdigest();assert info['runtime_executable_sha256']==sha
assert info['features']==[],'production release must not contain development-options'
for path,expected in info['source_sha256'].items():assert hashlib.sha256((root/path).read_bytes()).hexdigest()==expected,path
out=(a.output or root/'release').resolve();out.mkdir(parents=True,exist_ok=True)
(out/name).write_bytes(data);(out/name).chmod(0o755)
(out/'manifest.json').write_text(json.dumps({'binary':name,'sha256':sha,'bytes':len(data),'build_info':info},indent=2)+'\n')
(out/'SHA256SUMS.txt').write_text(sha+'  '+name+'\n'+hashlib.sha256((out/'manifest.json').read_bytes()).hexdigest()+'  manifest.json\n',encoding='ascii',newline='\n')
print(name,sha)
