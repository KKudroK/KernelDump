"""Restore only CRLF transformations whose canonical bytes match vendor hashes."""
import hashlib,json,pathlib,sys
root=pathlib.Path(sys.argv[1]);changes=[]
for checksum in sorted((root/'vendor').glob('*/.cargo-checksum.json')):
    spec=json.loads(checksum.read_text())
    for name,expected in spec['files'].items():
        path=checksum.parent/name;data=path.read_bytes();actual=hashlib.sha256(data).hexdigest()
        if actual==expected:continue
        canonical=data.replace(b'\r\n',b'\n')
        if hashlib.sha256(canonical).hexdigest()!=expected:raise ValueError('non-newline vendor mismatch: '+str(path))
        path.write_bytes(canonical);changes.append({'path':str(path.relative_to(root)),'before_sha256':actual,'verified_sha256':expected})
print(json.dumps({'normalization':'only CRLF to hash-matching canonical LF','changes':changes},indent=2))
