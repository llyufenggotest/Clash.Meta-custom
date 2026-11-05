"""Verify fixed upstream bytes and print the maintained delta (no cache required)."""
import difflib
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
inventory = json.loads((root / 'UPSTREAM-INVENTORY.json').read_text())
allowed_modified = {'internal/engine/host.go'}
changed = []
for entry in inventory['files']:
    path = root / entry['path']
    assert path.is_file(), f'missing upstream file: {path}'
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != entry['sha256'] or len(raw) != entry['bytes']:
        changed.append(entry['path'])
assert set(changed) == allowed_modified, f'unexpected upstream delta: {changed}'
wasm = root / 'internal/artifact/easytier_core.wasm'
wasm_hash = hashlib.sha256(wasm.read_bytes()).hexdigest()
assert wasm_hash == '8b82f37d62fba2ffe8e256386096fddf448d4261d51c495d5bd97cd11bbb24a0'
commit = '63519db2b5f2a6a1b9b7f20905f036dab54eb829'
assert commit in (root / 'internal/artifact/provenance.go').read_text()
assert commit in (root / 'proto/provenance.go').read_text()
assert '4fc7f40eac5d3803ed8afe707f2be1db121a022547f91568955c369212875064' in (root / 'proto/provenance.go').read_text()
original = {e['path'] for e in inventory['files']}
added = sorted(p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and p.relative_to(root).as_posix() not in original)
print(json.dumps({'module': inventory['module'], 'version': inventory['version'], 'original_files': len(original), 'original_bytes': sum(e['bytes'] for e in inventory['files']), 'modified_upstream_files': changed, 'added_files': added, 'embedded_wasm_sha256': wasm_hash}, indent=2))
