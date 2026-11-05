"""Verify fixed upstream bytes and print the maintained delta (no cache required)."""
import difflib
import hashlib
import json
import re
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
# Added production files are local maintenance, never upstream inventory entries.
# Verify their complete patch payload; hash-only upstream checks cannot detect a
# stale patch that still documents the old serial compiler.
patch = (root / 'OIX-PRODUCTION.patch').read_text()
added_production = ['internal/engine/core_cache.go', 'internal/engine/core_workers_default.go', 'internal/engine/core_workers_lowmem.go']
for name in added_production:
    header = f'--- /dev/null\n+++ b/{name}\n'
    assert header in patch, f'missing added production patch: {name}'
    section = re.split(r'(?m)(?=^--- )', patch.split(header, 1)[1], maxsplit=1)[0]
    lines = section.splitlines(keepends=True)
    assert re.fullmatch(r'@@ -0,0 \+1,\d+ @@\n', lines[0]), f'invalid added hunk: {name}'
    assert all(line.startswith('+') for line in lines[1:]), f'invalid added payload: {name}'
    payload = ''.join(line[1:] for line in lines[1:])
    assert payload == (root / name).read_text(), f'stale production patch: {name}'
    assert int(re.search(r'\+1,(\d+)', lines[0]).group(1)) == len(lines)-1
added = sorted(p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and p.relative_to(root).as_posix() not in original)
print(json.dumps({'module': inventory['module'], 'version': inventory['version'], 'original_files': len(original), 'original_bytes': sum(e['bytes'] for e in inventory['files']), 'modified_upstream_files': changed, 'added_files': added, 'embedded_wasm_sha256': wasm_hash}, indent=2))
