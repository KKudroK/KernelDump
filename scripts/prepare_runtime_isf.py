"""Create a separate, evidence-checked task allocation-size analysis overlay.

This does not change memory bytes, the collector or the installed analyzer.
It does not rewrite nested optional FPU layouts. Preserve the original ISF.
"""
import argparse
import base64
import hashlib
import json
from pathlib import Path


def sha(data):
    return hashlib.sha256(data).hexdigest()


def prepare(isf_path, manifest_path, proof_path, output):
    raw = isf_path.read_bytes()
    isf = json.loads(raw)
    manifest = json.loads(manifest_path.read_bytes())
    proof = json.loads(proof_path.read_bytes())
    source = manifest['source']
    if sha(raw) != proof['isf_sha256']:
        raise ValueError('ISF hash does not match the supplied layout proof')
    if source['kernel_btf']['sha256'] != proof['btf_sha256']:
        raise ValueError('Captured BTF does not match the layout proof')
    if source['kernel_gnu_build_ids'] != proof['live_gnu_build_id']:
        raise ValueError('Captured build ID does not match the layout proof')
    task_checks = [x for x in proof['layout_comparison'] if x['name'] == 'task_struct']
    if len(task_checks) != 1 or task_checks[0]['offset_mismatches']:
        raise ValueError('Missing or failed task field layout comparison')
    task = isf['user_types']['task_struct']
    if task_checks[0]['compared_fields'] != len(task['fields']):
        raise ValueError('Proof did not check every task_struct field')
    if task_checks[0]['btf_size'] != task['size'] or task_checks[0]['isf_size'] != task['size']:
        raise ValueError('Static size does not match the layout proof')
    banner = base64.b64decode(isf['symbols']['linux_banner']['constant_data'])
    if banner.rstrip(b'\0') != source['kernel_banner'].encode():
        raise ValueError('ISF and captured kernel banners differ')
    runtime = source['runtime_task_struct_allocation']['bytes']
    if not 0 < runtime <= task['size'] or task['fields']['thread']['offset'] >= runtime:
        raise ValueError('Invalid runtime allocation size or thread offset')
    original_size = task['size']
    task['size'] = runtime
    result = json.dumps(isf, separators=(',', ':')).encode()
    provenance = output.with_name(output.name + '.provenance.json')
    if output.exists() or provenance.exists():
        raise FileExistsError('Overlay and provenance paths must both be new')
    record = {
        'input_sha256': sha(raw), 'output_sha256': sha(result),
        'manifest_sha256': sha(manifest_path.read_bytes()),
        'proof_sha256': sha(proof_path.read_bytes()),
        'only_json_change': 'user_types.task_struct.size',
        'static_size': original_size, 'runtime_allocation_size': runtime,
        'limitation': 'Nested static FPU types are unchanged. Do not interpret bytes beyond the recorded allocation. This overlay addresses analyzer object-readability bounds, not missing physical bytes or a mismatched kernel build.',
    }
    with output.open('xb') as f:
        f.write(result)
    with provenance.open('x', encoding='utf-8') as f:
        json.dump(record, f, indent=2)
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('isf', 'manifest', 'proof', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.isf, args.manifest, args.proof, args.output), indent=2))
